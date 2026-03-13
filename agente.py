import os
import re
import json
import time
import ipaddress
from datetime import datetime
from pathlib import Path

import anthropic
import requests
from dotenv import load_dotenv

load_dotenv()

# ── Carpeta de reportes ──────────────────────────────────────
REPORTES_DIR = Path("C:/agente-seguridad/reportes")
REPORTES_DIR.mkdir(exist_ok=True)

MAX_TOOL_CALLS = 10   # seguridad: límite de herramientas por análisis
HTTP_TIMEOUT   = 10   # segundos máximos de espera por cada API

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ═══════════════════════════════════════════════════
#  VALIDADORES
# ═══════════════════════════════════════════════════

def validar_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def validar_dominio(d):
    return bool(re.match(r'^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$', d.strip()))

def validar_hash(h):
    h = h.strip()
    return bool(re.match(r'^[a-fA-F0-9]{32}$', h) or
                re.match(r'^[a-fA-F0-9]{40}$', h) or
                re.match(r'^[a-fA-F0-9]{64}$', h))

def detectar_tipo(target):
    target = target.strip()
    if validar_ip(target):        return "ip"
    if validar_hash(target):      return "hash"
    if target.startswith("http"): return "url"
    if validar_dominio(target):   return "dominio"
    return "desconocido"

def sanitizar(texto):
    texto = re.sub(r'[^\w\s\.\-\:\/\@\?\=\&\%]', '', texto.strip())
    return texto[:300]

# ═══════════════════════════════════════════════════
#  HTTP SEGURO
# ═══════════════════════════════════════════════════

def http_get(url, headers=None, params=None):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.Timeout:
        return {"error": f"Timeout conectando con {url.split('/')[2]}"}
    except Exception as e:
        return {"error": str(e)[:100]}

# ═══════════════════════════════════════════════════
#  HERRAMIENTAS
# ═══════════════════════════════════════════════════

def check_virustotal(target):
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "Falta VIRUSTOTAL_API_KEY en .env"}
    tipo = detectar_tipo(target)
    urls = {
        "ip":      f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
        "dominio": f"https://www.virustotal.com/api/v3/domains/{target}",
        "hash":    f"https://www.virustotal.com/api/v3/files/{target}",
    }
    if tipo not in urls:
        return {"error": f"VirusTotal no soporta el tipo: {tipo}"}
    data = http_get(urls[tipo], headers={"x-apikey": api_key})
    if "error" in data:
        return data
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    total = sum(stats.values()) if stats else 0
    malos = stats.get("malicious", 0)
    return {
        "fuente":        "VirusTotal",
        "malicioso":     malos,
        "sospechoso":    stats.get("suspicious", 0),
        "limpio":        stats.get("undetected", 0),
        "total_motores": total,
        "veredicto":     "PELIGROSO" if malos > 3 else "SOSPECHOSO" if malos > 0 else "LIMPIO"
    }

def check_abuseipdb(ip):
    if not validar_ip(ip):
        return {"error": f"'{ip}' no es una IP válida"}
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "Falta ABUSEIPDB_API_KEY en .env"}
    data = http_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    if "error" in data:
        return data
    d     = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    return {
        "fuente":         "AbuseIPDB",
        "score_abuso":    score,
        "total_reportes": d.get("totalReports", 0),
        "pais":           d.get("countryCode", "?"),
        "isp":            d.get("isp", "?"),
        "en_whitelist":   d.get("isWhitelisted", False),
        "veredicto":      "PELIGROSO" if score >= 50 else "SOSPECHOSO" if score >= 10 else "LIMPIO"
    }

def check_ipinfo(ip):
    if not validar_ip(ip):
        return {"error": f"'{ip}' no es una IP válida"}
    data = http_get(f"https://ipinfo.io/{ip}/json")
    if "error" in data:
        return data
    return {
        "fuente":       "IPInfo",
        "ciudad":       data.get("city", "?"),
        "pais":         data.get("country", "?"),
        "organizacion": data.get("org", "?"),
        "hostname":     data.get("hostname", "Sin hostname"),
        "timezone":     data.get("timezone", "?"),
    }

def buscar_cves(software, version=""):
    query = f"{software} {version}".strip()
    data  = http_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": query, "resultsPerPage": 5}
    )
    if "error" in data:
        return data
    vulns = []
    for item in data.get("vulnerabilities", []):
        cve     = item.get("cve", {})
        cve_id  = cve.get("id", "N/A")
        metrics = cve.get("metrics", {})
        score, severidad = "N/A", "N/A"
        if metrics.get("cvssMetricV31"):
            m         = metrics["cvssMetricV31"][0]["cvssData"]
            score     = m.get("baseScore", "N/A")
            severidad = m.get("baseSeverity", "N/A")
        desc = next(
            (d["value"][:150] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "Sin descripción"
        )
        vulns.append({"cve": cve_id, "score": score, "severidad": severidad, "descripcion": desc})
    return {
        "fuente":           "NIST NVD",
        "consulta":         query,
        "total":            data.get("totalResults", 0),
        "vulnerabilidades": vulns
    }

def check_whois(dominio):
    if not validar_dominio(dominio):
        return {"error": f"'{dominio}' no es un dominio válido"}
    data = http_get(f"https://rdap.org/domain/{dominio}")
    if "error" in data:
        return data
    estados = [s.get("value", "") for s in data.get("status", [])]
    return {
        "fuente":  "RDAP/WHOIS",
        "dominio": dominio,
        "nombre":  data.get("ldhName", dominio),
        "estados": estados,
        "nota":    "Para datos completos de registrador agrega WHOISXML_API_KEY"
    }

def buscar_subdominios(dominio):
    if not validar_dominio(dominio):
        return {"error": f"'{dominio}' no es un dominio válido"}
    data = http_get("https://crt.sh/", params={"q": f"%.{dominio}", "output": "json"})
    if not data or isinstance(data, dict) and "error" in data:
        return {"error": "No se pudo conectar con crt.sh"}
    subs = set()
    for entry in data:
        for nombre in entry.get("name_value", "").split("\n"):
            nombre = nombre.strip().lower()
            if nombre.endswith(f".{dominio}") and "*" not in nombre:
                subs.add(nombre)
    lista = sorted(subs)[:20]
    return {
        "fuente":      "Certificate Transparency",
        "dominio":     dominio,
        "total":       len(subs),
        "subdominios": lista
    }

# ═══════════════════════════════════════════════════
#  DEFINICIÓN DE HERRAMIENTAS PARA EL AGENTE
# ═══════════════════════════════════════════════════

TOOLS = [
    {
        "name": "check_virustotal",
        "description": "Verifica reputación de IPs, dominios y hashes en 90+ antivirus. Úsala siempre primero.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, dominio o hash"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_abuseipdb",
        "description": "Consulta reportes de abuso de una IP: spam, ataques, brute-force.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Dirección IP"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "check_ipinfo",
        "description": "Geolocalización de una IP: país, ciudad, ISP, organización.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Dirección IP"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "buscar_cves",
        "description": "Busca vulnerabilidades CVE conocidas para un software y versión específicos.",
        "input_schema": {
            "type": "object",
            "properties": {
                "software": {"type": "string", "description": "Nombre del software (ej: Apache, nginx, OpenSSH)"},
                "version":  {"type": "string", "description": "Versión específica (opcional)"}
            },
            "required": ["software"]
        }
    },
    {
        "name": "check_whois",
        "description": "Datos de registro de un dominio: estado, fechas, registrador.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dominio": {"type": "string", "description": "Nombre de dominio (ej: ejemplo.com)"}
            },
            "required": ["dominio"]
        }
    },
    {
        "name": "buscar_subdominios",
        "description": "Descubre subdominios de un dominio de forma pasiva usando Certificate Transparency.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dominio": {"type": "string", "description": "Dominio raíz (ej: ejemplo.com)"}
            },
            "required": ["dominio"]
        }
    },
]

# ═══════════════════════════════════════════════════
#  EJECUTOR DE HERRAMIENTAS
# ═══════════════════════════════════════════════════

def ejecutar_herramienta(nombre, parametros):
    mapa = {
        "check_virustotal":   lambda p: check_virustotal(p["target"]),
        "check_abuseipdb":    lambda p: check_abuseipdb(p["ip"]),
        "check_ipinfo":       lambda p: check_ipinfo(p["ip"]),
        "buscar_cves":        lambda p: buscar_cves(p["software"], p.get("version", "")),
        "check_whois":        lambda p: check_whois(p["dominio"]),
        "buscar_subdominios": lambda p: buscar_subdominios(p["dominio"]),
    }
    if nombre not in mapa:
        return {"error": f"Herramienta '{nombre}' no existe"}
    try:
        return mapa[nombre](parametros)
    except Exception as e:
        return {"error": f"Error en {nombre}: {str(e)[:100]}"}

# ═══════════════════════════════════════════════════
#  MOTOR PRINCIPAL DEL AGENTE
# ═══════════════════════════════════════════════════

def analizar(target):
    target = sanitizar(target)
    tipo   = detectar_tipo(target)

    if tipo == "desconocido":
        print(f"\n⚠️  No entiendo '{target}'.")
        print("    Ingresa una IP (1.2.3.4), dominio (ejemplo.com),")
        print("    hash MD5/SHA1/SHA256, o URL (https://...).\n")
        return None

    print(f"\n{'─'*55}")
    print(f"  🎯 Analizando : {target}")
    print(f"  📌 Tipo       : {tipo.upper()}")
    print(f"  🕐 Inicio     : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'─'*55}\n")

    system = """Eres un analista de ciberseguridad senior. Analiza el target usando las herramientas disponibles y sé exhaustivo.

Al terminar tu análisis técnico, escribe obligatoriamente este bloque final:

═══ RESUMEN PARA TODOS ═══
Explica los resultados en lenguaje completamente simple, sin jerga técnica, como si se los explicaras a alguien que nunca ha escuchado sobre ciberseguridad. Incluye:
• ¿Qué es este target en palabras simples?
• ¿Es peligroso? ¿Por qué sí o por qué no?
• ¿Qué debería hacer alguien que vio este target en sus registros?
• NIVEL DE RIESGO: CRÍTICO / ALTO / MEDIO / BAJO / LIMPIO
  (explica qué significa ese nivel en una oración)

Responde siempre en español."""

    mensajes   = [{"role": "user", "content": f"Analiza este target: {target}"}]
    tool_calls = 0
    inicio     = time.time()

    nombres_amigables = {
        "check_virustotal":   "🦠 Verificando en 90+ antivirus",
        "check_abuseipdb":    "🚨 Revisando reportes de abuso",
        "check_ipinfo":       "🌍 Obteniendo geolocalización",
        "buscar_cves":        "🔍 Buscando vulnerabilidades conocidas",
        "check_whois":        "📋 Consultando registro del dominio",
        "buscar_subdominios": "🗺️  Mapeando subdominios",
    }

    while True:
        # Forzar conclusión si se alcanza el límite
        if tool_calls >= MAX_TOOL_CALLS:
            mensajes.append({
                "role": "user",
                "content": "Has alcanzado el límite de herramientas. Resume los hallazgos y escribe tu conclusión final ahora."
            })

        try:
            respuesta = client.messages.create(
                model      = "claude-opus-4-5",
                max_tokens = 4096,
                system     = system,
                tools      = TOOLS if tool_calls < MAX_TOOL_CALLS else [],
                messages   = mensajes
            )
        except anthropic.AuthenticationError:
            print("\n❌ ANTHROPIC_API_KEY inválida. Revisa tu archivo .env\n")
            return None
        except anthropic.RateLimitError:
            print("\n⏳ Límite de rate alcanzado. Esperando 30 segundos...\n")
            time.sleep(30)
            continue
        except anthropic.BadRequestError as e:
            print(f"\n❌ Error de solicitud: {e}\n")
            return None

        if respuesta.stop_reason == "tool_use":
            mensajes.append({"role": "assistant", "content": respuesta.content})
            tool_results = []

            for bloque in respuesta.content:
                if bloque.type == "tool_use":
                    tool_calls += 1
                    label = nombres_amigables.get(bloque.name, f"⚙️  {bloque.name}")
                    print(f"{label}...")

                    resultado = ejecutar_herramienta(bloque.name, bloque.input)

                    # Mostrar resultado resumido
                    if "error" in resultado:
                        print(f"   ⚠️  {resultado['error']}\n")
                    elif "veredicto" in resultado:
                        emoji = {"PELIGROSO": "🔴", "SOSPECHOSO": "🟡", "LIMPIO": "🟢"}.get(resultado["veredicto"], "⚪")
                        print(f"   {emoji} {resultado['veredicto']}\n")
                    elif "total" in resultado:
                        print(f"   ✅ {resultado.get('total', 0)} resultados encontrados\n")
                    else:
                        print(f"   ✅ OK\n")

                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": bloque.id,
                        "content":     json.dumps(resultado, ensure_ascii=False)
                    })

            mensajes.append({"role": "user", "content": tool_results})

        else:
            # El agente terminó
            duracion = round(time.time() - inicio, 1)
            analisis = next((b.text for b in respuesta.content if hasattr(b, "text")), "")

            print(f"\n{'═'*55}")
            print(analisis)
            print(f"{'═'*55}")
            print(f"  ⏱️  {duracion}s  |  🔧 {tool_calls} herramientas usadas")
            print(f"{'═'*55}\n")

            return {
                "target":    target,
                "tipo":      tipo,
                "timestamp": datetime.now().isoformat(),
                "duracion":  duracion,
                "analisis":  analisis
            }

# ═══════════════════════════════════════════════════
#  REPORTES E HISTORIAL
# ═══════════════════════════════════════════════════

def guardar_reporte(resultado):
    nombre = re.sub(r'[^\w\-\.]', '_', resultado["target"])
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    path   = REPORTES_DIR / f"{nombre}_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, ensure_ascii=False, indent=2)
    print(f"💾 Reporte guardado en: {path}\n")

def ver_historial():
    archivos = sorted(REPORTES_DIR.glob("*.json"), reverse=True)[:10]
    if not archivos:
        print("\n📂 Aún no hay reportes guardados.\n")
        return
    print(f"\n{'─'*55}")
    print(f"  📂 ÚLTIMOS {len(archivos)} ANÁLISIS")
    print(f"{'─'*55}")
    for i, f in enumerate(archivos, 1):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            print(f"  {i:2}. [{data['tipo'].upper():8}] {data['target']:28} {data['timestamp'][:16]}")
        except Exception:
            print(f"  {i:2}. {f.name}")
    print()

# ═══════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ═══════════════════════════════════════════════════

BANNER = """
╔═══════════════════════════════════════════════════╗
║      🔐 AGENTE DE CIBERSEGURIDAD v2.0 🔐         ║
╠═══════════════════════════════════════════════════╣
║  Analiza: IPs · Dominios · Hashes · URLs          ║
║  Resultados técnicos + explicación para todos     ║
╠═══════════════════════════════════════════════════╣
║  Herramientas: VirusTotal · AbuseIPDB · IPInfo    ║
║                CVE/NVD · WHOIS · Subdominios      ║
╠═══════════════════════════════════════════════════╣
║  Autor: Miguel Ángel Ramírez Galicia              ║
║  GitHub/Handle: MikeUchiha                 2026   ║
╚═══════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print(BANNER)
    while True:
        print("  [1] Analizar un target")
        print("  [2] Ver historial de análisis")
        print("  [3] Salir")
        opcion = input("\n  Elige una opción: ").strip()

        if opcion == "1":
            print("\n  Ejemplos válidos:")
            print("    IP      → 8.8.8.8")
            print("    Dominio → google.com")
            print("    Hash    → d41d8cd98f00b204e9800998ecf8427e")
            print("    URL     → https://sitio-sospechoso.com")
            target = input("\n  🎯 Ingresa el target: ").strip()
            if target:
                resultado = analizar(target)
                if resultado:
                    guardar = input("  ¿Guardar reporte? (s/n): ").strip().lower()
                    if guardar == "s":
                        guardar_reporte(resultado)
            else:
                print("  ⚠️  Escribe algo para analizar.\n")

        elif opcion == "2":
            ver_historial()

        elif opcion == "3":
            print("\n  👋 Hasta luego.\n")
            break

        else:
            print("  ⚠️  Opción inválida. Escribe 1, 2 o 3.\n")