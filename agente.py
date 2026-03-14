import os
import re
import json
import time
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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
    # Nota de seguridad: & y @ removidos de la whitelist (riesgo de command injection)
    # El ; ' " < > también se filtran. DROP/SELECT sin ; son inofensivos para este uso.
    texto = re.sub(r'[^\w\s\.\-\:\/\?\=\%]', '', texto.strip())
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

# ── Marcas conocidas para detectar suplantación ─────
MARCAS_CONOCIDAS = [
    "paypal", "bbva", "banamex", "santander", "hsbc", "banorte",
    "citibank", "chase", "wellsfargo", "bankofamerica",
    "google", "gmail", "facebook", "instagram", "whatsapp",
    "apple", "icloud", "microsoft", "outlook", "netflix",
    "amazon", "mercadolibre", "mercadopago", "sat", "imss",
    "visa", "mastercard", "bancomer", "rappi", "oxxo"
]

def verificar_ssl(url) -> dict:
    """
    Verifica el certificado SSL de una URL sin visitar el sitio.
    Detecta si el certificado es valido, a quien fue emitido,
    cuanto tiempo lleva activo y si el dominio coincide.
    Un SSL valido NO garantiza que el sitio sea seguro.
    """
    try:
        parsed  = urlparse(url if url.startswith("http") else f"https://{url}")
        dominio = parsed.netloc or parsed.path.split("/")[0]
        puerto  = parsed.port or 443

        ctx = ssl.create_default_context()
        with socket.create_connection((dominio, puerto), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()

        # Fechas
        fecha_inicio = datetime.strptime(
            cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        fecha_fin = datetime.strptime(
            cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        ahora        = datetime.now(timezone.utc)
        dias_activo  = (ahora - fecha_inicio).days
        dias_expira  = (fecha_fin - ahora).days

        # Emisor y sujeto
        emisor  = dict(x[0] for x in cert.get("issuer",  []))
        sujeto  = dict(x[0] for x in cert.get("subject", []))
        org_emisor   = emisor.get("organizationName", "Desconocido")
        cn_sujeto    = sujeto.get("commonName", dominio)

        # SANs (Subject Alternative Names)
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        # Alertas
        alertas = []
        if dias_activo < 30:
            alertas.append(f"Certificado muy nuevo: solo {dias_activo} dias de antiguedad")
        if dias_expira < 15:
            alertas.append(f"Certificado vence en {dias_expira} dias")
        if dominio not in cn_sujeto and not any(dominio.endswith(s.lstrip("*")) for s in sans):
            alertas.append("El dominio NO coincide con el certificado (posible MITM)")
        if org_emisor in ("Let's Encrypt", "ZeroSSL", "Desconocido"):
            alertas.append("Certificado gratuito automatico — comun en phishing pero tambien en sitios legitimos")

        return {
            "fuente":          "SSL/TLS directo",
            "dominio":         dominio,
            "valido":          True,
            "emitido_por":     org_emisor,
            "emitido_a":       cn_sujeto,
            "dias_activo":     dias_activo,
            "dias_para_vencer": dias_expira,
            "dominios_cubiertos": sans[:5],
            "alertas_ssl":     alertas,
            "nota":            "SSL valido no garantiza que el sitio sea seguro"
        }

    except ssl.SSLCertVerificationError:
        return {
            "fuente":  "SSL/TLS directo",
            "valido":  False,
            "error":   "Certificado SSL INVALIDO o no confiable — senial de alerta grave",
            "alertas_ssl": ["El navegador mostraria advertencia de seguridad"]
        }
    except ssl.SSLError as e:
        return {"fuente": "SSL/TLS directo", "valido": False, "error": f"Error SSL: {str(e)[:100]}"}
    except Exception as e:
        return {"fuente": "SSL/TLS directo", "error": f"No se pudo verificar SSL: {str(e)[:100]}"}


def analizar_url_phishing(url) -> dict:
    """
    Analiza una URL buscando patrones clasicos de phishing:
    - Suplantacion de marcas conocidas en el dominio
    - Dominios con caracteres parecidos (typosquatting)
    - Estructura de URL sospechosa (muchos subdominios, palabras clave)
    - Palabras de urgencia o engano en la URL
    - Discrepancia entre marca mencionada y dominio real
    """
    if not url.startswith("http"):
        url = "https://" + url

    parsed  = urlparse(url)
    dominio = parsed.netloc.lower()
    path    = parsed.path.lower()
    tld_dominio = dominio.split(".")[-1] if "." in dominio else ""

    # Dominio raiz real (ultimo nivel antes del TLD)
    partes      = dominio.replace("www.", "").split(".")
    dominio_raiz = partes[-2] if len(partes) >= 2 else dominio

    alertas    = []
    positivos  = []

    # 1. Typosquatting: sustitucion de caracteres comunes
    sustituciones = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"}
    dominio_normalizado = dominio
    for k, v in sustituciones.items():
        dominio_normalizado = dominio_normalizado.replace(k, v)

    marca_en_dominio     = None
    marca_en_path        = None
    for marca in MARCAS_CONOCIDAS:
        if marca in dominio_normalizado:
            marca_en_dominio = marca
        if marca in path:
            marca_en_path = marca

    # 2. Marca en dominio pero dominio raiz NO es la marca oficial
    if marca_en_dominio and marca_en_dominio != dominio_raiz:
        alertas.append(
            f"ALERTA CRITICA: Menciona '{marca_en_dominio}' pero el dominio real es '{dominio_raiz}.{tld_dominio}'"
        )
    elif marca_en_dominio and marca_en_dominio == dominio_raiz:
        positivos.append(f"Dominio raiz coincide con la marca '{marca_en_dominio}'")

    # 3. Marca en el path pero no en el dominio (tecnica comun de phishing)
    if marca_en_path and not marca_en_dominio:
        alertas.append(
            f"ALERTA: Menciona '{marca_en_path}' en la ruta pero el dominio es '{dominio_raiz}'"
        )

    # 4. Demasiados subdominios
    n_subdominios = len(partes) - 2
    if n_subdominios >= 3:
        alertas.append(f"URL con {n_subdominios} niveles de subdominio — estructura inusual")
    elif n_subdominios >= 2:
        alertas.append(f"Subdominio multiple detectado: {dominio}")

    # 5. Palabras de urgencia/engano en la URL
    palabras_phishing = [
        "login", "verify", "secure", "update", "confirm", "account",
        "password", "signin", "banking", "alert", "suspended",
        "acceso", "verificar", "seguro", "actualizar", "confirmar",
        "cuenta", "contrasena", "alerta", "suspendido", "urgente"
    ]
    encontradas = [p for p in palabras_phishing if p in dominio + path]
    if len(encontradas) >= 3:
        alertas.append(f"Multiples palabras de engano en la URL: {', '.join(encontradas[:5])}")
    elif len(encontradas) >= 1:
        alertas.append(f"Palabras sospechosas en la URL: {', '.join(encontradas)}")

    # 6. TLD sospechoso (no es regla absoluta pero es indicador)
    tlds_riesgo = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link"]
    if tld_dominio in tlds_riesgo:
        alertas.append(f"TLD '.{tld_dominio}' frecuentemente usado en dominios maliciosos gratuitos")

    # 7. Dominio muy largo
    if len(dominio_raiz) > 20:
        alertas.append(f"Dominio inusualmente largo ({len(dominio_raiz)} caracteres)")

    # 8. Caracteres especiales sospechosos en dominio
    if re.search(r'[^\w\-\.]', dominio):
        alertas.append("Caracteres especiales en el dominio — posible homoglyph attack")

    # Veredicto
    if len(alertas) >= 3:
        veredicto = "MUY SOSPECHOSO"
    elif len(alertas) >= 1:
        veredicto = "SOSPECHOSO"
    else:
        veredicto = "SIN ALERTAS OBVIAS"

    return {
        "fuente":           "Analisis de URL local",
        "url":              url,
        "dominio_raiz":     f"{dominio_raiz}.{tld_dominio}",
        "marca_detectada":  marca_en_dominio or marca_en_path,
        "veredicto_url":    veredicto,
        "alertas":          alertas,
        "positivos":        positivos,
        "limitaciones":     [
            "No analiza el contenido visual del sitio",
            "No detecta phishing en sitios recien creados sin historial",
            "No inspecciona el codigo JavaScript del sitio"
        ]
    }


def verificar_redireccion(url) -> dict:
    """
    Sigue las redirecciones de una URL SIN cargar el contenido completo.
    Detecta si la URL lleva a un dominio diferente al esperado.
    Usa HEAD request para no descargar el sitio.
    """
    if not url.startswith("http"):
        url = "https://" + url

    dominio_original = urlparse(url).netloc.lower()
    historial        = [url]
    alertas          = []

    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (Security Scanner)"}
        )

        url_final        = resp.url
        dominio_final    = urlparse(url_final).netloc.lower()
        historial        = [r.url for r in resp.history] + [url_final]
        n_redirecciones  = len(resp.history)

        # Alertas
        if dominio_final != dominio_original:
            alertas.append(
                f"REDIRIGE a dominio diferente: {dominio_original} → {dominio_final}"
            )

        if n_redirecciones > 3:
            alertas.append(f"Cadena larga de redirecciones: {n_redirecciones} saltos")

        # Detectar acortadores de URL
        acortadores = ["bit.ly", "t.co", "tinyurl", "goo.gl", "ow.ly", "rb.gy", "cutt.ly"]
        if any(a in dominio_original for a in acortadores):
            alertas.append(f"URL acortada detectada — el destino real era: {dominio_final}")

        return {
            "fuente":            "Verificacion de redirecciones",
            "url_original":      url,
            "url_final":         url_final,
            "dominio_original":  dominio_original,
            "dominio_final":     dominio_final,
            "n_redirecciones":   n_redirecciones,
            "hubo_cambio":       dominio_final != dominio_original,
            "cadena":            historial[:6],
            "alertas":           alertas,
            "codigo_http":       resp.status_code
        }

    except requests.exceptions.SSLError:
        return {
            "fuente":   "Verificacion de redirecciones",
            "url":      url,
            "error":    "Error SSL al conectar — el sitio tiene certificado invalido",
            "alertas":  ["Certificado SSL invalido detectado en la conexion"]
        }
    except Exception as e:
        return {
            "fuente":  "Verificacion de redirecciones",
            "url":     url,
            "error":   f"No se pudo conectar: {str(e)[:100]}",
            "alertas": []
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
    {
        "name": "verificar_ssl",
        "description": "Verifica el certificado SSL de una URL. Detecta si es válido, quién lo emitió, hace cuántos días fue creado y si el dominio coincide. Úsala siempre que analices una URL antes de ingresar datos.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL completa o dominio a verificar (ej: https://banco.com o banco.com)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "analizar_url_phishing",
        "description": "Analiza la estructura de una URL buscando patrones de phishing: suplantación de marcas, typosquatting, palabras de engaño, subdominios sospechosos. No necesita conectarse al sitio.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL a analizar (ej: https://bbva-login-secure.com/acceso)"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "verificar_redireccion",
        "description": "Sigue las redirecciones de una URL para ver a dónde lleva realmente, sin cargar el sitio completo. Detecta si la URL lleva a un dominio diferente al esperado o si es una URL acortada.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL a verificar (ej: https://bit.ly/xyz o https://sitio.com)"}
            },
            "required": ["url"]
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
        "verificar_ssl":      lambda p: verificar_ssl(p["url"]),
        "analizar_url_phishing": lambda p: analizar_url_phishing(p["url"]),
        "verificar_redireccion": lambda p: verificar_redireccion(p["url"]),
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

    system = """Eres un analista de ciberseguridad senior especializado en detección de phishing y sitios fraudulentos.

Cuando analices una URL o dominio con intención de verificar si es seguro antes de ingresar datos:
1. Usa analizar_url_phishing para detectar patrones de engaño en la URL
2. Usa verificar_ssl para revisar el certificado
3. Usa verificar_redireccion para ver a dónde lleva realmente
4. Usa check_virustotal para reputación en bases de datos
5. Usa check_whois para ver la edad del dominio

Para otros tipos de target (IPs, hashes, dominios sin URL) usa las herramientas correspondientes.

Al terminar escribe OBLIGATORIAMENTE estos dos bloques:

━━━ VEREDICTO FINAL ━━━
SEGURO / PRECAUCIÓN / NO ENTRES
(una línea explicando por qué)

━━━ RESUMEN PARA TODOS ━━━
Explica en lenguaje completamente simple, sin tecnicismos:
• ¿Qué encontramos?
• ¿Es seguro ingresar datos aquí? ¿Por qué sí o no?
• ¿Qué debería hacer alguien que recibió este link?
• NIVEL DE RIESGO: CRÍTICO / ALTO / MEDIO / BAJO / LIMPIO

━━━ LO QUE NO PUDIMOS VERIFICAR ━━━
Lista honesta de qué limitaciones tuvo este análisis
(diseño visual, scripts JS, comportamiento del formulario, etc.)

Responde siempre en español."""

    mensajes   = [{"role": "user", "content": f"Analiza este target: {target}"}]
    tool_calls = 0
    inicio     = time.time()

    nombres_amigables = {
        "check_virustotal":      "🦠 Verificando en 90+ antivirus",
        "check_abuseipdb":       "🚨 Revisando reportes de abuso",
        "check_ipinfo":          "🌍 Obteniendo geolocalización",
        "buscar_cves":           "🔍 Buscando vulnerabilidades conocidas",
        "check_whois":           "📋 Consultando registro del dominio",
        "buscar_subdominios":    "🗺️  Mapeando subdominios",
        "verificar_ssl":         "🔒 Verificando certificado SSL",
        "analizar_url_phishing": "🎣 Analizando patrones de phishing en la URL",
        "verificar_redireccion": "↪️  Siguiendo redirecciones",
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
╔═══════════════════════════════════════════════════════╗
║       🔐 AGENTE DE CIBERSEGURIDAD v3.0 🔐             ║
╠═══════════════════════════════════════════════════════╣
║  Analiza: IPs · Dominios · Hashes · URLs              ║
║  Verifica sitios ANTES de ingresar tus datos          ║
╠═══════════════════════════════════════════════════════╣
║  VirusTotal · AbuseIPDB · IPInfo · CVE/NVD            ║
║  WHOIS · SSL · Anti-Phishing · Redirecciones          ║
╠═══════════════════════════════════════════════════════╣
║  Autor: MikeUchiha122                                 ║
╚═══════════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print(BANNER)
    while True:
        print("  [1] Analizar un target (IP, dominio, hash)")
        print("  [2] Verificar URL antes de ingresar datos")
        print("  [3] Ver historial de análisis")
        print("  [4] Salir")
        opcion = input("\n  Elige una opción: ").strip()

        if opcion == "1":
            print("\n  Ejemplos:")
            print("    IP      → 8.8.8.8")
            print("    Dominio → google.com")
            print("    Hash    → d41d8cd98f00b204e9800998ecf8427e")
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
            print("\n  Pega la URL que quieres verificar antes de entrar.")
            print("  Ejemplo: https://bbva-login-seguro.com/acceso\n")
            url = input("  🔗 URL a verificar: ").strip()
            if url:
                if not url.startswith("http"):
                    url = "https://" + url
                resultado = analizar(url)
                if resultado:
                    guardar = input("  ¿Guardar reporte? (s/n): ").strip().lower()
                    if guardar == "s":
                        guardar_reporte(resultado)
            else:
                print("  ⚠️  Escribe una URL.\n")

        elif opcion == "3":
            ver_historial()

        elif opcion == "4":
            print("\n  👋 Hasta luego.\n")
            break

        else:
            print("  ⚠️  Opción inválida. Escribe 1, 2, 3 o 4.\n")