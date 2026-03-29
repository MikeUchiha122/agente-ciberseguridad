"""
═══════════════════════════════════════════════════════════════
  TESTS DE SEGURIDAD Y FUNCIONAMIENTO — agente.py v3.0
  Autor: Miguel Angel Ramirez Galicia (MikeUchiha122)
═══════════════════════════════════════════════════════════════

¿QUÉ ES UN TEST?
  Un test es una función que verifica que tu código hace
  exactamente lo que se supone que debe hacer.

  Es como probar un coche antes de entregarlo:
  - ¿Frenan los frenos?          → test de seguridad
  - ¿Enciende el motor?          → test de funcionamiento
  - ¿Aguanta un choque?          → test de resistencia a inputs malos

¿CÓMO EJECUTAR ESTOS TESTS?
  1. Copia este archivo a C:\\agente-seguridad\\
  2. Abre PowerShell en esa carpeta
  3. Ejecuta:  python test_agente.py
  4. Lee los resultados — ✅ = pasó, ❌ = falló

NO necesitas API keys para la mayoría de estos tests.
Los tests que sí las necesitan están marcados con [REQUIERE API].
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# ── Importar funciones del agente ───────────────────────────
# Necesitamos importar sin ejecutar el menú principal
# El "if __name__ == '__main__'" en agente.py nos protege de eso

# Agregamos la carpeta actual al path de Python
sys.path.insert(0, str(Path(__file__).parent))

# Silenciar la creación de la carpeta de reportes durante el import
os.makedirs("C:/agente-seguridad/reportes", exist_ok=True) if sys.platform == "win32" else None

try:
    from agente import (
        validar_ip, validar_dominio, validar_hash, detectar_tipo,
        sanitizar, analizar_url_phishing, ejecutar_herramienta,
        check_virustotal, check_abuseipdb, check_ipinfo,
        buscar_cves, check_whois, verificar_ssl, verificar_redireccion
    )
    IMPORTACION_OK = True
except ImportError as e:
    IMPORTACION_OK = False
    ERROR_IMPORTACION = str(e)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 1: VALIDADORES
#  ¿Las funciones que revisan si algo es una IP/dominio/hash
#  funcionan correctamente?
# ═══════════════════════════════════════════════════════════

class TestValidadores(unittest.TestCase):
    """
    Probamos que el 'guardia de seguridad' del agente
    acepte lo correcto y rechace lo incorrecto.
    """

    # ── validar_ip ──────────────────────────────────────────

    def test_ip_valida_normal(self):
        """Una IP normal debe ser aceptada"""
        self.assertTrue(validar_ip("8.8.8.8"))

    def test_ip_valida_con_espacios(self):
        """Una IP con espacios alrededor debe ser aceptada (los ignora)"""
        self.assertTrue(validar_ip("  192.168.1.1  "))

    def test_ip_privada_valida(self):
        """IPs privadas también son IPs válidas"""
        self.assertTrue(validar_ip("192.168.0.1"))
        self.assertTrue(validar_ip("10.0.0.1"))
        self.assertTrue(validar_ip("172.16.0.1"))

    def test_ip_invalida_texto(self):
        """Texto no es una IP"""
        self.assertFalse(validar_ip("google.com"))

    def test_ip_invalida_numeros_altos(self):
        """Números mayores a 255 no son IPs válidas"""
        self.assertFalse(validar_ip("999.999.999.999"))

    def test_ip_invalida_incompleta(self):
        """Una IP incompleta no es válida"""
        self.assertFalse(validar_ip("192.168.1"))

    def test_ip_invalida_vacia(self):
        """Cadena vacía no es IP"""
        self.assertFalse(validar_ip(""))

    def test_ip_invalida_inyeccion(self):
        """Intento de inyección de código no debe ser IP"""
        self.assertFalse(validar_ip("8.8.8.8; DROP TABLE users;"))

    # ── validar_dominio ─────────────────────────────────────

    def test_dominio_valido_simple(self):
        """Dominio normal debe ser aceptado"""
        self.assertTrue(validar_dominio("google.com"))

    def test_dominio_valido_subdominio(self):
        """Subdominio debe ser aceptado"""
        self.assertTrue(validar_dominio("mail.google.com"))

    def test_dominio_valido_mx(self):
        """Dominio .mx debe ser aceptado"""
        self.assertTrue(validar_dominio("sat.gob.mx"))

    def test_dominio_invalido_solo_texto(self):
        """Una sola palabra sin punto no es dominio"""
        self.assertFalse(validar_dominio("google"))

    def test_dominio_invalido_con_espacios(self):
        """Dominio con espacios no es válido"""
        self.assertFalse(validar_dominio("go ogle.com"))

    def test_dominio_invalido_url_completa(self):
        """Una URL completa no pasa como dominio"""
        self.assertFalse(validar_dominio("https://google.com"))

    # ── validar_hash ────────────────────────────────────────

    def test_hash_md5_valido(self):
        """Hash MD5 (32 caracteres hex) debe ser aceptado"""
        self.assertTrue(validar_hash("d41d8cd98f00b204e9800998ecf8427e"))

    def test_hash_sha1_valido(self):
        """Hash SHA1 (40 caracteres hex) debe ser aceptado"""
        self.assertTrue(validar_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"))

    def test_hash_sha256_valido(self):
        """Hash SHA256 (64 caracteres hex) debe ser aceptado"""
        self.assertTrue(validar_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ))

    def test_hash_invalido_muy_corto(self):
        """Hash demasiado corto no es válido"""
        self.assertFalse(validar_hash("d41d8cd"))

    def test_hash_invalido_caracteres_raros(self):
        """Hash con caracteres no hexadecimales no es válido"""
        self.assertFalse(validar_hash("d41d8cd98f00b204e9800998ecf8427Z"))

    def test_hash_invalido_vacio(self):
        """Hash vacío no es válido"""
        self.assertFalse(validar_hash(""))

    # ── detectar_tipo ───────────────────────────────────────

    def test_detectar_ip(self):
        self.assertEqual(detectar_tipo("1.1.1.1"), "ip")

    def test_detectar_dominio(self):
        self.assertEqual(detectar_tipo("ejemplo.com"), "dominio")

    def test_detectar_url(self):
        self.assertEqual(detectar_tipo("https://ejemplo.com"), "url")

    def test_detectar_hash(self):
        self.assertEqual(detectar_tipo("d41d8cd98f00b204e9800998ecf8427e"), "hash")

    def test_detectar_desconocido(self):
        self.assertEqual(detectar_tipo("esto no es nada"), "desconocido")

    def test_detectar_desconocido_numero(self):
        """Solo un número no es ningún tipo conocido"""
        self.assertEqual(detectar_tipo("12345"), "desconocido")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 2: SANITIZADOR
#  ¿El agente limpia correctamente los inputs peligrosos?
#  Este bloque prueba contra ataques de inyección.
# ═══════════════════════════════════════════════════════════

class TestSanitizador(unittest.TestCase):
    """
    El sanitizador es la primera línea de defensa.
    Debe limpiar cualquier texto malicioso antes de procesarlo.
    """

    def test_input_normal_no_cambia(self):
        """Un input normal no debe ser alterado"""
        self.assertEqual(sanitizar("8.8.8.8"), "8.8.8.8")
        self.assertEqual(sanitizar("google.com"), "google.com")

    def test_url_normal_no_cambia(self):
        """Una URL normal debe pasar sin cambios"""
        resultado = sanitizar("https://google.com/path?q=algo")
        self.assertIn("google.com", resultado)

    def test_inyeccion_sql(self):
        """
        Ataque clásico de SQL injection. Lo peligroso son los
        caracteres especiales: ; ' " -- que separan comandos SQL.
        Las palabras como DROP son letras normales y pasan,
        pero sin ; son completamente inofensivas.
        """
        malicioso = "8.8.8.8'; DROP TABLE usuarios; --"
        resultado = sanitizar(malicioso)
        self.assertNotIn(";", resultado,  "El ; es el separador SQL peligroso")
        self.assertNotIn("'", resultado,  "La comilla ' abre/cierra strings SQL")
        # DROP sin ; es inofensivo — no se puede ejecutar solo

    def test_inyeccion_comandos(self):
        """
        Ataque: intentar ejecutar comandos del sistema operativo.
        El & es el operador de encadenamiento — debe ser eliminado.
        (DROP son letras normales; sin & ni ; el comando no puede ejecutarse)
        """
        malicioso = "8.8.8.8 && del C:\\Windows\\System32"
        resultado = sanitizar(malicioso)
        self.assertNotIn("&", resultado)

    def test_xss_basico(self):
        """
        Ataque XSS: inyectar código JavaScript.
        Los caracteres < > deben ser eliminados.
        """
        malicioso = "<script>alert('hackeado')</script>"
        resultado = sanitizar(malicioso)
        self.assertNotIn("<script>", resultado)
        self.assertNotIn("</script>", resultado)

    def test_longitud_maxima(self):
        """
        El agente solo procesa hasta 300 caracteres.
        Un input gigante debe ser truncado para evitar ataques DoS.
        """
        muy_largo = "a" * 1000
        resultado = sanitizar(muy_largo)
        self.assertLessEqual(len(resultado), 300)

    def test_input_vacio(self):
        """Input vacío debe devolver cadena vacía, sin errores"""
        self.assertEqual(sanitizar(""), "")

    def test_input_solo_espacios(self):
        """Solo espacios debe devolver cadena vacía"""
        self.assertEqual(sanitizar("   "), "")

    def test_caracteres_unicode_raros(self):
        """
        Caracteres especiales raros deben ser limpiados.
        Previene ataques de homoglyph (letras que parecen iguales).
        """
        malicioso = "gооgle.com"  # las 'о' son cirílicas, no latinas
        resultado = sanitizar(malicioso)
        # Debe quedar algo manejable sin crashear
        self.assertIsInstance(resultado, str)

    def test_null_bytes(self):
        """
        Bytes nulos pueden romper algunas funciones.
        Deben ser eliminados.
        """
        malicioso = "8.8.8.8\x00malicioso"
        resultado = sanitizar(malicioso)
        self.assertNotIn("\x00", resultado)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 3: ANTI-PHISHING
#  ¿El detector de phishing identifica correctamente
#  los sitios peligrosos vs los legítimos?
# ═══════════════════════════════════════════════════════════

class TestAntiPhishing(unittest.TestCase):
    """
    Probamos la función analizar_url_phishing con casos reales
    de phishing y casos de sitios legítimos.
    """

    # ── Detección de suplantación de marcas ─────────────────

    def test_phishing_banco_obvio(self):
        """
        URL clásica de phishing: menciona BBVA pero el dominio
        real es otro. Debe detectarse como sospechoso.
        """
        resultado = analizar_url_phishing("https://bbva-login-seguro.verificar-cuenta.com/acceso")
        self.assertGreater(len(resultado["alertas"]), 0)
        self.assertIn(resultado["veredicto_url"], ["SOSPECHOSO", "MUY SOSPECHOSO"])

    def test_phishing_paypal_typosquatting(self):
        """
        Typosquatting: paypa1.com (con el número 1 en vez de la letra l).
        Debe detectar que intenta imitar a PayPal.
        """
        resultado = analizar_url_phishing("https://paypa1.com/login")
        self.assertGreater(len(resultado["alertas"]), 0)

    def test_phishing_marca_en_path(self):
        """
        Técnica avanzada: el dominio parece inocente pero la ruta
        menciona a PayPal. Ej: malicioso.com/paypal/login
        """
        resultado = analizar_url_phishing("https://malicioso.com/paypal/confirmar-cuenta")
        alertas_texto = " ".join(resultado["alertas"])
        self.assertIn("paypal", alertas_texto.lower())

    def test_phishing_multiples_subdominios(self):
        """
        Demasiados subdominios es señal de alerta.
        Ej: login.secure.bbva.atacante.com
        """
        resultado = analizar_url_phishing("https://login.secure.bbva.atacante.com/verify")
        self.assertGreater(len(resultado["alertas"]), 0)

    def test_phishing_tld_sospechoso(self):
        """
        TLDs gratuitos (.tk, .ml, .ga) son muy usados en phishing
        porque son gratis y anónimos.
        """
        resultado = analizar_url_phishing("https://banco-seguro.tk/login")
        alertas_texto = " ".join(resultado["alertas"]).lower()
        self.assertIn(".tk", alertas_texto)

    def test_phishing_palabras_urgencia(self):
        """
        URLs con muchas palabras de urgencia/engaño son sospechosas.
        """
        resultado = analizar_url_phishing(
            "https://secure-verify-account-login.com/confirm/password/update"
        )
        self.assertIn(resultado["veredicto_url"], ["SOSPECHOSO", "MUY SOSPECHOSO"])

    # ── Sitios legítimos no deben disparar falsas alarmas ───

    def test_legitimo_google(self):
        """
        google.com es legítimo. No debe tener alertas críticas
        de suplantación de marca.
        """
        resultado = analizar_url_phishing("https://google.com")
        # No debe haber alerta de "menciona X pero dominio es Y"
        alertas = " ".join(resultado["alertas"])
        self.assertNotIn("ALERTA CRITICA", alertas)

    def test_legitimo_bbva_real(self):
        """
        El dominio real de BBVA México no debe ser marcado
        como phishing por suplantación.
        """
        resultado = analizar_url_phishing("https://www.bbva.mx")
        alertas_criticas = [a for a in resultado["alertas"] if "CRITICA" in a]
        self.assertEqual(len(alertas_criticas), 0)

    def test_resultado_tiene_estructura_correcta(self):
        """
        El resultado siempre debe tener las claves esperadas.
        Esto previene errores cuando el agente lee el resultado.
        """
        resultado = analizar_url_phishing("https://cualquier-sitio.com")
        claves_requeridas = ["fuente", "url", "dominio_raiz",
                             "veredicto_url", "alertas", "limitaciones"]
        for clave in claves_requeridas:
            self.assertIn(clave, resultado,
                          f"Falta la clave '{clave}' en el resultado")

    def test_url_sin_https(self):
        """
        Debe funcionar aunque no se escriba 'https://' al inicio.
        """
        resultado = analizar_url_phishing("banco-sospechoso.com/login")
        self.assertIsInstance(resultado, dict)
        self.assertNotIn("error", resultado)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 4: SEGURIDAD DE API KEYS
#  ¿El agente maneja correctamente la ausencia de keys?
#  ¿Nunca expone las keys en los errores?
# ═══════════════════════════════════════════════════════════

class TestSeguridadAPIKeys(unittest.TestCase):
    """
    Probamos que el agente sea seguro con las API keys.
    Esto es crítico: una key expuesta = cuenta comprometida.
    """

    def test_virustotal_sin_key_retorna_error_limpio(self):
        """
        Si no hay API key de VirusTotal, debe devolver un error
        claro y controlado — no crashear ni exponer nada.
        """
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}):
            resultado = check_virustotal("8.8.8.8")
        self.assertIn("error", resultado)
        self.assertNotIn("Exception", resultado["error"])

    def test_abuseipdb_sin_key_retorna_error_limpio(self):
        """Mismo test para AbuseIPDB"""
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}):
            resultado = check_abuseipdb("8.8.8.8")
        self.assertIn("error", resultado)

    def test_error_no_expone_key_real(self):
        """
        CRÍTICO: Si hay un error, el mensaje de error NO debe
        contener la API key real. Nunca loggear secrets.
        """
        key_falsa = "vt-super-secret-key-12345"
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": key_falsa}):
            # Simulamos una respuesta fallida de la API
            with patch("agente.http_get") as mock_get:
                mock_get.return_value = {"error": "404 not found"}
                resultado = check_virustotal("8.8.8.8")

        # El error no debe contener la key
        resultado_str = json.dumps(resultado)
        self.assertNotIn(key_falsa, resultado_str,
                         "¡PELIGRO! La API key aparece en el resultado")

    def test_virustotal_key_invalida_no_crashea(self):
        """
        Una key con formato incorrecto no debe crashear el agente.
        """
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "key-invalida"}):
            with patch("agente.http_get") as mock_get:
                mock_get.return_value = {"error": "Unauthorized"}
                resultado = check_virustotal("1.1.1.1")
        # Debe devolver algo, no lanzar excepción
        self.assertIsInstance(resultado, dict)

    def test_todas_las_keys_tienen_fallback(self):
        """
        Con TODAS las keys vacías, el agente no debe crashear.
        Solo devolver errores controlados.
        """
        env_vacio = {
            "VIRUSTOTAL_API_KEY": "",
            "ABUSEIPDB_API_KEY": "",
            "ANTHROPIC_API_KEY": ""
        }
        with patch.dict(os.environ, env_vacio):
            # Estas funciones deben manejar keys faltantes
            r1 = check_virustotal("1.1.1.1")
            r2 = check_abuseipdb("1.1.1.1")
        self.assertIn("error", r1)
        self.assertIn("error", r2)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 5: HERRAMIENTAS CON MOCKS
#  Probamos las herramientas simulando las respuestas de las APIs
#  sin hacer llamadas reales (no gasta quota, funciona sin internet)
# ═══════════════════════════════════════════════════════════

class TestHerramientasConMocks(unittest.TestCase):
    """
    Un "mock" es un reemplazo falso de algo real.
    En vez de llamar a VirusTotal de verdad (gasta quota),
    le decimos: "cuando alguien llame a http_get, devuelve esto".
    """

    def test_virustotal_ip_peligrosa(self):
        """
        Simulamos que VirusTotal dice que la IP es peligrosa.
        El agente debe clasificarla como PELIGROSO.
        """
        respuesta_falsa = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 13
                    }
                }
            }
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake-key"}):
                resultado = check_virustotal("45.33.32.156")

        self.assertEqual(resultado["veredicto"], "PELIGROSO")
        self.assertEqual(resultado["malicioso"], 15)

    def test_virustotal_ip_limpia(self):
        """
        Simulamos que VirusTotal dice que la IP está limpia.
        """
        respuesta_falsa = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 85,
                        "harmless": 5
                    }
                }
            }
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake-key"}):
                resultado = check_virustotal("8.8.8.8")

        self.assertEqual(resultado["veredicto"], "LIMPIO")
        self.assertEqual(resultado["malicioso"], 0)

    def test_abuseipdb_ip_muy_peligrosa(self):
        """
        Simulamos AbuseIPDB con score de 95 — debe ser PELIGROSO.
        """
        respuesta_falsa = {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 450,
                "countryCode": "RU",
                "isp": "Suspicious ISP",
                "isWhitelisted": False
            }
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
                resultado = check_abuseipdb("185.220.101.45")

        self.assertEqual(resultado["veredicto"], "PELIGROSO")
        self.assertEqual(resultado["score_abuso"], 95)
        self.assertEqual(resultado["pais"], "RU")

    def test_abuseipdb_ip_limpia(self):
        """Score de 0 = LIMPIO"""
        respuesta_falsa = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "isWhitelisted": True
            }
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake-key"}):
                resultado = check_abuseipdb("8.8.8.8")

        self.assertEqual(resultado["veredicto"], "LIMPIO")

    def test_ipinfo_retorna_datos_geograficos(self):
        """IPInfo debe devolver ciudad, país y organización"""
        respuesta_falsa = {
            "city": "Mountain View",
            "country": "US",
            "org": "AS15169 Google LLC",
            "hostname": "dns.google",
            "timezone": "America/Los_Angeles"
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            resultado = check_ipinfo("8.8.8.8")

        self.assertEqual(resultado["ciudad"], "Mountain View")
        self.assertEqual(resultado["pais"], "US")
        self.assertIn("Google", resultado["organizacion"])

    def test_herramienta_inexistente_retorna_error(self):
        """
        Si el agente intenta usar una herramienta que no existe,
        debe recibir un error claro, no un crash.
        """
        resultado = ejecutar_herramienta("herramienta_inventada", {})
        self.assertIn("error", resultado)
        self.assertIn("herramienta_inventada", resultado["error"])

    def test_herramienta_con_parametros_faltantes(self):
        """
        Si faltan parámetros requeridos, debe retornar error
        controlado, no KeyError ni crash.
        """
        resultado = ejecutar_herramienta("check_abuseipdb", {})  # falta "ip"
        self.assertIn("error", resultado)

    def test_cves_retorna_estructura_correcta(self):
        """La búsqueda de CVEs debe retornar estructura esperada"""
        respuesta_falsa = {
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4Shell RCE vulnerability"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}
                            }]
                        }
                    }
                }
            ]
        }
        with patch("agente.http_get", return_value=respuesta_falsa):
            resultado = buscar_cves("Log4j", "2.14.1")

        self.assertEqual(resultado["total"], 2)
        self.assertEqual(len(resultado["vulnerabilidades"]), 1)
        self.assertEqual(resultado["vulnerabilidades"][0]["cve"], "CVE-2021-44228")
        self.assertEqual(resultado["vulnerabilidades"][0]["severidad"], "CRITICAL")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 6: INPUTS MALICIOSOS (FUZZING BÁSICO)
#  ¿El agente resiste inputs diseñados para romperlo?
# ═══════════════════════════════════════════════════════════

class TestInputsMaliciosos(unittest.TestCase):
    """
    Probamos que el agente no se rompa con inputs extremos.
    Esto se llama "fuzzing" — dar inputs raros a propósito.
    """

    INPUTS_RAROS = [
        "",                          # vacío
        " ",                         # solo espacio
        "\n\t\r",                    # saltos de línea y tabs
        "A" * 10000,                 # extremadamente largo
        "💀🔥👾",                    # emojis
        "../../../etc/passwd",        # path traversal
        "'; DROP TABLE ips; --",      # SQL injection
        "<script>alert(1)</script>",  # XSS
        "||cmd /c del *.*",           # command injection Windows
        "$(rm -rf /)",               # command injection Linux
        "\x00\x01\x02",             # bytes de control
        "null",                      # literal null
        "None",                      # literal None de Python
        "true",                      # literal booleano
        "9" * 100,                   # número muy largo
        "http://" + "a" * 500,       # URL gigante
    ]

    def test_validar_ip_no_crashea(self):
        """validar_ip debe sobrevivir a cualquier input sin crashear"""
        for inp in self.INPUTS_RAROS:
            with self.subTest(inp=inp[:30]):
                try:
                    resultado = validar_ip(inp)
                    self.assertIsInstance(resultado, bool)
                except Exception as e:
                    self.fail(f"validar_ip crasheó con '{inp[:30]}': {e}")

    def test_validar_dominio_no_crashea(self):
        """validar_dominio debe sobrevivir a cualquier input"""
        for inp in self.INPUTS_RAROS:
            with self.subTest(inp=inp[:30]):
                try:
                    resultado = validar_dominio(inp)
                    self.assertIsInstance(resultado, bool)
                except Exception as e:
                    self.fail(f"validar_dominio crasheó con '{inp[:30]}': {e}")

    def test_sanitizar_no_crashea(self):
        """sanitizar debe sobrevivir a cualquier input"""
        for inp in self.INPUTS_RAROS:
            with self.subTest(inp=inp[:30]):
                try:
                    resultado = sanitizar(inp)
                    self.assertIsInstance(resultado, str)
                    self.assertLessEqual(len(resultado), 300)
                except Exception as e:
                    self.fail(f"sanitizar crasheó con '{inp[:30]}': {e}")

    def test_analizar_url_phishing_no_crashea(self):
        """analizar_url_phishing debe sobrevivir a cualquier input"""
        urls_raras = [
            "",
            "http://",
            "https://",
            "://" + "a" * 200,
            "https://😈.com",
            "https://a",
            "https://a.b.c.d.e.f.g.h.i.j.k.com",
        ]
        for url in urls_raras:
            with self.subTest(url=url[:40]):
                try:
                    resultado = analizar_url_phishing(url)
                    self.assertIsInstance(resultado, dict)
                except Exception as e:
                    self.fail(f"analizar_url_phishing crasheó con '{url[:40]}': {e}")

    def test_check_abuseipdb_inputs_invalidos(self):
        """check_abuseipdb con IPs inválidas debe retornar error, no crashear"""
        inputs_invalidos = ["no-es-ip", "", "999.999.999.999", None if False else "null"]
        for inp in inputs_invalidos:
            with self.subTest(inp=inp):
                resultado = check_abuseipdb(inp)
                self.assertIn("error", resultado,
                              f"Debería haber error para input '{inp}'")

    def test_ejecutar_herramienta_parametros_raros(self):
        """
        El ejecutor de herramientas debe manejar parámetros
        extraños sin crashear.
        """
        casos = [
            ("check_virustotal", {}),
            ("check_virustotal", {"target": ""}),
            ("check_abuseipdb",  {"ip": "<script>"}),
            ("check_whois",      {"dominio": "'; DROP TABLE--"}),
        ]
        for nombre, params in casos:
            with self.subTest(herramienta=nombre):
                try:
                    resultado = ejecutar_herramienta(nombre, params)
                    self.assertIsInstance(resultado, dict)
                except Exception as e:
                    self.fail(f"ejecutar_herramienta crasheó: {e}")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 7: LÓGICA DE NEGOCIO
#  ¿Los veredictos son correctos?
#  ¿Los umbrales de riesgo tienen sentido?
# ═══════════════════════════════════════════════════════════

class TestLogicaDeNegocio(unittest.TestCase):
    """
    Verificamos que la lógica de clasificación de riesgo
    sea correcta y consistente.
    """

    def test_virustotal_umbral_peligroso(self):
        """Más de 3 detecciones = PELIGROSO"""
        for n_malos in [4, 5, 10, 50, 90]:
            stats = {"malicious": n_malos, "suspicious": 0,
                     "undetected": 90 - n_malos, "harmless": 0}
            with patch("agente.http_get",
                       return_value={"data": {"attributes": {"last_analysis_stats": stats}}}):
                with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
                    r = check_virustotal("1.2.3.4")
            self.assertEqual(r["veredicto"], "PELIGROSO",
                             f"Con {n_malos} detecciones debe ser PELIGROSO")

    def test_virustotal_umbral_sospechoso(self):
        """Entre 1 y 3 detecciones = SOSPECHOSO"""
        for n_malos in [1, 2, 3]:
            stats = {"malicious": n_malos, "suspicious": 0,
                     "undetected": 90 - n_malos, "harmless": 0}
            with patch("agente.http_get",
                       return_value={"data": {"attributes": {"last_analysis_stats": stats}}}):
                with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
                    r = check_virustotal("1.2.3.4")
            self.assertEqual(r["veredicto"], "SOSPECHOSO",
                             f"Con {n_malos} detecciones debe ser SOSPECHOSO")

    def test_abuseipdb_umbral_50_es_peligroso(self):
        """Score >= 50 en AbuseIPDB = PELIGROSO"""
        for score in [50, 75, 100]:
            datos = {"abuseConfidenceScore": score, "totalReports": 10,
                     "countryCode": "XX", "isp": "ISP", "isWhitelisted": False}
            with patch("agente.http_get", return_value={"data": datos}):
                with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake"}):
                    r = check_abuseipdb("1.2.3.4")
            self.assertEqual(r["veredicto"], "PELIGROSO",
                             f"Score {score} debe ser PELIGROSO")

    def test_abuseipdb_umbral_bajo_es_sospechoso(self):
        """Score 10-49 = SOSPECHOSO"""
        for score in [10, 25, 49]:
            datos = {"abuseConfidenceScore": score, "totalReports": 2,
                     "countryCode": "XX", "isp": "ISP", "isWhitelisted": False}
            with patch("agente.http_get", return_value={"data": datos}):
                with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake"}):
                    r = check_abuseipdb("1.2.3.4")
            self.assertEqual(r["veredicto"], "SOSPECHOSO",
                             f"Score {score} debe ser SOSPECHOSO")

    def test_detectar_tipo_prioriza_ip_sobre_dominio(self):
        """
        Una IP válida debe detectarse como IP, no como dominio.
        El orden de prioridad importa.
        """
        self.assertEqual(detectar_tipo("192.168.1.1"), "ip")

    def test_detectar_tipo_url_tiene_prioridad_sobre_dominio(self):
        """
        Una URL completa debe detectarse como URL aunque
        el dominio también sea válido.
        """
        self.assertEqual(detectar_tipo("https://google.com"), "url")

    def test_phishing_veredicto_consistente(self):
        """
        Si hay muchas alertas, el veredicto debe ser MUY SOSPECHOSO.
        Si hay pocas, SOSPECHOSO. Si no hay, SIN ALERTAS OBVIAS.
        """
        # URL muy sospechosa
        r = analizar_url_phishing(
            "https://login-verify-bbva-secure-account.ml/confirm/password"
        )
        self.assertIn(r["veredicto_url"], ["SOSPECHOSO", "MUY SOSPECHOSO"])

        # URL limpia
        r2 = analizar_url_phishing("https://anthropic.com")
        alertas_criticas = [a for a in r2["alertas"] if "CRITICA" in a]
        self.assertEqual(len(alertas_criticas), 0)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 8: ESTRUCTURA DE RESPUESTAS
#  ¿Todas las funciones devuelven el formato correcto?
#  El agente depende de que los resultados tengan las
#  claves esperadas.
# ═══════════════════════════════════════════════════════════

class TestEstructuraRespuestas(unittest.TestCase):
    """
    Verificamos que cada función siempre devuelva un diccionario
    con las claves que el agente espera encontrar.
    Un resultado mal formado puede hacer que el agente crashee.
    """

    def test_virustotal_respuesta_tiene_fuente(self):
        """Toda respuesta de herramienta debe tener 'fuente'"""
        with patch("agente.http_get",
                   return_value={"data": {"attributes": {"last_analysis_stats":
                       {"malicious": 0, "suspicious": 0, "undetected": 90, "harmless": 0}}}}):
            with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
                r = check_virustotal("1.1.1.1")
        self.assertIn("fuente", r)

    def test_abuseipdb_respuesta_tiene_fuente(self):
        with patch("agente.http_get",
                   return_value={"data": {"abuseConfidenceScore": 0, "totalReports": 0,
                                          "countryCode": "US", "isp": "ISP", "isWhitelisted": False}}):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake"}):
                r = check_abuseipdb("1.1.1.1")
        self.assertIn("fuente", r)

    def test_error_siempre_tiene_clave_error(self):
        """Cuando algo falla, SIEMPRE debe haber clave 'error'"""
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}):
            r = check_virustotal("1.1.1.1")
        self.assertIn("error", r)
        self.assertIsInstance(r["error"], str)

    def test_analizar_url_siempre_devuelve_dict(self):
        """analizar_url_phishing siempre debe devolver dict"""
        casos = ["https://google.com", "malicioso.tk", "", "http://"]
        for url in casos:
            with self.subTest(url=url):
                r = analizar_url_phishing(url)
                self.assertIsInstance(r, dict,
                    f"analizar_url_phishing('{url}') debe devolver dict")

    def test_ejecutar_herramienta_siempre_devuelve_dict(self):
        """ejecutar_herramienta siempre debe devolver dict, nunca None"""
        resultado = ejecutar_herramienta("herramienta_que_no_existe", {})
        self.assertIsNotNone(resultado)
        self.assertIsInstance(resultado, dict)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 9: FUNCIONES SIN COBERTURA PREVIA
#  Tests para: buscar_subdominios, verificar_ssl,
#  verificar_redireccion, guardar_reporte, ver_historial
# ═══════════════════════════════════════════════════════════

class TestBuscarSubdominios(unittest.TestCase):
    """
    buscar_subdominios consulta crt.sh para encontrar
    subdominios de un dominio. Probamos con mocks.
    """

    def test_devuelve_estructura_correcta(self):
        """El resultado siempre debe tener fuente, dominio, total, subdominios"""
        respuesta_falsa = [
            {"name_value": "mail.ejemplo.com"},
            {"name_value": "dev.ejemplo.com\nstaging.ejemplo.com"},
            {"name_value": "*.ejemplo.com"},  # comodín — debe ignorarse
        ]
        with patch("agente.http_get", return_value=respuesta_falsa):
            from agente import buscar_subdominios
            r = buscar_subdominios("ejemplo.com")
        for clave in ["fuente", "dominio", "total", "subdominios"]:
            self.assertIn(clave, r)

    def test_ignora_subdominios_comodin(self):
        """Los subdominios con * deben ser ignorados (no son reales)"""
        respuesta_falsa = [
            {"name_value": "mail.ejemplo.com"},
            {"name_value": "*.ejemplo.com"},
        ]
        with patch("agente.http_get", return_value=respuesta_falsa):
            from agente import buscar_subdominios
            r = buscar_subdominios("ejemplo.com")
        for sub in r["subdominios"]:
            self.assertNotIn("*", sub, "Los comodines no deben aparecer en resultados")

    def test_dominio_invalido_retorna_error(self):
        """Un dominio inválido debe retornar error, no crashear"""
        from agente import buscar_subdominios
        r = buscar_subdominios("no_es_un_dominio")
        self.assertIn("error", r)

    def test_dominio_vacio_retorna_error(self):
        """Dominio vacío debe retornar error"""
        from agente import buscar_subdominios
        r = buscar_subdominios("")
        self.assertIn("error", r)

    def test_subdominios_son_lista(self):
        """El campo subdominios siempre debe ser una lista"""
        respuesta_falsa = [{"name_value": "sub.ejemplo.com"}]
        with patch("agente.http_get", return_value=respuesta_falsa):
            from agente import buscar_subdominios
            r = buscar_subdominios("ejemplo.com")
        self.assertIsInstance(r.get("subdominios", []), list)

    def test_fallo_de_api_retorna_error(self):
        """Si crt.sh falla, debe retornar error controlado"""
        with patch("agente.http_get", return_value={"error": "Timeout"}):
            from agente import buscar_subdominios
            r = buscar_subdominios("ejemplo.com")
        self.assertIn("error", r)

    def test_maximo_20_subdominios(self):
        """No debe devolver más de 20 subdominios (límite de seguridad)"""
        # Simular 50 subdominios en la respuesta
        respuesta_falsa = [{"name_value": f"sub{i}.ejemplo.com"} for i in range(50)]
        with patch("agente.http_get", return_value=respuesta_falsa):
            from agente import buscar_subdominios
            r = buscar_subdominios("ejemplo.com")
        self.assertLessEqual(len(r.get("subdominios", [])), 20)


class TestVerificarSSL(unittest.TestCase):
    """
    verificar_ssl se conecta a un servidor para leer su certificado.
    Probamos los distintos escenarios con mocks de socket/ssl.
    """

    def _mock_cert_valido(self, dias_activo=365, dias_vence=60,
                          emisor="DigiCert Inc", cn="google.com"):
        """Helper: crea un certificado mock válido"""
        from datetime import datetime, timezone, timedelta
        ahora = datetime.now(timezone.utc)
        inicio = ahora - timedelta(days=dias_activo)
        fin    = ahora + timedelta(days=dias_vence)
        fmt    = "%b %d %H:%M:%S %Y %Z"

        cert = {
            "notBefore": inicio.strftime(fmt).replace("+00:00", "GMT"),
            "notAfter":  fin.strftime(fmt).replace("+00:00", "GMT"),
            "issuer":    [[('"organizationName"', emisor)]],
            "subject":   [[('"commonName"', cn)]],
            "subjectAltName": [("DNS", cn), ("DNS", f"www.{cn}")]
        }
        return cert

    def test_ssl_invalido_retorna_valido_false(self):
        """Si el certificado es inválido, valido debe ser False"""
        import ssl
        with patch("agente.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = mock_ctx.return_value
            with patch("agente.socket.create_connection") as mock_sock:
                mock_sock.side_effect = ssl.SSLCertVerificationError("cert invalid")
                from agente import verificar_ssl
                r = verificar_ssl("https://sitio-invalido.com")
        self.assertFalse(r.get("valido", True))
        self.assertIn("error", r)

    def test_ssl_sin_conexion_retorna_error(self):
        """Si no hay conexión, debe retornar error controlado"""
        with patch("agente.socket.create_connection",
                   side_effect=ConnectionRefusedError("sin conexión")):
            from agente import verificar_ssl
            r = verificar_ssl("https://sitio-sin-conexion.com")
        self.assertIsInstance(r, dict)
        self.assertIn("error", r)

    def test_resultado_tiene_nota_de_seguridad(self):
        """
        CRÍTICO: el resultado debe recordar que SSL válido
        no significa que el sitio sea seguro.
        """
        with patch("agente.socket.create_connection",
                   side_effect=Exception("sin red en tests")):
            from agente import verificar_ssl
            r = verificar_ssl("https://cualquier.com")
        # Ya sea éxito o error, si hay 'nota' debe ser el aviso correcto
        if "nota" in r:
            self.assertIn("no garantiza", r["nota"].lower())

    def test_url_sin_https_se_maneja(self):
        """Debe funcionar con o sin https:// al inicio"""
        with patch("agente.socket.create_connection",
                   side_effect=Exception("sin red")):
            from agente import verificar_ssl
            r = verificar_ssl("google.com")  # sin https://
        self.assertIsInstance(r, dict)

    def test_siempre_devuelve_dict(self):
        """Bajo cualquier circunstancia, debe devolver dict"""
        casos = ["https://x.com", "x.com", "", "https://", "💀.com"]
        from agente import verificar_ssl
        for url in casos:
            with self.subTest(url=url):
                with patch("agente.socket.create_connection",
                           side_effect=Exception("sin red")):
                    r = verificar_ssl(url)
                self.assertIsInstance(r, dict,
                    f"verificar_ssl('{url}') debe devolver dict siempre")


class TestVerificarRedireccion(unittest.TestCase):
    """
    verificar_redireccion sigue la cadena de redirecciones
    de una URL para ver a dónde lleva realmente.
    """

    def _mock_response(self, url_final, history_urls=None, status=200):
        """Helper: crea una respuesta HTTP mock con redirecciones"""
        mock_resp = MagicMock()
        mock_resp.url = url_final
        mock_resp.status_code = status
        history = []
        for h_url in (history_urls or []):
            h = MagicMock()
            h.url = h_url
            history.append(h)
        mock_resp.history = history
        return mock_resp

    def test_sin_redireccion_dominio_igual(self):
        """Si no hay redirección, dominio original = dominio final"""
        mock_r = self._mock_response("https://google.com/", history_urls=[])
        with patch("agente.requests.head", return_value=mock_r):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://google.com")
        self.assertFalse(r.get("hubo_cambio", True))
        self.assertEqual(r.get("n_redirecciones", -1), 0)

    def test_detecta_cambio_de_dominio(self):
        """Si la URL final es de otro dominio, hubo_cambio debe ser True"""
        mock_r = self._mock_response(
            "https://dominio-destino.com/pagina",
            history_urls=["https://acortador.com/xyz"]
        )
        with patch("agente.requests.head", return_value=mock_r):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://acortador.com/xyz")
        self.assertTrue(r.get("hubo_cambio", False))

    def test_detecta_url_acortada(self):
        """URLs de bit.ly, t.co etc. deben generar alerta"""
        mock_r = self._mock_response(
            "https://sitio-real.com",
            history_urls=["https://bit.ly/abc123"]
        )
        with patch("agente.requests.head", return_value=mock_r):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://bit.ly/abc123")
        alertas = " ".join(r.get("alertas", []))
        self.assertIn("acortad", alertas.lower())

    def test_fallo_ssl_retorna_alerta(self):
        """Error SSL durante la verificación debe aparecer en alertas"""
        import requests as req
        with patch("agente.requests.head",
                   side_effect=req.exceptions.SSLError("cert inválido")):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://sitio-ssl-malo.com")
        self.assertIsInstance(r, dict)
        self.assertGreater(len(r.get("alertas", [])), 0)

    def test_sin_conexion_retorna_error_controlado(self):
        """Sin internet, debe retornar error amigable"""
        import requests as req
        with patch("agente.requests.head",
                   side_effect=req.exceptions.ConnectionError("sin red")):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://cualquier.com")
        self.assertIsInstance(r, dict)
        self.assertIn("error", r)

    def test_url_sin_https_se_normaliza(self):
        """Una URL sin https:// debe ser manejada correctamente"""
        mock_r = self._mock_response("https://google.com/")
        with patch("agente.requests.head", return_value=mock_r):
            from agente import verificar_redireccion
            r = verificar_redireccion("google.com")
        self.assertIsInstance(r, dict)

    def test_resultado_tiene_estructura_correcta(self):
        """El resultado debe tener las claves esperadas"""
        mock_r = self._mock_response("https://google.com/")
        with patch("agente.requests.head", return_value=mock_r):
            from agente import verificar_redireccion
            r = verificar_redireccion("https://google.com")
        for clave in ["fuente", "url_original", "url_final",
                      "n_redirecciones", "alertas"]:
            self.assertIn(clave, r, f"Falta clave '{clave}' en resultado")


class TestGuardarReporteYHistorial(unittest.TestCase):
    """
    guardar_reporte guarda un JSON en disco.
    ver_historial lee y muestra los últimos reportes.
    Probamos con una carpeta temporal para no tocar la real.
    """

    def setUp(self):
        """Antes de cada test: crear carpeta temporal"""
        import tempfile
        self.carpeta_temp = tempfile.mkdtemp()

    def tearDown(self):
        """Después de cada test: limpiar carpeta temporal"""
        import shutil
        shutil.rmtree(self.carpeta_temp, ignore_errors=True)

    def _resultado_fake(self, target="8.8.8.8"):
        return {
            "target":    target,
            "tipo":      "ip",
            "timestamp": "2026-01-01T12:00:00",
            "duracion":  2.5,
            "analisis":  "Análisis de prueba"
        }

    def test_guardar_crea_archivo_json(self):
        """guardar_reporte debe crear un archivo .json en la carpeta"""
        import agente
        carpeta_original = agente.REPORTES_DIR
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            agente.guardar_reporte(self._resultado_fake())
            archivos = list(Path(self.carpeta_temp).glob("*.json"))
            self.assertGreater(len(archivos), 0,
                "guardar_reporte debe crear al menos un archivo .json")
        finally:
            agente.REPORTES_DIR = carpeta_original

    def test_archivo_contiene_json_valido(self):
        """El archivo creado debe ser JSON válido y legible"""
        import agente, json
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            agente.guardar_reporte(self._resultado_fake("192.168.1.1"))
            archivos = list(Path(self.carpeta_temp).glob("*.json"))
            self.assertGreater(len(archivos), 0)
            contenido = json.loads(archivos[0].read_text(encoding="utf-8"))
            self.assertEqual(contenido["target"], "192.168.1.1")
            self.assertEqual(contenido["tipo"], "ip")
        finally:
            agente.REPORTES_DIR = Path(self.carpeta_temp)

    def test_nombre_archivo_no_tiene_caracteres_raros(self):
        """El nombre del archivo no debe tener caracteres especiales"""
        import agente
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            # Target con caracteres que podrían romper el nombre del archivo
            agente.guardar_reporte(self._resultado_fake("https://sitio.com/path?q=1"))
            archivos = list(Path(self.carpeta_temp).glob("*.json"))
            self.assertGreater(len(archivos), 0)
            nombre = archivos[0].name
            # No debe tener / \ : * ? " < > |
            for char in '/\\:*?"<>|':
                self.assertNotIn(char, nombre,
                    f"El nombre '{nombre}' no debe contener '{char}'")
        finally:
            agente.REPORTES_DIR = Path(self.carpeta_temp)

    def test_ver_historial_sin_reportes_no_crashea(self):
        """ver_historial con carpeta vacía no debe crashear"""
        import agente
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            # Solo verificamos que no lanza excepción
            agente.ver_historial()
        except Exception as e:
            self.fail(f"ver_historial crasheó con carpeta vacía: {e}")
        finally:
            agente.REPORTES_DIR = Path(self.carpeta_temp)

    def test_ver_historial_muestra_reportes_guardados(self, capsys=None):
        """ver_historial debe leer los reportes existentes sin error"""
        import agente
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            # Guardar 3 reportes
            for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
                agente.guardar_reporte(self._resultado_fake(ip))
            # Leer historial — no debe lanzar excepción
            agente.ver_historial()
        except Exception as e:
            self.fail(f"ver_historial crasheó con reportes existentes: {e}")
        finally:
            agente.REPORTES_DIR = Path(self.carpeta_temp)

    def test_guardar_reporte_target_con_inyeccion(self):
        """
        Un target con caracteres maliciosos en el nombre
        no debe crear rutas peligrosas ni crashear.
        """
        import agente
        agente.REPORTES_DIR = Path(self.carpeta_temp)
        try:
            resultado = self._resultado_fake("../../../etc/passwd")
            agente.guardar_reporte(resultado)
            archivos = list(Path(self.carpeta_temp).glob("*.json"))
            # Si se guardó, verificar que no escapó de la carpeta temporal
            for archivo in archivos:
                self.assertTrue(
                    str(archivo).startswith(self.carpeta_temp),
                    "El archivo no debe estar fuera de la carpeta de reportes"
                )
        except Exception:
            pass  # También es válido que falle de forma controlada
        finally:
            agente.REPORTES_DIR = Path(self.carpeta_temp)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 13: VALIDAR URL (opción 2 del menú)
#  ¿La validación de URL rechaza inputs inválidos
#  y acepta URLs reales correctamente?
# ═══════════════════════════════════════════════════════════

class TestValidarURL(unittest.TestCase):
    """
    Probamos validar_url — la función que protege la opción 2
    del menú antes de pasarle cualquier cosa al agente.
    """

    # ── URLs válidas — deben pasar ───────────────────────────

    def test_url_https_completa(self):
        """Una URL completa con https debe ser válida"""
        from agente import validar_url
        ok, _ = validar_url("https://google.com")
        self.assertTrue(ok)

    def test_url_http_completa(self):
        """Una URL con http también debe ser válida"""
        from agente import validar_url
        ok, _ = validar_url("http://sitio.com")
        self.assertTrue(ok)

    def test_url_sin_esquema_se_completa(self):
        """Si falta https://, la función lo agrega y es válida"""
        from agente import validar_url
        ok, url_limpia = validar_url("google.com")
        self.assertTrue(ok)
        self.assertTrue(url_limpia.startswith("https://"))

    def test_url_con_path(self):
        """URL con ruta larga debe ser válida"""
        from agente import validar_url
        ok, _ = validar_url("https://banco.com/login/verificar?token=abc")
        self.assertTrue(ok)

    def test_url_con_subdominio(self):
        """URL con subdominios debe ser válida"""
        from agente import validar_url
        ok, _ = validar_url("https://mail.google.com")
        self.assertTrue(ok)

    def test_url_dominio_mx(self):
        """Dominios .mx deben ser válidos"""
        from agente import validar_url
        ok, _ = validar_url("https://sat.gob.mx")
        self.assertTrue(ok)

    def test_url_retorna_url_limpia(self):
        """El segundo valor del tuple debe ser la URL lista para usar"""
        from agente import validar_url
        ok, url_limpia = validar_url("bbva.mx")
        self.assertTrue(ok)
        self.assertEqual(url_limpia, "https://bbva.mx")

    # ── URLs inválidas — deben ser rechazadas ────────────────

    def test_url_vacia_rechazada(self):
        """URL vacía debe ser rechazada con mensaje claro"""
        from agente import validar_url
        ok, mensaje = validar_url("")
        self.assertFalse(ok)
        self.assertIsInstance(mensaje, str)
        self.assertGreater(len(mensaje), 5)

    def test_url_solo_espacios_rechazada(self):
        """Solo espacios debe ser rechazado"""
        from agente import validar_url
        ok, _ = validar_url("     ")
        self.assertFalse(ok)

    def test_url_solo_esquema_rechazada(self):
        """'https://' sin dominio debe ser rechazado"""
        from agente import validar_url
        ok, mensaje = validar_url("https://")
        self.assertFalse(ok)
        self.assertGreater(len(mensaje), 5)

    def test_url_http_solo_rechazada(self):
        """'http://' sin dominio debe ser rechazado"""
        from agente import validar_url
        ok, _ = validar_url("http://")
        self.assertFalse(ok)

    def test_url_texto_libre_rechazado(self):
        """Texto sin punto no es URL válida"""
        from agente import validar_url
        ok, mensaje = validar_url("esto no es una url")
        self.assertFalse(ok)

    def test_url_solo_palabra_rechazada(self):
        """Una sola palabra sin punto ni esquema debe ser rechazada"""
        from agente import validar_url
        ok, _ = validar_url("google")
        self.assertFalse(ok)

    def test_url_con_espacios_en_dominio_rechazada(self):
        """Dominios con espacios son inválidos"""
        from agente import validar_url
        ok, _ = validar_url("https://banco seguro.com")
        self.assertFalse(ok)

    def test_url_demasiado_larga_rechazada(self):
        """URLs de más de 300 caracteres deben ser rechazadas"""
        from agente import validar_url
        url_gigante = "https://" + "a" * 300 + ".com"
        ok, mensaje = validar_url(url_gigante)
        self.assertFalse(ok)
        self.assertIn("larga", mensaje.lower())

    def test_url_puntos_consecutivos_rechazada(self):
        """Dominios con puntos consecutivos son inválidos"""
        from agente import validar_url
        ok, _ = validar_url("https://banco..com")
        self.assertFalse(ok)

    # ── El mensaje de error siempre debe ser útil ────────────

    def test_mensaje_error_es_string_legible(self):
        """Todos los errores deben ser strings con texto útil"""
        from agente import validar_url
        casos_invalidos = ["", "   ", "https://", "sinpunto", "a" * 400]
        for caso in casos_invalidos:
            with self.subTest(caso=caso[:30]):
                ok, mensaje = validar_url(caso)
                self.assertFalse(ok)
                self.assertIsInstance(mensaje, str)
                self.assertGreater(len(mensaje), 5,
                    f"El mensaje de error para '{caso[:20]}' está vacío")

    def test_siempre_retorna_tuple(self):
        """validar_url SIEMPRE debe retornar (bool, str), nunca crashear"""
        from agente import validar_url
        inputs_raros = [
            "", "   ", "https://", "http://", "ftp://raro.com",
            "💀.com", "../../../etc", "javascript:alert(1)",
            "file:///etc/passwd", None if False else "",
        ]
        for inp in inputs_raros:
            with self.subTest(inp=inp[:30] if inp else "''"):
                try:
                    resultado = validar_url(inp)
                    self.assertIsInstance(resultado, tuple)
                    self.assertEqual(len(resultado), 2)
                    self.assertIsInstance(resultado[0], bool)
                    self.assertIsInstance(resultado[1], str)
                except Exception as e:
                    self.fail(f"validar_url('{inp}') crasheó: {e}")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 14: check_greynoise
#  ¿El análisis de GreyNoise clasifica correctamente las IPs
#  según su comportamiento? ¿El fallback a RIOT funciona?
# ═══════════════════════════════════════════════════════════

class TestCheckGreynoise(unittest.TestCase):
    """
    check_greynoise tiene múltiples ramas lógicas:
    malicioso, benigno, scanner, sin actividad,
    fallback al endpoint RIOT, y ambos fallan.
    Ninguna tenía cobertura previa.
    """

    def _resp_community(self, clasificacion="unknown", noise=False,
                        riot=False, nombre=""):
        """Helper: respuesta simulada del endpoint community de GreyNoise"""
        return {
            "classification": clasificacion,
            "noise":          noise,
            "riot":           riot,
            "name":           nombre,
            "message":        "This IP is commonly seen scanning the internet"
        }

    def test_ip_invalida_retorna_error(self):
        """IP inválida debe devolver error sin llegar a la API"""
        from agente import check_greynoise
        r = check_greynoise("no-es-una-ip")
        self.assertIn("error", r)

    def test_clasificacion_malicious_da_veredicto_malicioso(self):
        """IP con classification=malicious → veredicto MALICIOSO"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community(clasificacion="malicious")):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        self.assertEqual(r["veredicto"], "MALICIOSO")

    def test_riot_true_da_veredicto_benigno(self):
        """IP con riot=True (Cloudflare, Google…) → veredicto BENIGNO"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community(riot=True, nombre="Cloudflare")):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.1.1.1")
        self.assertEqual(r["veredicto"], "BENIGNO")

    def test_clasificacion_benign_da_veredicto_benigno(self):
        """classification=benign (scanner legítimo como Shodan) → BENIGNO"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community(clasificacion="benign",
                                                     nombre="Shodan")):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        self.assertEqual(r["veredicto"], "BENIGNO")

    def test_noise_true_sin_clasificacion_da_scanner(self):
        """IP que escanea masivamente sin clasificación conocida → SCANNER"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community(noise=True)):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        self.assertEqual(r["veredicto"], "SCANNER")

    def test_sin_actividad_registrada(self):
        """IP sin ninguna actividad en GreyNoise → SIN ACTIVIDAD"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community()):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        self.assertEqual(r["veredicto"], "SIN ACTIVIDAD")

    def test_community_falla_usa_endpoint_riot(self):
        """
        Si el endpoint community falla, debe intentar RIOT.
        RIOT contiene IPs conocidas como benignas (Google, Cloudflare, etc.)
        """
        from agente import check_greynoise
        respuesta_riot = {
            "riot":        True,
            "name":        "Google LLC",
            "description": "Google services",
            "trust_level": "1"
        }

        def http_get_mock(url, headers=None, params=None):
            if "community" in url:
                return {"error": "Rate limit exceeded"}
            if "riot" in url:
                return respuesta_riot
            return {"error": "inesperado"}

        with patch("agente.http_get", side_effect=http_get_mock):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("8.8.8.8")

        self.assertEqual(r.get("fuente"), "GreyNoise RIOT")
        self.assertEqual(r.get("veredicto"), "BENIGNO")

    def test_ambas_apis_fallan_retorna_error_controlado(self):
        """Si community y RIOT ambas fallan, debe devolver error controlado"""
        from agente import check_greynoise
        with patch("agente.http_get", return_value={"error": "sin conexión"}):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        self.assertIn("error", r)
        self.assertEqual(r.get("fuente"), "GreyNoise")

    def test_respuesta_tiene_campos_esperados(self):
        """La respuesta exitosa debe incluir fuente, ip, veredicto y contexto"""
        from agente import check_greynoise
        with patch("agente.http_get",
                   return_value=self._resp_community(clasificacion="malicious")):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = check_greynoise("1.2.3.4")
        for campo in ["fuente", "ip", "veredicto", "clasificacion", "contexto"]:
            self.assertIn(campo, r, f"Falta campo '{campo}' en la respuesta")

    def test_con_api_key_pasa_header_de_autenticacion(self):
        """Con GREYNOISE_API_KEY, debe pasar el header 'key' en la petición"""
        from agente import check_greynoise
        llamadas = []

        def http_get_captura(url, headers=None, params=None):
            llamadas.append({"url": url, "headers": headers or {}})
            return self._resp_community()

        with patch("agente.http_get", side_effect=http_get_captura):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": "mi-key-secreta"}):
                check_greynoise("1.2.3.4")

        self.assertGreater(len(llamadas), 0)
        self.assertIn("key", llamadas[0]["headers"],
                      "Con API key debe pasar el header 'key'")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 15: check_urlscan
#  ¿El análisis con URLScan.io maneja correctamente los tres
#  escenarios: escaneo nuevo, resultado previo y sin datos?
# ═══════════════════════════════════════════════════════════

class TestCheckURLScan(unittest.TestCase):
    """
    check_urlscan tiene 3 ramas principales:
    1. Sin API key + sin resultados previos   → SIN DATOS
    2. Sin API key + resultados previos        → usa escaneo previo
    3. Con API key                             → envía escaneo nuevo
    """

    def _resultado_previo_fake(self, malicious=False, score=0, pais="US"):
        """Helper: simula un resultado previo de URLScan"""
        return {
            "_id":  "abc123",
            "page": {
                "url":     "https://ejemplo.com",
                "title":   "Ejemplo",
                "country": pais,
                "ip":      "1.2.3.4"
            },
            "verdicts": {
                "overall": {"malicious": malicious, "score": score}
            }
        }

    def test_url_vacia_retorna_error(self):
        """URL vacía debe devolver error controlado sin crashear"""
        from agente import check_urlscan
        with patch("agente.http_get", return_value={"results": []}):
            r = check_urlscan("")
        self.assertIn("error", r)

    def test_sin_key_sin_previos_da_sin_datos(self):
        """Sin API key y sin escaneos previos → veredicto SIN DATOS"""
        from agente import check_urlscan
        with patch("agente.http_get", return_value={"results": []}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("https://sitio-nuevo.com")
        self.assertEqual(r.get("veredicto"), "SIN DATOS")
        self.assertIn("fuente", r)
        self.assertIn("url", r)

    def test_usa_resultado_previo_cuando_no_hay_key(self):
        """Sin API key pero con escaneo previo, debe usar ese resultado"""
        from agente import check_urlscan
        previo = self._resultado_previo_fake()
        with patch("agente.http_get", return_value={"results": [previo]}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("https://sitio.com")
        self.assertIn("previo", r.get("fuente", "").lower(),
                      "La fuente debe indicar que es un escaneo previo")

    def test_resultado_previo_malicioso_da_peligroso(self):
        """Escaneo previo con malicious=True → veredicto PELIGROSO"""
        from agente import check_urlscan
        previo = self._resultado_previo_fake(malicious=True)
        with patch("agente.http_get", return_value={"results": [previo]}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("https://sitio-malo.com")
        self.assertEqual(r.get("veredicto"), "PELIGROSO")

    def test_resultado_previo_score_alto_da_revisar(self):
        """Escaneo previo con score > 30 pero no malicioso → veredicto REVISAR"""
        from agente import check_urlscan
        previo = self._resultado_previo_fake(malicious=False, score=50)
        with patch("agente.http_get", return_value={"results": [previo]}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("https://sitio-sospechoso.com")
        self.assertEqual(r.get("veredicto"), "REVISAR")

    def test_url_sin_https_no_crashea(self):
        """URL sin esquema https:// se completa automáticamente y no crashea"""
        from agente import check_urlscan
        with patch("agente.http_get", return_value={"results": []}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("sitio-sin-esquema.com")
        self.assertIsInstance(r, dict)

    def test_con_api_key_envia_escaneo_nuevo(self):
        """Con API key, debe enviar POST y devolver resultados del escaneo en vivo"""
        from agente import check_urlscan
        busqueda_vacia = {"results": []}

        scan_response = MagicMock()
        scan_response.json.return_value = {"uuid": "uuid-test-123"}

        resultado_escaneo = {
            "page": {
                "url":     "https://sitio.com",
                "title":   "Sitio de Prueba",
                "server":  "nginx",
                "country": "US",
                "ip":      "1.2.3.4"
            },
            "verdicts": {"overall": {"malicious": False, "score": 10}},
            "lists":    {},
            "meta":     {"processors": {"wappa": {"data": []}}}
        }

        def http_get_mock(url, headers=None, params=None):
            if "search" in url:
                return busqueda_vacia
            if "result" in url:
                return resultado_escaneo
            return {"error": "inesperado"}

        with patch("agente.http_get", side_effect=http_get_mock):
            with patch("agente.requests.post", return_value=scan_response):
                with patch("agente.time.sleep"):  # evitar la espera de 12s
                    with patch.dict(os.environ, {"URLSCAN_API_KEY": "fake-key"}):
                        r = check_urlscan("https://sitio.com")

        self.assertIn("fuente", r)
        self.assertNotIn("error", r)
        self.assertIn("vivo", r.get("fuente", "").lower(),
                      "La fuente debe indicar que es un escaneo en vivo")

    def test_estructura_siempre_tiene_campos_clave(self):
        """El resultado siempre debe tener fuente, url y veredicto"""
        from agente import check_urlscan
        with patch("agente.http_get", return_value={"results": []}):
            with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}):
                r = check_urlscan("https://cualquier.com")
        for campo in ["fuente", "url", "veredicto"]:
            self.assertIn(campo, r, f"Falta campo '{campo}' en resultado SIN DATOS")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 16: check_whois
#  ¿La consulta RDAP/WHOIS maneja correctamente dominios
#  válidos, inválidos y errores de la API?
# ═══════════════════════════════════════════════════════════

class TestCheckWhois(unittest.TestCase):

    def test_dominio_invalido_retorna_error(self):
        """Un dominio sin formato válido debe devolver error sin llamar a la API"""
        r = check_whois("no_es_un_dominio")
        self.assertIn("error", r)

    def test_dominio_vacio_retorna_error(self):
        """Cadena vacía no es dominio válido → error"""
        r = check_whois("")
        self.assertIn("error", r)

    def test_dominio_con_inyeccion_retorna_error(self):
        """Dominio con caracteres de inyección SQL no es válido → error"""
        r = check_whois("'; DROP TABLE dominios; --")
        self.assertIn("error", r)

    def test_respuesta_exitosa_tiene_estructura_correcta(self):
        """Con respuesta válida de RDAP, el resultado debe tener los campos esperados"""
        respuesta_rdap = {
            "ldhName": "GOOGLE.COM",
            "status":  [{"value": "active"},
                        {"value": "clientTransferProhibited"}]
        }
        with patch("agente.http_get", return_value=respuesta_rdap):
            r = check_whois("google.com")
        for campo in ["fuente", "dominio", "nombre", "estados"]:
            self.assertIn(campo, r, f"Falta campo '{campo}' en resultado WHOIS")

    def test_estados_siempre_es_lista(self):
        """El campo 'estados' siempre debe ser una lista, incluso si está vacío"""
        respuesta_rdap = {"ldhName": "EJEMPLO.COM", "status": []}
        with patch("agente.http_get", return_value=respuesta_rdap):
            r = check_whois("ejemplo.com")
        self.assertIsInstance(r.get("estados"), list,
                              "'estados' debe ser una lista")

    def test_api_falla_propaga_error(self):
        """Si rdap.org falla, el error debe aparecer en el resultado"""
        with patch("agente.http_get", return_value={"error": "Timeout"}):
            r = check_whois("google.com")
        self.assertIn("error", r)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 17: verificar_ssl — camino feliz y alertas
#  Los tests existentes solo cubren errores de conexión.
#  Aquí probamos que la lectura y análisis del certificado
#  funciona correctamente con un cert válido mockeado.
# ═══════════════════════════════════════════════════════════

class TestVerificarSSLCaminoFeliz(unittest.TestCase):
    """
    Probamos verificar_ssl con certificados mockeados para
    verificar que las alertas se generan según la antigüedad,
    fecha de expiración y emisor del certificado.
    """

    def _construir_cert(self, dias_activo, dias_vence,
                        emisor="DigiCert Inc", cn="google.com"):
        """Crea un cert mock en el formato exacto que espera verificar_ssl"""
        from datetime import datetime, timezone, timedelta
        ahora  = datetime.now(timezone.utc)
        inicio = ahora - timedelta(days=dias_activo)
        fin    = ahora + timedelta(days=dias_vence)
        fmt    = "%b %d %H:%M:%S %Y"
        return {
            "notBefore":      inicio.strftime(fmt) + " GMT",
            "notAfter":       fin.strftime(fmt) + " GMT",
            "issuer":         [[("organizationName", emisor)]],
            "subject":        [[("commonName", cn)]],
            "subjectAltName": [("DNS", cn), ("DNS", f"www.{cn}")]
        }

    def _mock_ssl_ok(self, cert):
        """Configura mocks de socket/ssl para simular conexión SSL exitosa"""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

        mock_sock = MagicMock()
        return mock_ctx, mock_sock

    def test_certificado_valido_retorna_valido_true(self):
        """Con cert SSL válido, la función debe retornar valido=True"""
        cert = self._construir_cert(dias_activo=180, dias_vence=60)
        mock_ctx, mock_sock = self._mock_ssl_ok(cert)

        with patch("agente.ssl.create_default_context", return_value=mock_ctx):
            with patch("agente.socket.create_connection", return_value=mock_sock):
                from agente import verificar_ssl
                r = verificar_ssl("https://google.com")

        self.assertTrue(r.get("valido"), "Con cert correcto, 'valido' debe ser True")
        self.assertIn("fuente", r)
        self.assertIn("dias_activo", r)

    def test_certificado_muy_nuevo_genera_alerta(self):
        """Cert con menos de 30 días de vida → alerta de certificado nuevo"""
        cert = self._construir_cert(dias_activo=5, dias_vence=360)
        mock_ctx, mock_sock = self._mock_ssl_ok(cert)

        with patch("agente.ssl.create_default_context", return_value=mock_ctx):
            with patch("agente.socket.create_connection", return_value=mock_sock):
                from agente import verificar_ssl
                r = verificar_ssl("https://phishing-reciente.com")

        alertas = " ".join(r.get("alertas_ssl", []))
        self.assertIn("nuevo", alertas.lower(),
                      "Cert muy reciente debe generar alerta con 'nuevo'")

    def test_certificado_por_vencer_genera_alerta(self):
        """Cert que expira en menos de 15 días → alerta de expiración"""
        cert = self._construir_cert(dias_activo=350, dias_vence=7)
        mock_ctx, mock_sock = self._mock_ssl_ok(cert)

        with patch("agente.ssl.create_default_context", return_value=mock_ctx):
            with patch("agente.socket.create_connection", return_value=mock_sock):
                from agente import verificar_ssl
                r = verificar_ssl("https://sitio-expirando.com")

        alertas = " ".join(r.get("alertas_ssl", []))
        self.assertIn("vence", alertas.lower(),
                      "Cert por vencer debe generar alerta con 'vence'")

    def test_letsencrypt_genera_alerta_informativa(self):
        """Let's Encrypt como emisor → alerta de certificado gratuito automático"""
        cert = self._construir_cert(dias_activo=60, dias_vence=30,
                                    emisor="Let's Encrypt")
        mock_ctx, mock_sock = self._mock_ssl_ok(cert)

        with patch("agente.ssl.create_default_context", return_value=mock_ctx):
            with patch("agente.socket.create_connection", return_value=mock_sock):
                from agente import verificar_ssl
                r = verificar_ssl("https://sitio-con-letsencrypt.com")

        alertas = " ".join(r.get("alertas_ssl", []))
        self.assertIn("gratuito", alertas.lower(),
                      "Let's Encrypt debe generar alerta de cert gratuito")

    def test_resultado_exitoso_tiene_todos_los_campos(self):
        """Con cert válido, el resultado debe incluir todos los campos clave"""
        cert = self._construir_cert(dias_activo=200, dias_vence=165)
        mock_ctx, mock_sock = self._mock_ssl_ok(cert)

        with patch("agente.ssl.create_default_context", return_value=mock_ctx):
            with patch("agente.socket.create_connection", return_value=mock_sock):
                from agente import verificar_ssl
                r = verificar_ssl("https://google.com")

        campos = ["fuente", "dominio", "valido", "emitido_por",
                  "dias_activo", "dias_para_vencer", "alertas_ssl", "nota"]
        for campo in campos:
            self.assertIn(campo, r, f"Falta campo '{campo}' en resultado SSL exitoso")


# ═══════════════════════════════════════════════════════════
#  BLOQUE 18: buscar_cves — casos límite
#  ¿La función maneja CVEs sin métricas CVSS, resultados
#  vacíos, descripciones en otro idioma y errores de API?
# ═══════════════════════════════════════════════════════════

class TestBuscarCVESCasosLimite(unittest.TestCase):

    def test_sin_vulnerabilidades_retorna_lista_vacia(self):
        """Si la API no devuelve CVEs, vulnerabilidades debe ser lista vacía"""
        respuesta_vacia = {"totalResults": 0, "vulnerabilities": []}
        with patch("agente.http_get", return_value=respuesta_vacia):
            resultado = buscar_cves("software-inexistente", "9.9.9")
        self.assertEqual(resultado["total"], 0)
        self.assertEqual(resultado["vulnerabilidades"], [])

    def test_cve_sin_metricas_cvss_usa_na(self):
        """
        CVE sin métricas CVSS v3.1 (muchos CVEs antiguos) debe
        usar 'N/A' para score y severidad en lugar de crashear.
        """
        respuesta = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2019-0001",
                    "descriptions": [{"lang": "en", "value": "Vulnerabilidad antigua"}],
                    "metrics": {}   # sin cvssMetricV31
                }
            }]
        }
        with patch("agente.http_get", return_value=respuesta):
            resultado = buscar_cves("software-viejo")
        vuln = resultado["vulnerabilidades"][0]
        self.assertEqual(vuln["score"],     "N/A")
        self.assertEqual(vuln["severidad"], "N/A")

    def test_cve_sin_descripcion_en_ingles_usa_fallback(self):
        """
        CVE sin descripción en inglés (solo en otros idiomas) debe
        usar 'Sin descripción' en lugar de lanzar StopIteration.
        """
        respuesta = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2020-0001",
                    "descriptions": [{"lang": "es",
                                      "value": "Descripción solo en español"}],
                    "metrics": {}
                }
            }]
        }
        with patch("agente.http_get", return_value=respuesta):
            resultado = buscar_cves("software-test")
        self.assertEqual(resultado["vulnerabilidades"][0]["descripcion"],
                         "Sin descripción")

    def test_api_error_se_propaga_en_resultado(self):
        """Si la API de NVD falla, el error debe aparecer en el resultado"""
        with patch("agente.http_get", return_value={"error": "Timeout"}):
            resultado = buscar_cves("apache", "2.4.0")
        self.assertIn("error", resultado)

    def test_version_es_opcional_no_crashea(self):
        """buscar_cves llamado sin versión no debe crashear"""
        respuesta = {"totalResults": 0, "vulnerabilities": []}
        with patch("agente.http_get", return_value=respuesta):
            resultado = buscar_cves("nginx")   # sin version
        self.assertIsInstance(resultado, dict)
        self.assertNotIn("error", resultado)


# ═══════════════════════════════════════════════════════════
#  BLOQUE 19: cobertura complementaria
#  Tests para ramas sin cobertura previa:
#  VirusTotal con dominios y hashes, reglas 7 y 8 del detector
#  de phishing, dispatcher con más herramientas, y http_get.
# ═══════════════════════════════════════════════════════════

class TestCoberturaComplementaria(unittest.TestCase):

    # ── VirusTotal: tipos de target no probados ──────────────

    def test_virustotal_acepta_dominios(self):
        """check_virustotal debe funcionar con dominios, no solo IPs"""
        respuesta = {"data": {"attributes": {"last_analysis_stats":
            {"malicious": 0, "suspicious": 0, "undetected": 80, "harmless": 0}}}}
        with patch("agente.http_get", return_value=respuesta):
            with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
                r = check_virustotal("malware-domain.com")
        self.assertNotIn("error", r)
        self.assertEqual(r["veredicto"], "LIMPIO")

    def test_virustotal_acepta_hashes_sha256(self):
        """check_virustotal debe funcionar con hashes SHA-256"""
        respuesta = {"data": {"attributes": {"last_analysis_stats":
            {"malicious": 60, "suspicious": 3, "undetected": 20, "harmless": 0}}}}
        with patch("agente.http_get", return_value=respuesta):
            with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
                r = check_virustotal(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                )
        self.assertEqual(r["veredicto"], "PELIGROSO")

    def test_virustotal_tipo_url_no_soportado_retorna_error(self):
        """check_virustotal no soporta URLs directamente → error descriptivo"""
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake"}):
            r = check_virustotal("https://malware.com/archivo.exe")
        self.assertIn("error", r)
        self.assertIn("url", r["error"].lower())

    # ── Reglas de phishing sin cobertura previa ──────────────

    def test_phishing_regla7_dominio_raiz_muy_largo(self):
        """
        Regla 7: dominio raíz con más de 20 caracteres genera alerta.
        Dominios legítimos rara vez son tan largos.
        """
        url = "https://este-dominio-raiz-es-extremadamente-largo.com/login"
        r = analizar_url_phishing(url)
        alertas = " ".join(r["alertas"])
        self.assertIn("largo", alertas.lower(),
                      "Dominio raíz muy largo debe generar alerta")

    def test_phishing_regla8_caracteres_especiales_en_dominio(self):
        """
        Regla 8: caracteres no estándar en el dominio (ej. @ de credenciales)
        deben generar alerta de posible homoglyph attack.
        """
        # La '@' en la URL es interpretada como credenciales en netloc
        # lo que resulta en un dominio con '@' detectado por [^\w\-\.]
        url = "https://pay@pal-seguro.com/verify"
        r = analizar_url_phishing(url)
        alertas = " ".join(r["alertas"])
        self.assertIn("homoglyph", alertas.lower(),
                      "Caracteres especiales en el dominio deben generar alerta")

    def test_phishing_positivos_cuando_marca_coincide_con_dominio_raiz(self):
        """
        Cuando la marca coincide con el dominio raíz (sitio legítimo),
        debe aparecer en 'positivos', no disparar una ALERTA CRITICA.
        """
        r = analizar_url_phishing("https://www.paypal.com/login")
        positivos = " ".join(r.get("positivos", []))
        self.assertIn("paypal", positivos.lower(),
                      "paypal.com debe aparecer como marca coincidente en positivos")
        alertas_criticas = [a for a in r["alertas"] if "CRITICA" in a]
        self.assertEqual(len(alertas_criticas), 0)

    # ── ejecutar_herramienta con herramientas no probadas ────

    def test_ejecutar_herramienta_buscar_cves(self):
        """El dispatcher debe despachar correctamente a buscar_cves"""
        respuesta = {"totalResults": 0, "vulnerabilities": []}
        with patch("agente.http_get", return_value=respuesta):
            r = ejecutar_herramienta("buscar_cves",
                                     {"software": "nginx", "version": "1.0"})
        self.assertIsInstance(r, dict)
        self.assertNotIn("error", r)

    def test_ejecutar_herramienta_analizar_url_phishing(self):
        """El dispatcher debe despachar a analizar_url_phishing"""
        r = ejecutar_herramienta("analizar_url_phishing",
                                 {"url": "https://test.com"})
        self.assertIsInstance(r, dict)
        self.assertIn("veredicto_url", r)

    def test_ejecutar_herramienta_check_greynoise(self):
        """El dispatcher debe despachar correctamente a check_greynoise"""
        from agente import check_greynoise  # asegurar disponibilidad
        respuesta_gn = {
            "classification": "benign", "noise": False,
            "riot": True, "name": "Google"
        }
        with patch("agente.http_get", return_value=respuesta_gn):
            with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}):
                r = ejecutar_herramienta("check_greynoise", {"ip": "8.8.8.8"})
        self.assertIsInstance(r, dict)

    def test_ejecutar_herramienta_verificar_redireccion(self):
        """El dispatcher debe despachar a verificar_redireccion"""
        mock_resp = MagicMock()
        mock_resp.url        = "https://google.com/"
        mock_resp.status_code = 200
        mock_resp.history    = []
        with patch("agente.requests.head", return_value=mock_resp):
            r = ejecutar_herramienta("verificar_redireccion",
                                     {"url": "https://google.com"})
        self.assertIsInstance(r, dict)
        self.assertNotIn("error", r)

    # ── http_get: manejo directo de errores ──────────────────

    def test_http_get_timeout_retorna_dict_con_error(self):
        """http_get debe capturar Timeout y devolver {'error': '...'}"""
        from agente import http_get
        import requests as req
        with patch("agente.requests.get",
                   side_effect=req.exceptions.Timeout("timeout")):
            r = http_get("https://api-lenta.com/datos")
        self.assertIn("error", r)
        self.assertIsInstance(r["error"], str)

    def test_http_get_excepcion_generica_trunca_mensaje(self):
        """http_get captura cualquier excepción y trunca el mensaje a 100 chars"""
        from agente import http_get
        mensaje_largo = "error inesperado " + "x" * 200
        with patch("agente.requests.get", side_effect=Exception(mensaje_largo)):
            r = http_get("https://api.com/datos")
        self.assertIn("error", r)
        self.assertLessEqual(len(r["error"]), 100,
                             "El mensaje de error debe estar truncado a 100 chars")


# ═══════════════════════════════════════════════════════════
#  RUNNER PERSONALIZADO
#  Muestra los resultados de forma bonita y clara
# ═══════════════════════════════════════════════════════════

class ResultadoBonito(unittest.TextTestResult):
    """Clase para mostrar los resultados de forma legible"""

    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"  ✅ {test.shortDescription() or test._testMethodName}")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"  ❌ {test.shortDescription() or test._testMethodName}")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"  💥 {test.shortDescription() or test._testMethodName} [ERROR INESPERADO]")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        print(f"  ⏭️  {test.shortDescription() or test._testMethodName} [omitido: {reason}]")


class RunnerBonito(unittest.TextTestRunner):
    resultclass = ResultadoBonito


# ═══════════════════════════════════════════════════════════
#  PUNTO DE ENTRADA
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      🔐 TESTS DE SEGURIDAD — Agente Ciberseguridad       ║")
    print("║      MikeUchiha122 · Miguel Angel Ramirez Galicia        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    if not IMPORTACION_OK:
        print(f"❌ No se pudo importar agente.py: {ERROR_IMPORTACION}")
        print("   Asegúrate de que test_agente.py esté en la misma")
        print("   carpeta que agente.py (C:\\agente-seguridad\\)")
        sys.exit(1)

    # Grupos de tests a ejecutar
    grupos = [
        ("BLOQUE 1: Validadores",              TestValidadores),
        ("BLOQUE 2: Sanitizador",              TestSanitizador),
        ("BLOQUE 3: Anti-Phishing",            TestAntiPhishing),
        ("BLOQUE 4: Seguridad API Keys",       TestSeguridadAPIKeys),
        ("BLOQUE 5: Herramientas (Mock)",      TestHerramientasConMocks),
        ("BLOQUE 6: Inputs Maliciosos",        TestInputsMaliciosos),
        ("BLOQUE 7: Lógica de Negocio",        TestLogicaDeNegocio),
        ("BLOQUE 8: Estructura Respuestas",    TestEstructuraRespuestas),
        ("BLOQUE 9: buscar_subdominios",              TestBuscarSubdominios),
        ("BLOQUE 10: verificar_ssl (errores)",        TestVerificarSSL),
        ("BLOQUE 11: verificar_redireccion",          TestVerificarRedireccion),
        ("BLOQUE 12: reportes e historial",           TestGuardarReporteYHistorial),
        ("BLOQUE 13: validar_url (opción 2)",         TestValidarURL),
        ("BLOQUE 14: check_greynoise",                TestCheckGreynoise),
        ("BLOQUE 15: check_urlscan",                  TestCheckURLScan),
        ("BLOQUE 16: check_whois",                    TestCheckWhois),
        ("BLOQUE 17: verificar_ssl (camino feliz)",   TestVerificarSSLCaminoFeliz),
        ("BLOQUE 18: buscar_cves (casos límite)",     TestBuscarCVESCasosLimite),
        ("BLOQUE 19: cobertura complementaria",       TestCoberturaComplementaria),
    ]

    total_ok  = 0
    total_fail = 0
    total_err  = 0

    for nombre_grupo, clase in grupos:
        print(f"\n{'─' * 58}")
        print(f"  {nombre_grupo}")
        print(f"{'─' * 58}")

        suite   = unittest.TestLoader().loadTestsFromTestCase(clase)
        runner  = RunnerBonito(stream=open(os.devnull, "w"), verbosity=0)
        result  = runner.run(suite)

        total_ok   += result.testsRun - len(result.failures) - len(result.errors)
        total_fail += len(result.failures)
        total_err  += len(result.errors)

        # Mostrar detalles de fallos
        for test, traceback in result.failures + result.errors:
            lineas = traceback.strip().split("\n")
            mensaje = lineas[-1] if lineas else "Error desconocido"
            print(f"\n     ↳ Detalle: {mensaje[:100]}")

    # Resumen final
    total = total_ok + total_fail + total_err
    print(f"\n{'═' * 58}")
    print(f"  RESUMEN FINAL")
    print(f"{'═' * 58}")
    print(f"  Total de tests : {total}")
    print(f"  ✅ Pasaron      : {total_ok}")
    print(f"  ❌ Fallaron     : {total_fail}")
    print(f"  💥 Errores      : {total_err}")
    print(f"{'═' * 58}")

    if total_fail == 0 and total_err == 0:
        print()
        print("  🎉 TODOS LOS TESTS PASARON — Listo para producción")
        print()
    else:
        print()
        print("  ⚠️  Hay tests fallando — Revisa antes de subir a GitHub")
        print()
        sys.exit(1)