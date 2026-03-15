# 🔐 Agente de Ciberseguridad v4.0

[![Tests de Seguridad](https://github.com/MikeUchiha122/agente-ciberseguridad/actions/workflows/tests.yml/badge.svg)](https://github.com/MikeUchiha122/agente-ciberseguridad/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Claude](https://img.shields.io/badge/Powered%20by-Claude%20AI-orange)
![License](https://img.shields.io/badge/Uso-Ético%20y%20Defensivo-green)
[![Portfolio Demo](https://img.shields.io/badge/Portfolio-Demo%20en%20vivo-green)](https://mikeuchiha122.github.io/agente-cibersegui/)
[![Invítame un café](https://img.shields.io/badge/Invítame%20un%20café-Gracias!-orange)](https://paypal.me/MikeUchiha122)

**Autor:** Miguel Ángel Ramírez Galicia — [@MikeUchiha122](https://github.com/MikeUchiha122)

---

## ¿Qué es esto?

Agente de inteligencia artificial para análisis de ciberseguridad. Dado una IP, dominio, hash o URL, el agente consulta múltiples fuentes de seguridad de forma autónoma, razona sobre los resultados y genera un reporte completo — incluyendo una explicación en lenguaje simple para cualquier persona.

También permite **verificar si una página es segura antes de ingresar datos personales**, detectando phishing, typosquatting, certificados sospechosos y redirecciones maliciosas.

```
Tú escribes:  45.33.32.156
El agente:    Consulta 6 fuentes → Razona → Genera reporte
Resultado:    🔴 ALTO RIESGO — IP asociada a ataques SSH en 47 países
```

---

## ¿Cómo funciona?

El agente usa el patrón **ReAct** (Razonar → Actuar → Observar → Repetir):

```
Tu input
   ↓
[Claude AI] → "Necesito verificar esta IP"
   ↓
[VirusTotal] + [AbuseIPDB] + [IPInfo]   ← corre en paralelo
   ↓
[Claude AI] → "Necesito más contexto"
   ↓
[WHOIS] + [CVE/NVD]
   ↓
[Claude AI] → "Tengo suficiente información"
   ↓
Reporte técnico + Resumen para todos + Nivel de riesgo
```

---

## Herramientas integradas

| Herramienta | Qué analiza | API Key |
|-------------|-------------|---------|
| 🦠 **VirusTotal** | IP, dominio, hash o URL contra 90+ antivirus | Requerida (gratis) |
| 🚨 **AbuseIPDB** | Historial de reportes de abuso de una IP | Requerida (gratis) |
| 🌍 **IPInfo** | Geolocalización, ISP, si es VPN o Tor | No requerida |
| 🔍 **NIST NVD** | Vulnerabilidades conocidas (CVEs) por software | No requerida |
| 📋 **WHOIS/RDAP** | Registro y edad de un dominio | No requerida |
| 🗺️ **Subdominios** | Mapeo pasivo via Certificate Transparency | No requerida |
| 🔒 **SSL/TLS** | Validez y antigüedad del certificado | No requerida |
| 🎣 **Anti-Phishing** | Patrones de fraude en la estructura de la URL | No requerida |
| ↪️ **Redirecciones** | Destino real de una URL acortada o sospechosa | No requerida |

---

## Instalación (Windows)

### Opción 1 — Con doble clic (recomendado)

1. **Instala Python 3.12+** si no lo tienes:
   - Descarga desde: https://www.python.org/downloads/
   - DURANTE LA INSTALACIÓN: marca ✅ "Add Python to PATH"

2. **Clona el repositorio:**
   ```powershell
   git clone https://github.com/MikeUchiha122/agente-ciberseguridad.git
   cd agente-ciberseguridad
   ```

3. **Instala las dependencias:**
   ```powershell
   pip install anthropic requests python-dotenv
   ```

4. **Crea el archivo `.env`** en la raíz del proyecto:
   ```env
   ANTHROPIC_API_KEY=sk-ant-api03-TU-KEY-AQUI
   VIRUSTOTAL_API_KEY=TU-KEY-AQUI
   ABUSEIPDB_API_KEY=TU-KEY-AQUI
   ```

5. **¡Listo!** Haz doble clic en `ejecutar.bat` para iniciar el agente.

### Opción 2 — Desde terminal

1-4. Igual que arriba.

5. Ejecuta:
   ```powershell
   python agente.py
   ```

---

### Si Python no está en el PATH (error: "python no se reconoce")

El archivo `ejecutar.bat` ya incluye Python automáticamente. Si prefieres agregar Python al PATH manualmente:

1. Busca "Variables de entorno" en Windows
2. Edita la variable "Path" del usuario
3. Agrega: `C:\Users\TU_USUARIO\AppData\Local\Programs\Python\Python313`

O simplemente usa el archivo `ejecutar.bat` que ya hace esto por ti.

---

## Instalación (Linux/Mac)

```bash
git clone https://github.com/MikeUchiha122/agente-ciberseguridad.git
cd agente-ciberseguridad
pip install anthropic requests python-dotenv
cp .env.example .env  # y-edita con tus API keys
python agente.py
```

---

## Uso

Al iniciar verás el menú principal:

```
╔══════════════════════════════════════════════════════╗
║       🔐 AGENTE DE CIBERSEGURIDAD v4.0 🔐            ║
╠══════════════════════════════════════════════════════╣
║  [1] Analizar un target (IP, dominio, hash)          ║
║  [2] Verificar URL antes de ingresar datos           ║
║  [3] Ver historial de análisis                       ║
║  [4] Salir                                           ║
╚══════════════════════════════════════════════════════╝
```

### Opción 1 — Analizar un target

Ingresa cualquiera de estos formatos:

```
IP      →  8.8.8.8
Dominio →  ejemplo.com
Hash    →  d41d8cd98f00b204e9800998ecf8427e
```

### Opción 2 — Verificar URL antes de ingresar datos

Pega la URL que quieres revisar antes de escribir tu contraseña o datos personales:

```
https://bbva-login-seguro-verificar.com/acceso
paypal-account-verify.tk
http://sitio-que-me-mandaron.com
```

El agente responde con un veredicto claro:

```
━━━ VEREDICTO FINAL ━━━
🔴 NO ENTRES — Alto riesgo de phishing

━━━ RESUMEN PARA TODOS ━━━
Este sitio imita al banco BBVA pero el dominio real
es "verificar.com", no "bbva.com". Fue creado hace
3 días y 8 antivirus ya lo marcan como phishing.
No ingreses ningún dato aquí.

NIVEL DE RIESGO: CRÍTICO

━━━ LO QUE NO PUDIMOS VERIFICAR ━━━
• Diseño visual del sitio
• Comportamiento del formulario
• Scripts JavaScript ocultos
```

### Opción 3 — Ver historial

Muestra los últimos 10 análisis realizados con fecha y tipo.

---

## Tests de seguridad

El proyecto incluye una suite de **120 tests** que se ejecutan automáticamente antes de cada commit y en cada push a GitHub.

```powershell
python test_agente.py
```

| Bloque | Tests | Qué verifica |
|--------|-------|-------------|
| Validadores | 26 | IPs, dominios, hashes, tipos |
| Sanitizador | 10 | SQL injection, XSS, command injection |
| Anti-Phishing | 10 | Detección de phishing, falsos positivos |
| Seguridad API Keys | 5 | Manejo seguro de credenciales |
| Herramientas Mock | 8 | Lógica sin gastar quota de API |
| Inputs Maliciosos | 6 | Fuzzing con 16 inputs extremos |
| Lógica de Negocio | 7 | Umbrales de riesgo correctos |
| Estructura Respuestas | 5 | Formato consistente de resultados |
| buscar_subdominios | 7 | Parsing y límites |
| verificar_ssl | 5 | Manejo de certificados |
| verificar_redireccion | 7 | Detección de cambios de dominio |
| Reportes e Historial | 6 | Escritura segura en disco |
| validar_url | 18 | Validación de entrada opción 2 |

Los tests corren automáticamente en GitHub Actions con cada push. El badge arriba muestra el estado actual.

---

## Seguridad

- Las API keys se leen del archivo `.env` y nunca se exponen en logs ni errores
- Todos los inputs pasan por `sanitizar()` antes de procesarse (elimina `;`, `<`, `>`, `&`, `'`)
- `validar_url()` verifica que la URL sea real antes de analizarla
- Límite de 10 llamadas a herramientas por análisis para prevenir bucles infinitos
- Timeout de 10 segundos por cada llamada HTTP externa

---

## Estructura del proyecto

```
agente-ciberseguridad/
├── agente.py           # Agente principal (20 funciones, ~840 líneas)
├── test_agente.py      # Suite de tests (120 tests, 13 bloques)
├── .env                # API keys — NO se sube a GitHub
├── .gitignore          # Protege .env, reportes/ y __pycache__
├── reportes/           # JSONs de análisis guardados localmente
└── .github/
    └── workflows/
        └── tests.yml   # GitHub Actions — tests automáticos en la nube
```

---

## Aviso legal

Este proyecto es de uso **ético y defensivo únicamente.**

Está diseñado para que personas y equipos de seguridad puedan verificar si un recurso de internet es peligroso, protegerse de phishing y analizar amenazas conocidas. No debe usarse para atacar sistemas, recopilar información sin autorización ni ninguna actividad ilegal.

---

*Miguel Ángel Ramírez Galicia · MikeUchiha122 · 2026*
