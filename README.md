# 🔐 Agente de Ciberseguridad v2.0

**Autor:** MikeUchiha

Agente de IA para análisis de threat intelligence. Analiza IPs, dominios, hashes y URLs combinando múltiples fuentes de seguridad.

## Herramientas integradas
- 🦠 VirusTotal — 90+ motores antivirus
- 🚨 AbuseIPDB — reportes de abuso
- 🌍 IPInfo — geolocalización
- 🔍 CVE/NVD — vulnerabilidades conocidas
- 📋 WHOIS — registro de dominios
- 🗺️ Subdominios — Certificate Transparency

## Instalación
pip install anthropic requests python-dotenv

Crea un archivo .env con tus keys:
ANTHROPIC_API_KEY=tu_key
VIRUSTOTAL_API_KEY=tu_key
ABUSEIPDB_API_KEY=tu_key

## Uso
python agente.py

## Aviso
Uso ético y defensivo únicamente.
