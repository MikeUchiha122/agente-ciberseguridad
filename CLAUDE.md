# agente-ciberseguridad — Contexto para Claude Code

## Proyecto
Agente de ciberseguridad en Python (agente.py v3.0), 837 líneas, 19 funciones.
Suite de tests: test_agente.py (77 tests en 8 bloques).

## Memory
Tienes acceso a memoria persistente via Engram (MCP tools: mem_save, mem_search, etc.).

### Cuándo guardar memoria (mem_save):
- Después de corregir un bug
- Después de añadir una nueva función de detección
- Cuando tomes una decisión de arquitectura
- Cuando descubras un patrón nuevo de amenaza/URL phishing
- Cuando cambies la estructura de tests

### Cuándo buscar en memoria (mem_search):
- Al empezar una sesión nueva ("¿qué hice la última vez con X?")
- Antes de tocar una función que ya modificaste antes
- Si el agente menciona "recuerda" o "recordar"

### Al empezar sesión:
Llama mem_context para recuperar el estado de la sesión anterior.

### Al terminar sesión:
Llama mem_session_summary SIEMPRE antes de terminar. No es opcional.

---

## Parte 4 — Flujo de trabajo práctico

Así quedaría tu día a día con Engram activo:

```
🟢 Abres Claude Code en tu repo
    → Claude llama mem_context automáticamente
    → Recupera: "Última sesión: añadí detección de URLs con VirusTotal API,
                 falta testear edge cases con URLs sin schema"

💻 Trabajas en agente.py
    → Corriges el bug en la función de phishing detection
    → Claude llama mem_save:
        title: "Fix en phishing_detector para URLs sin schema"
        type: "bugfix"  
        content: "Las URLs sin http:// causaban IndexError en parse_url().
                  Fix: añadir normalización antes del parse."

🔴 Cierras la sesión
    → Claude llama mem_session_summary:
        goal: "Mejorar detección de phishing"
        accomplished: ["Fix parse_url", "3 tests nuevos"]
        next: ["Testear con dataset real", "Integrar VirusTotal"]
```

---

## Parte 5 — Comandos CLI útiles para ti

```bash
# Ver todo lo que Engram recuerda de tu proyecto
engram search "agente ciberseguridad"

# Ver contexto de sesiones recientes
engram context

# Ver estadísticas
engram stats

# Abrir la TUI interactiva (navegar memories visualmente)
engram tui

# Exportar toda la memoria a JSON (backup)
engram export backup_engram.json

# Sincronizar con tu repo de GitHub (para persistir entre máquinas)
engram sync
git add .engram/ && git commit -m "sync engram memories"
```

---

## Parte 6 — Git Sync con tu repo

Esto es especialmente útil para ti porque tienes el repo en GitHub. Engram puede guardar las memories **dentro del propio repo** como archivos comprimidos:

```
agente-ciberseguridad/
├── agente.py
├── test_agente.py
├── CLAUDE.md          ← nuevo (contexto para Claude Code)
├── .engram/           ← nuevo (memories sincronizadas)
│   ├── manifest.json
│   └── chunks/
│       └── abc123.jsonl.gz
└── .gitignore         ← añadir: .engram/engram.db
```

En tu `.gitignore` añade:

```
.engram/engram.db
```

Y commitea el resto normalmente. Así si trabajas desde otra máquina, haces `engram sync --import` y recuperas toda la memoria del proyecto.