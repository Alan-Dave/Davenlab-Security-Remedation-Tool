<div align="center">

<h1>🛡️ Davenlab Security Remediation Tool</h1>

<p>
  <strong>Asistente avanzado de análisis forense y mitigación guiada para Windows</strong><br>
  Diseñado para correlacionar reportes de seguridad, visualizar amenazas y ejecutar acciones de limpieza de forma segura.
</p>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/PyQt6-6.4%2B-green?style=flat-square&logo=qt&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Windows-informational?style=flat-square&logo=windows&logoColor=white"/>
  <img src="https://img.shields.io/badge/Requires-Admin-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square"/>
</p>

</div>

---

## 📸 Vista Previa

| Pantalla de Inicio | Dashboard de Amenazas |
|---|---|
| Escudo central, aviso de permisos y acceso directo a la carpeta de logs | Tabla categorizada con badges de severidad y visor RAW forense |

---

## 🎯 ¿Qué hace esta herramienta?

Davenlab Security Remediation Tool es una aplicación de escritorio en **Python + PyQt6** que actúa como un segundo nivel de análisis sobre los reportes generados por escáneres de seguridad (como [SecurityToolkit](https://wa.me/18493965470)). Su objetivo es guiar al usuario —técnico o no— a través del proceso de mitigación de amenazas de forma **segura y controlada**.

### Capacidades principales

- **🔍 Parser de Logs Real:** Lee archivos `.json` y `.txt` desde la carpeta `logs/` y los normaliza en un modelo de datos unificado.
- **🧠 Motor Heurístico de Correlación:** Aplica reglas automáticas que elevan la severidad de amenazas según su contexto (procesos no firmados en `Temp`, PowerShell ofuscado con Base64, `ModifiedBootRecord`, etc.).
- **📊 Dashboard Visual:** Tabla con filas coloreadas por severidad (`Critical` → rojo, `High` → naranja, `Medium` → amarillo), badges de conteo y visor de datos RAW forenses con doble clic.
- **⚡ Mitigación Híbrida (El Núcleo):**
  - **En Caliente:** Elimina tareas programadas, archivos maliciosos y termina procesos de forma segura.
  - **Asistente de Bajo Nivel:** Detecta amenazas que **no** pueden mitigarse en caliente (rootkits, inyecciones de kernel, `ModifiedBootRecord`) y genera scripts `.bat` para ejecutarse en Modo Seguro, evitando Pantallas Azules (BSOD).
- **🔐 Guardián de Privilegios:** Si no se ejecuta como Administrador, el botón de mitigación se desactiva automáticamente.

---

## 🗂️ Estructura del Proyecto

```
Davenlab-Security-Remediation-Tool/
│
├── main.py                   # Punto de entrada. Verifica permisos y lanza la UI.
├── requirements.txt          # Dependencias (PyQt6)
├── .gitignore
├── README.md
│
├── core/
│   ├── analyzer.py           # Parser de logs (.json y .txt) + motor heurístico
│   ├── mitigator.py          # Mitigación en caliente (taskkill, schtasks, os.remove)
│   └── low_level_guide.py    # Generación de scripts .bat para Modo Seguro
│
├── logs/                     # ← Coloca aquí tus reportes de análisis
│   └── .gitkeep              # (el contenido de esta carpeta está en .gitignore)
│
└── ui/
    └── dashboard.py          # UI completa en PyQt6 (3 pantallas con transiciones fade)
```

---

## 🚀 Instalación y Uso

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU_USUARIO/Davenlab-Security-Remediation-Tool.git
cd Davenlab-Security-Remediation-Tool
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Colocar reportes de análisis

Coloca tus archivos de reporte en la carpeta `logs/`.  
La app acepta dos formatos:

| Formato | Descripción |
|---|---|
| `.json` | Reporte estructurado con clave `findings[]` |
| `.txt` | Reporte en texto plano con el formato `[SEVERITY] Título \n Motivo: ...` |

> La propia aplicación tiene un botón **"📂 Abrir carpeta de logs"** en la pantalla de inicio para acceder a ella directamente.

### 4. Ejecutar **como Administrador**

```powershell
# Abre PowerShell como Administrador y ejecuta:
python main.py
```

> Si lo ejecutas sin permisos de administrador, la aplicación arranca en **Modo Solo Lectura** y el botón de mitigación queda deshabilitado.

---

## 🧠 Lógica de Mitigación

```
Amenaza detectada
       │
       ├── ¿Es tipo "Kernel" o severidad "Critical"?
       │         │
       │         └── SÍ → ⛔ Bloquear mitigación en caliente
       │                      Generar script .bat para Modo Seguro
       │                      Notificar al usuario con instrucciones
       │
       └── NO → ✅ Mitigación En Caliente
                    Process    → taskkill /F /IM <nombre>
                    ScheduledTask → schtasks /Delete /TN <nombre>
                    File       → os.remove(<ruta>)
```

---

## 🔐 Consideraciones de Seguridad

- **Lista blanca de procesos críticos:** `wininit.exe`, `csrss.exe`, `smss.exe`, `lsass.exe`, `svchost.exe` y similares están explícitamente bloqueados de ser terminados en caliente.
- **Confirmación obligatoria:** Toda acción destructiva requiere confirmación del usuario mediante un diálogo modal.
- **Trazabilidad:** Todas las acciones se registran en el log de Python (nivel `INFO`/`ERROR`).
- **Contenido de logs excluido de Git:** La carpeta `logs/` está en `.gitignore` para proteger la privacidad del análisis del sistema.

---

## 📦 Compilar a ejecutable `.exe` (opcional)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=assets/icon.ico main.py
```

El ejecutable se generará en `dist/main.exe`.

---

## 📄 Licencia

Distribuido bajo la licencia **MIT**. Consulta el archivo `LICENSE` para más detalles.

---

<div align="center">
  <sub>Construido con Python + PyQt6 · Diseñado para análisis forense responsable en Windows</sub>
</div>
