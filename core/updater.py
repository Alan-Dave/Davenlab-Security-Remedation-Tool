"""
updater.py — Motor de actualización automática vía GitHub Releases.

Flujo:
  1. Consulta la API de GitHub para obtener el último release.
  2. Compara la versión usando `packaging.version`.
  3. Si hay una nueva versión, la descarga con barra de progreso.
  4. Escribe un script .bat que reemplaza el .exe actual y reinicia la app.
  5. Lanza el script y cierra la app actual.

Configurar GITHUB_OWNER y GITHUB_REPO en config.json antes de distribuir.
"""

import os
import sys
import tempfile
import subprocess
import logging
import requests
from packaging.version import Version
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal

log = logging.getLogger(__name__)

# ─── Constantes (ajustar antes de publicar) ───────────────────────────────────
APP_VERSION   = "1.1.0"
GITHUB_OWNER  = "Alan-Dave"          # ← Cambiar por tu usuario de GitHub
GITHUB_REPO   = "Davenlab-Security-Remedation-Tool"
# Sanitizar por si se ingresa la URL completa
GITHUB_REPO   = GITHUB_REPO.rstrip("/").split("/")[-1].removesuffix(".git") if "/" in GITHUB_REPO else GITHUB_REPO
API_URL       = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
TIMEOUT_SECS  = 8


# ─────────────────────────────────────────────────────────────────────────────
# Hilo de verificación (no bloquea la UI)
# ─────────────────────────────────────────────────────────────────────────────
class UpdateCheckerWorker(QThread):
    """Verifica en segundo plano si hay una nueva versión en GitHub."""
    update_available = pyqtSignal(str, str)  # (version_nueva, download_url)
    no_update        = pyqtSignal(str)        # (version_actual)
    check_failed     = pyqtSignal()

    def run(self):
        try:
            resp = requests.get(API_URL, timeout=TIMEOUT_SECS,
                                headers={"Accept": "application/vnd.github+json"})
            resp.raise_for_status()
            data = resp.json()

            latest_tag = data.get("tag_name", "").lstrip("v")
            if not latest_tag:
                self.check_failed.emit()
                return

            if Version(latest_tag) > Version(APP_VERSION):
                # Buscar el asset .exe entre los adjuntos del release
                download_url = ""
                for asset in data.get("assets", []):
                    if asset.get("name", "").endswith(".exe"):
                        download_url = asset["browser_download_url"]
                        break

                self.update_available.emit(latest_tag, download_url)
            else:
                self.no_update.emit(APP_VERSION)

        except requests.exceptions.ConnectionError:
            log.warning("[Updater] Sin conexión a internet.")
            self.check_failed.emit()
        except Exception as e:
            log.error(f"[Updater] Error inesperado: {e}")
            self.check_failed.emit()


# ─────────────────────────────────────────────────────────────────────────────
# Hilo de descarga con progreso
# ─────────────────────────────────────────────────────────────────────────────
class DownloadWorker(QThread):
    """Descarga el nuevo .exe y emite progreso (0-100)."""
    progress   = pyqtSignal(int)
    finished   = pyqtSignal(str)   # Ruta al archivo descargado
    error      = pyqtSignal(str)

    def __init__(self, url: str, dest_path: str):
        super().__init__()
        self.url       = url
        self.dest_path = dest_path

    def run(self):
        try:
            with requests.get(self.url, stream=True, timeout=60) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length", 0))
                downloaded = 0

                with open(self.dest_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total:
                                pct = int(downloaded * 100 / total)
                                self.progress.emit(pct)

            self.finished.emit(self.dest_path)

        except Exception as e:
            self.error.emit(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Aplicar actualización: script bat que sustituye el .exe en caliente
# ─────────────────────────────────────────────────────────────────────────────
def apply_update(new_exe_path: str):
    """
    Crea un .bat en Temp que:
    1. Espera 2 segundos (para que cierre el proceso actual).
    2. Reemplaza el .exe actual con el nuevo.
    3. Relanza la aplicación.
    4. Se autodestruye.
    """
    current_exe = sys.executable if getattr(sys, 'frozen', False) else None

    if not current_exe:
        log.warning("[Updater] No se detectó exe compilado. La auto-actualización solo funciona en el .exe compilado.")
        return False

    bat_path = os.path.join(tempfile.gettempdir(), "davenlab_updater.bat")
    bat_content = f"""@echo off
echo Aplicando actualizacion de Davenlab Security Tool...
timeout /t 2 /nobreak > nul
del /f /q "{current_exe}"
move /y "{new_exe_path}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
"""
    with open(bat_path, "w") as f:
        f.write(bat_content)

    subprocess.Popen(
        ["cmd", "/c", bat_path],
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    return True
