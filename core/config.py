"""
config.py — Gestión de la configuración persistente de la app.

Lee y escribe config.json en el directorio raíz del proyecto.
"""
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

_DEFAULTS = {
    "language": "es",
    "github_owner": "Alan-Dave",
    "github_repo": "Davenlab-Security-Remedation-Tool",
    "check_updates_on_start": True,
}

def load() -> dict:
    """Carga la configuración desde disco, rellenando valores faltantes."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {**_DEFAULTS, **data}
        except Exception:
            pass
    return _DEFAULTS.copy()

def save(cfg: dict):
    """Escribe la configuración al disco."""
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[Config] Error guardando configuración: {e}")

def get(key: str):
    return load().get(key, _DEFAULTS.get(key))

def set(key: str, value):
    cfg = load()
    cfg[key] = value
    save(cfg)
