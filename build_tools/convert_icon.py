"""
Script de conversión: convierte el JPG del ícono generado a formato .ico
con múltiples resoluciones (16, 32, 48, 64, 128, 256 px) para máxima
compatibilidad en Windows (barra de tareas, escritorio, instalador).

Ejecutar UNA sola vez antes de compilar con PyInstaller:
    python build_tools/convert_icon.py
"""

from PIL import Image
from pathlib import Path
import sys

def convert_to_ico():
    project_root = Path(__file__).parent.parent
    
    # Buscar el JPG del ícono generado (copia manual a assets/)
    src = project_root / "assets" / "icon.jpg"
    dst = project_root / "assets" / "icon.ico"
    
    if not src.exists():
        print(f"[ERROR] No se encontró: {src}")
        print("  → Copia el archivo de ícono JPG a la carpeta assets/ con el nombre 'icon.jpg'")
        sys.exit(1)
    
    img = Image.open(src).convert("RGBA")
    
    sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
    icons = [img.resize(s, Image.LANCZOS) for s in sizes]
    
    icons[0].save(dst, format="ICO", sizes=sizes, append_images=icons[1:])
    print(f"[OK] Ícono generado: {dst}")

if __name__ == "__main__":
    convert_to_ico()
