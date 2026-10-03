import sys
import ctypes
from PyQt6.QtWidgets import QApplication, QMessageBox
from ui.dashboard import Dashboard

def is_admin():
    """Verifica si el script se está ejecutando con privilegios de Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Fase de Auditoría: Comprobar privilegios antes de lanzar la app.
    admin_mode = is_admin()
    if not admin_mode:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Privilegios Insuficientes")
        msg.setText("La aplicación no se está ejecutando como Administrador.\nLas mitigaciones 'En Caliente' estarán deshabilitadas por seguridad.")
        msg.exec()

    window = Dashboard(admin_mode=admin_mode)
    window.show()
    sys.exit(app.exec())
