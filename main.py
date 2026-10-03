import sys
import ctypes
from PyQt6.QtWidgets import QApplication, QMessageBox
from core import config as cfg
from core.i18n import set_language, t
from ui.dashboard import Dashboard

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # ── Cargar configuración y aplicar idioma ──────────────────────
    app_cfg = cfg.load()
    set_language(app_cfg.get("language", "es"))

    # ── Comprobar privilegios ──────────────────────────────────────
    admin_mode = is_admin()
    if not admin_mode:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Privilegios Insuficientes / Insufficient Privileges")
        msg.setText(t('no_admin_warning'))
        msg.exec()

    window = Dashboard(admin_mode=admin_mode, app_cfg=app_cfg)
    window.show()
    sys.exit(app.exec())
