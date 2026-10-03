import json
import os
import sys
import tempfile
import subprocess
from pathlib import Path

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QLabel, QDialog, QTextEdit, QProgressBar, QFrame,
    QStackedWidget, QHeaderView, QComboBox, QApplication,
)
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve

from core.analyzer import ThreatAnalyzer
from core.mitigator import Mitigator
from core.low_level_guide import LowLevelGuide
from core.i18n import t, set_language, get_language
from core import config as cfg
from core.updater import (
    UpdateCheckerWorker, DownloadWorker, apply_update, APP_VERSION
)


# ─────────────────────────────────────────────────────────
#  HILO DE ANÁLISIS
# ─────────────────────────────────────────────────────────
class AnalysisWorker(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(str, int)

    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer

    def run(self):
        self.analyzer.progress_callback = lambda msg, pct: self.progress.emit(msg, pct)
        threats = self.analyzer.analyze()
        self.finished.emit(threats)


# ─────────────────────────────────────────────────────────
#  DIÁLOGO DE DETALLES FORENSES (RAW)
# ─────────────────────────────────────────────────────────
class ThreatDetailsDialog(QDialog):
    def __init__(self, threat_name, raw_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t('raw_dialog_title', name=threat_name))
        self.resize(600, 430)
        self.setStyleSheet(STYLE_DARK)

        layout = QVBoxLayout()
        layout.setSpacing(12)

        title = QLabel(f"<b style='color:#58a6ff'>{t('raw_dialog_header', name=threat_name)}</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#30363d"); layout.addWidget(sep)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit { background-color:#010409; color:#e6edf3;
                        border:1px solid #30363d; border-radius:6px; padding:10px; }
        """)
        formatted = json.dumps(raw_data, indent=4, ensure_ascii=False) if raw_data \
                    else t('raw_no_data')
        self.text_edit.setPlainText(formatted)
        self.text_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.text_edit)

        btn_close = QPushButton(t('btn_close'))
        btn_close.setFixedHeight(36)
        btn_close.setStyleSheet(BTN_SECONDARY)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)
        self.setLayout(layout)


# ─────────────────────────────────────────────────────────
#  DIÁLOGO DE DESCARGA DE ACTUALIZACIÓN
# ─────────────────────────────────────────────────────────
class UpdateDownloadDialog(QDialog):
    def __init__(self, version: str, url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t('update_available_title'))
        self.setFixedSize(420, 130)
        self.setStyleSheet(STYLE_DARK)
        self._url     = url
        self._version = version

        layout = QVBoxLayout()
        layout.setSpacing(10)

        self.label = QLabel(t('update_downloading', version=version))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("color:#8b949e;")
        layout.addWidget(self.label)

        self.pct = QLabel("0%")
        self.pct.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pct.setStyleSheet("color:#484f58; font-size:11px;")
        layout.addWidget(self.pct)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100); self.bar.setValue(0)
        self.bar.setTextVisible(False); self.bar.setFixedHeight(8)
        self.bar.setStyleSheet("""
            QProgressBar { background:#21262d; border-radius:4px; }
            QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #1f6feb, stop:1 #58a6ff); border-radius:4px; }
        """)
        layout.addWidget(self.bar)
        self.setLayout(layout)

        # Iniciar descarga
        dest = os.path.join(tempfile.gettempdir(), f"DavenlabSecurityTool_{version}.exe")
        self._worker = DownloadWorker(url, dest)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, pct: int):
        self.bar.setValue(pct)
        self.pct.setText(f"{pct}%")

    def _on_finished(self, path: str):
        QMessageBox.information(self, t('update_restart_title'), t('update_restart_body'))
        if apply_update(path):
            QApplication.quit()
        else:
            self.accept()

    def _on_error(self, msg: str):
        QMessageBox.warning(self, t('update_error_title'), msg)
        self.reject()


# ─────────────────────────────────────────────────────────
#  DIÁLOGO DE RESUMEN DE MITIGACIÓN
# ─────────────────────────────────────────────────────────
class MitigationSummaryDialog(QDialog):
    def __init__(self, plan_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(t('summary_dialog_title'))
        self.resize(700, 450)
        self.setStyleSheet(STYLE_DARK)

        layout = QVBoxLayout()
        
        lbl = QLabel(f"<b style='font-size:14px; color:#e6edf3'>{t('summary_dialog_header')}</b>")
        layout.addWidget(lbl)
        
        # Tabla resumen
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([t('col_severity'), t('col_name'), "Acción Planeada / Planned Action"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.setStyleSheet(TABLE_STYLE)
        
        self.table.setRowCount(len(plan_data))
        for row, (sev, name, action, action_color) in enumerate(plan_data):
            sev_item = QTableWidgetItem(f" {sev} ")
            # Reuse _sev_badge logic manually here for simplicity, or just set color
            sev_item.setForeground(QColor("#e6edf3"))
            self.table.setItem(row, 0, sev_item)
            
            self.table.setItem(row, 1, QTableWidgetItem(name))
            
            act_item = QTableWidgetItem(action)
            act_item.setForeground(QColor(action_color))
            self.table.setItem(row, 2, act_item)
            
            self.table.setRowHeight(row, 28)
            
        layout.addWidget(self.table)
        
        # Advertencia de punto de restauración
        lbl_warn = QLabel("<i>" + t('creating_restore_point') + "</i>")
        lbl_warn.setStyleSheet("color:#8b949e;")
        layout.addWidget(lbl_warn)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        
        btn_cancel = QPushButton(t('btn_cancel'))
        btn_cancel.setStyleSheet(BTN_SECONDARY)
        btn_cancel.setFixedHeight(36)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        
        btn_ok = QPushButton(t('btn_proceed'))
        btn_ok.setStyleSheet(BTN_PRIMARY_GLOW)
        btn_ok.setFixedHeight(36)
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)
        
        layout.addLayout(btn_row)
        self.setLayout(layout)



# ─────────────────────────────────────────────────────────
#  PANTALLA DE BIENVENIDA
# ─────────────────────────────────────────────────────────
class WelcomeScreen(QWidget):
    start_analysis = pyqtSignal()
    language_changed = pyqtSignal(str)

    def __init__(self, admin_mode: bool, app_cfg: dict):
        super().__init__()
        self.admin_mode = admin_mode
        self.app_cfg    = app_cfg
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(14)

        # ── Selector de idioma (top-right) ───────────────────────
        lang_row = QHBoxLayout()
        lang_row.addStretch()
        lang_lbl = QLabel(t('language_label'))
        lang_lbl.setStyleSheet("color:#484f58; font-size:11px;")
        lang_row.addWidget(lang_lbl)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("🇪🇸  Español", "es")
        self.lang_combo.addItem("🇬🇧  English", "en")
        # Seleccionar el idioma actual
        idx = self.lang_combo.findData(get_language())
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.setStyleSheet("""
            QComboBox { background:#161b22; color:#8b949e; border:1px solid #30363d;
                        border-radius:4px; padding:2px 8px; font-size:11px; }
            QComboBox::drop-down { border:none; }
            QComboBox QAbstractItemView { background:#161b22; color:#e6edf3;
                                          selection-background-color:#1f6feb33; }
        """)
        self.lang_combo.currentIndexChanged.connect(self._on_lang_change)
        lang_row.addWidget(self.lang_combo)
        layout.addLayout(lang_row)

        # ── Escudo ───────────────────────────────────────────────
        icon_label = QLabel("🛡️")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("font-size:80px;")
        layout.addWidget(icon_label)

        # ── Título ───────────────────────────────────────────────
        self.title_lbl = QLabel(t('app_title'))
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_lbl.setStyleSheet("color:#e6edf3; font-size:26px; font-weight:bold;")
        layout.addWidget(self.title_lbl)

        self.sub_lbl = QLabel(t('app_subtitle'))
        self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub_lbl.setStyleSheet("color:#8b949e; font-size:13px;")
        layout.addWidget(self.sub_lbl)

        self.ver_lbl = QLabel(t('app_version_label', version=APP_VERSION))
        self.ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ver_lbl.setStyleSheet("color:#484f58; font-size:11px;")
        layout.addWidget(self.ver_lbl)

        layout.addSpacing(8)

        # ── Aviso de permisos ────────────────────────────────────
        if not self.admin_mode:
            self.perm_lbl = QLabel(t('no_admin_warning'))
            self.perm_lbl.setStyleSheet("""
                background-color:#2d1b00; color:#e3b341;
                border:1px solid #9e6a03; border-radius:6px; padding:8px 16px; font-size:12px;
            """)
        else:
            self.perm_lbl = QLabel(t('admin_ok'))
            self.perm_lbl.setStyleSheet("""
                background-color:#0d2a1e; color:#3fb950;
                border:1px solid #238636; border-radius:6px; padding:8px 16px; font-size:12px;
            """)
        self.perm_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.perm_lbl.setWordWrap(True)
        layout.addWidget(self.perm_lbl)

        layout.addSpacing(6)

        # ── Botón de logs ────────────────────────────────────────
        logs_row = QHBoxLayout()
        logs_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logs_hint_lbl = QLabel(t('logs_hint'))
        self.logs_hint_lbl.setStyleSheet("color:#8b949e; font-size:12px;")
        logs_row.addWidget(self.logs_hint_lbl)

        self.btn_logs = QPushButton(t('open_logs_folder'))
        self.btn_logs.setFixedHeight(32)
        self.btn_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_logs.setStyleSheet(BTN_SECONDARY)
        self.btn_logs.clicked.connect(self._open_logs_folder)
        logs_row.addWidget(self.btn_logs)
        layout.addLayout(logs_row)

        layout.addSpacing(16)

        # ── Botón principal ──────────────────────────────────────
        self.btn_start = QPushButton(t('btn_start'))
        self.btn_start.setFixedSize(240, 52)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setStyleSheet(BTN_PRIMARY_GLOW)
        self.btn_start.clicked.connect(self._on_start_clicked)
        layout.addWidget(self.btn_start, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def _on_lang_change(self, idx: int):
        lang = self.lang_combo.itemData(idx)
        set_language(lang)
        cfg.set("language", lang)
        self.language_changed.emit(lang)
        self._refresh_texts()

    def _refresh_texts(self):
        """Actualiza todos los labels de la pantalla al cambiar el idioma."""
        self.title_lbl.setText(t('app_title'))
        self.sub_lbl.setText(t('app_subtitle'))
        self.ver_lbl.setText(t('app_version_label', version=APP_VERSION))
        self.perm_lbl.setText(t('no_admin_warning') if not self.admin_mode else t('admin_ok'))
        self.logs_hint_lbl.setText(t('logs_hint'))
        self.btn_logs.setText(t('open_logs_folder'))
        self.btn_start.setText(t('btn_start'))

    def _open_logs_folder(self):
        logs_path = Path(__file__).parent.parent / "logs"
        logs_path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(logs_path))

    def _on_start_clicked(self):
        self.btn_start.setEnabled(False)
        self.btn_start.setText(t('btn_starting'))
        self.btn_start.setStyleSheet(BTN_DISABLED)
        QTimer.singleShot(400, self.start_analysis.emit)


# ─────────────────────────────────────────────────────────
#  PANTALLA DE CARGA
# ─────────────────────────────────────────────────────────
class LoadingScreen(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        spin = QLabel("⚙️")
        spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        spin.setStyleSheet("font-size:64px;")
        layout.addWidget(spin)

        self.status_label = QLabel(t('loading_init'))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color:#8b949e; font-size:14px;")
        layout.addWidget(self.status_label)

        self.pct_label = QLabel("0%")
        self.pct_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pct_label.setStyleSheet("color:#484f58; font-size:11px;")
        layout.addWidget(self.pct_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100); self.progress.setValue(0)
        self.progress.setFixedWidth(380); self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { background:#21262d; border-radius:4px; }
            QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #1f6feb, stop:1 #58a6ff); border-radius:4px; }
        """)
        layout.addWidget(self.progress, alignment=Qt.AlignmentFlag.AlignCenter)

        self.collector_label = QLabel("")
        self.collector_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.collector_label.setStyleSheet("color:#30363d; font-size:10px; font-style:italic;")
        layout.addWidget(self.collector_label)
        self.setLayout(layout)

    def update_progress(self, message: str, percent: int):
        self.status_label.setText(message)
        self.pct_label.setText(f"{percent}%")
        self.progress.setValue(percent)
        col_map = {
            "proceso": "[ ProcessCollector ]",
            "defender": "[ DefenderCollector ]",
            "tarea": "[ TaskCollector ]",
            "persistencia": "[ PersistenceCollector ]",
            "clave": "[ PersistenceCollector ]",
            "log": "[ LogParser ]",
            "heurística": "[ HeuristicEngine ]",
            "heuristic": "[ HeuristicEngine ]",
        }
        ml = message.lower()
        self.collector_label.setText(
            next((v for k, v in col_map.items() if k in ml), "")
        )


# ─────────────────────────────────────────────────────────
#  PANTALLA DE RESULTADOS
# ─────────────────────────────────────────────────────────
class ResultsScreen(QWidget):
    def __init__(self, threats, admin_mode, mitigator, guide):
        super().__init__()
        self.threats    = threats
        self.admin_mode = admin_mode
        self.mitigator  = mitigator
        self.guide      = guide
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(16, 12, 16, 12)

        # ── Encabezado ───────────────────────────────────────────
        header_row = QHBoxLayout()
        icon = QLabel("🛡️"); icon.setStyleSheet("font-size:22px;")
        header_row.addWidget(icon)
        title = QLabel(t('dashboard_title'))
        title.setStyleSheet("color:#e6edf3; font-size:17px; font-weight:bold;")
        header_row.addWidget(title)
        header_row.addStretch()

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for th in self.threats:
            sev = th.get("severity", "Low")
            if sev in counts: counts[sev] += 1

        badge_styles = {
            "Critical": ("#ff000033", "#ff6b6b"),
            "High":     ("#ff7b0030", "#ffa657"),
            "Medium":   ("#9e6a0330", "#e3b341"),
            "Low":      ("#1f6feb30", "#79c0ff"),
        }
        for sev, (bg, fg) in badge_styles.items():
            if counts[sev] > 0:
                b = QLabel(f"  {sev}: {counts[sev]}  ")
                b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid {fg};"
                                "border-radius:10px; font-size:11px; padding:2px 4px;")
                header_row.addWidget(b); header_row.addSpacing(4)
        layout.addLayout(header_row)

        hint = QLabel(t('dbl_click_hint'))
        hint.setStyleSheet("color:#484f58; font-size:11px; font-style:italic;")
        layout.addWidget(hint)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#21262d;"); layout.addWidget(sep)

        # ── Tabla ────────────────────────────────────────────────
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            t('col_severity'), t('col_type'), t('col_name'), t('col_desc'), t('col_status')
        ])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setStyleSheet(TABLE_STYLE)
        self.table.itemDoubleClicked.connect(self._show_details)
        self.table.setColumnWidth(0, 90); self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 200); self.table.setColumnWidth(4, 120)
        layout.addWidget(self.table)
        self._populate_table()

        # ── Footer ───────────────────────────────────────────────
        footer = QHBoxLayout()
        total_lbl = QLabel(t('total_findings', n=len(self.threats)))
        total_lbl.setTextFormat(Qt.TextFormat.RichText)
        total_lbl.setStyleSheet("color:#8b949e; font-size:12px;")
        footer.addWidget(total_lbl); footer.addStretch()

        self.btn_mitigate = QPushButton(t('btn_mitigate'))
        self.btn_mitigate.setFixedHeight(40)
        self.btn_mitigate.setCursor(Qt.CursorShape.PointingHandCursor)

        if not self.admin_mode:
            self.btn_mitigate.setEnabled(False)
            self.btn_mitigate.setToolTip(t('btn_mitigate_disabled_tooltip'))
            self.btn_mitigate.setStyleSheet(BTN_DISABLED)
        else:
            self.btn_mitigate.setStyleSheet(BTN_PRIMARY_GLOW)
            self.btn_mitigate.clicked.connect(self._run_mitigation)

        footer.addWidget(self.btn_mitigate)
        layout.addLayout(footer)
        self.setLayout(layout)

    def _sev_badge(self, severity):
        colors = {
            "Critical": ("#ff6b6b", "#1a0000"), "High": ("#ffa657", "#1a0a00"),
            "Medium": ("#e3b341", "#1a1000"),   "Low":  ("#79c0ff", "#00101a"),
        }
        return colors.get(severity, ("#8b949e", "#161b22"))

    def _populate_table(self):
        self.table.setRowCount(len(self.threats))
        for row, threat in enumerate(self.threats):
            sev = threat.get("severity", "Low")
            fg, bg = self._sev_badge(sev)
            sev_item = QTableWidgetItem(f"  {sev}")
            sev_item.setForeground(QColor(fg)); sev_item.setBackground(QColor(bg))
            self.table.setItem(row, 0, sev_item)

            for col, key in enumerate(["type", "name", "desc"], start=1):
                item = QTableWidgetItem(threat.get(key, ""))
                item.setForeground(QColor("#e6edf3"))
                self.table.setItem(row, col, item)

            status = QTableWidgetItem(t('status_pending'))
            status.setForeground(QColor("#8b949e"))
            self.table.setItem(row, 4, status)
            self.table.setRowHeight(row, 34)

    def _show_details(self, item):
        row = item.row()
        if row < len(self.threats):
            th = self.threats[row]
            ThreatDetailsDialog(th["name"], th.get("raw_data", {}), self).exec()

    def _set_status(self, row, text, color):
        item = QTableWidgetItem(f"  {text}")
        item.setForeground(QColor(color))
        self.table.setItem(row, 4, item)

    def _run_mitigation(self):
        # 1. Generar plan de mitigación
        plan_data = []
        for th in self.threats:
            t_type, t_name, t_sev = th["type"], th["name"], th["severity"]
            if t_sev == "Critical" or t_type == "Kernel":
                action = t('action_safe_mode'); color = "#e3b341"
            elif t_type == "Process":
                action = t('action_kill'); color = "#ff6b6b"
            elif t_type == "ScheduledTask":
                action = t('action_delete_task'); color = "#ff6b6b"
            elif t_type == "File":
                action = t('action_delete_file'); color = "#ff6b6b"
            elif t_type == "DefenderLog":
                action = t('action_info_only'); color = "#8b949e"
            elif t_type == "Persistence":
                action = t('action_manual_reg'); color = "#e3b341"
            else:
                action = "Desconocido"; color = "#8b949e"
            
            plan_data.append((t_sev, t_name, action, color))
            
        # 2. Mostrar resumen al usuario
        summary_dlg = MitigationSummaryDialog(plan_data, self)
        if summary_dlg.exec() != QDialog.DialogCode.Accepted:
            return

        # 3. Crear Punto de Restauración
        self.btn_mitigate.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        
        ok, msg = self.mitigator.create_restore_point()
        
        QApplication.restoreOverrideCursor()
        
        if not ok:
            reply = QMessageBox.warning(
                self, "Restore Point", 
                t('restore_point_failed', error=msg),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.btn_mitigate.setEnabled(True)
                return

        # 4. Ejecutar mitigación
        for row in range(self.table.rowCount()):
            th = self.threats[row]
            t_type, t_name, t_sev = th["type"], th["name"], th["severity"]

            if t_sev == "Critical" or t_type == "Kernel":
                QMessageBox.critical(self, t('critical_threat_title'), t('critical_threat_body', name=t_name))
                ok, path = self.guide.generate_safe_mode_script(t_name, t_type)
                self._set_status(row, f"Script → {path}" if ok else "Error", "#e3b341")
                continue
                
            if t_type == "DefenderLog":
                self._set_status(row, t('info_skipped'), "#8b949e")
                continue
                
            if t_type == "Persistence":
                self._set_status(row, t('manual_skipped'), "#e3b341")
                continue

            success, msg = False, ""
            if t_type == "Process":
                success, msg = self.mitigator.mitigate_process(t_name)
            elif t_type == "ScheduledTask":
                success, msg = self.mitigator.mitigate_task(t_name)
            elif t_type == "File":
                success, msg = self.mitigator.mitigate_file(t_name)

            self._set_status(row, ("✅ " if success else "❌ ") + msg,
                             "#3fb950" if success else "#f85149")

        self.btn_mitigate.setEnabled(True)
        QMessageBox.information(self, t('mitigation_done_title'), t('mitigation_done_body'))


# ─────────────────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ─────────────────────────────────────────────────────────
class Dashboard(QMainWindow):
    def __init__(self, admin_mode=False, app_cfg=None):
        super().__init__()
        self.admin_mode = admin_mode
        self.app_cfg    = app_cfg or {}
        self.analyzer   = ThreatAnalyzer()
        self.mitigator  = Mitigator()
        self.guide      = LowLevelGuide()

        self.setWindowTitle(t('app_title'))
        self.setMinimumSize(900, 580)
        self.setStyleSheet(STYLE_DARK)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.welcome = WelcomeScreen(admin_mode, self.app_cfg)
        self.welcome.start_analysis.connect(self._begin_analysis)
        self.stack.addWidget(self.welcome)

        self.loading = LoadingScreen()
        self.stack.addWidget(self.loading)

        # ── Verificar actualizaciones en background (silencioso) ─
        if self.app_cfg.get("check_updates_on_start", True):
            self._check_updates_silent()

    def _check_updates_silent(self):
        """Lanza la verificación en background; solo muestra diálogo si hay update."""
        self._update_worker = UpdateCheckerWorker()
        self._update_worker.update_available.connect(self._on_update_available)
        # no_update y check_failed se ignoran silenciosamente
        self._update_worker.start()

    def _on_update_available(self, version: str, url: str):
        reply = QMessageBox.question(
            self, t('update_available_title'),
            t('update_available_body', new=version, current=APP_VERSION),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if reply == QMessageBox.StandardButton.Yes:
            dlg = UpdateDownloadDialog(version, url, self)
            dlg.exec()

    def _fade_to(self, new_widget):
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        self.stack.addWidget(new_widget)
        self.stack.setCurrentWidget(new_widget)
        effect = QGraphicsOpacityEffect(new_widget)
        new_widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(380); anim.setStartValue(0.0); anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()
        self._current_anim = anim

    def _begin_analysis(self):
        self._fade_to(self.loading)
        self.worker = AnalysisWorker(self.analyzer)
        self.worker.finished.connect(self._show_results)
        self.worker.progress.connect(self.loading.update_progress)
        self.worker.start()

    def _show_results(self, threats):
        results = ResultsScreen(threats, self.admin_mode, self.mitigator, self.guide)
        QTimer.singleShot(600, lambda: self._fade_to(results))


# ─────────────────────────────────────────────────────────
#  ESTILOS GLOBALES
# ─────────────────────────────────────────────────────────
STYLE_DARK = """
    QMainWindow, QWidget { background-color:#0d1117; color:#e6edf3;
                           font-family:'Segoe UI',sans-serif; font-size:13px; }
    QDialog { background-color:#161b22; }
    QScrollBar:vertical { background:#161b22; width:8px; border-radius:4px; }
    QScrollBar::handle:vertical { background:#30363d; border-radius:4px; min-height:20px; }
"""

BTN_PRIMARY_GLOW = """
    QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #1f6feb,stop:1 #388bfd);
                  color:white; border:none; border-radius:8px;
                  font-size:13px; font-weight:bold; padding:0 20px; }
    QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #388bfd,stop:1 #58a6ff); }
    QPushButton:pressed { background:#1f6feb; }
"""

BTN_SECONDARY = """
    QPushButton { background:#21262d; color:#8b949e; border:1px solid #30363d;
                  border-radius:6px; padding:0 16px; font-size:12px; }
    QPushButton:hover { background:#30363d; color:#e6edf3; }
"""

BTN_DISABLED = """
    QPushButton { background:#161b22; color:#484f58; border:1px solid #21262d;
                  border-radius:8px; font-size:13px; padding:0 20px; }
"""

TABLE_STYLE = """
    QTableWidget { background-color:#161b22; alternate-background-color:#1a1f27;
                   border:1px solid #21262d; border-radius:8px;
                   gridline-color:transparent; color:#e6edf3;
                   selection-background-color:#1f6feb55; outline:none; }
    QHeaderView::section { background-color:#0d1117; color:#8b949e;
                           font-size:11px; font-weight:bold;
                           padding:6px 8px; border:none;
                           border-bottom:1px solid #21262d; }
    QTableWidget::item { padding:4px 8px; border-bottom:1px solid #21262d11; }
    QTableWidget::item:selected { background-color:#1f6feb33; color:#e6edf3; }
"""
