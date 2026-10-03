from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QLabel, QDialog, QTextEdit, QProgressBar, QFrame, QSizePolicy,
    QStackedWidget, QHeaderView, QGraphicsDropShadowEffect, QApplication
)
from PyQt6.QtGui import QColor, QFont, QLinearGradient, QPainter, QBrush, QPen, QIcon
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QRect
import json
import os
import subprocess
from pathlib import Path
from core.analyzer import ThreatAnalyzer
from core.mitigator import Mitigator
from core.low_level_guide import LowLevelGuide

# ─────────────────────────────────────────────────────────
#  HILO DE ANÁLISIS (para no congelar la UI)
# ─────────────────────────────────────────────────────────
class AnalysisWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer

    def run(self):
        threats = self.analyzer.analyze()
        self.finished.emit(threats)

# ─────────────────────────────────────────────────────────
#  DIÁLOGO DE DETALLES FORENSES (RAW DATA)
# ─────────────────────────────────────────────────────────
class ThreatDetailsDialog(QDialog):
    def __init__(self, threat_name, raw_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"🔍 Detalles Forenses — {threat_name}")
        self.resize(600, 430)
        self.setStyleSheet(STYLE_DARK)

        layout = QVBoxLayout()
        layout.setSpacing(12)

        title = QLabel(f"<b style='color:#58a6ff'>📋 RAW Data — {threat_name}</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#30363d")
        layout.addWidget(sep)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #010409;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        formatted = json.dumps(raw_data, indent=4, ensure_ascii=False) if raw_data else "Sin datos RAW disponibles."
        self.text_edit.setPlainText(formatted)
        self.text_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.text_edit)

        btn_close = QPushButton("Cerrar")
        btn_close.setFixedHeight(36)
        btn_close.setStyleSheet(BTN_SECONDARY)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)

        self.setLayout(layout)

# ─────────────────────────────────────────────────────────
#  PANTALLA DE BIENVENIDA
# ─────────────────────────────────────────────────────────
class WelcomeScreen(QWidget):
    start_analysis = pyqtSignal()

    def __init__(self, admin_mode):
        super().__init__()
        self.admin_mode = admin_mode
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        # Ícono escudo (emoji grande como sustituto visual)
        icon_label = QLabel("🛡️")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("font-size: 80px;")
        layout.addWidget(icon_label)

        # Título principal
        title = QLabel("Davenlab Security\nRemediation Tool")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#e6edf3; font-size:28px; font-weight:bold; letter-spacing:1px;")
        layout.addWidget(title)

        # Subtítulo
        sub = QLabel("Análisis forense y mitigación guiada para Windows")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color:#8b949e; font-size:13px;")
        layout.addWidget(sub)

        # Versión / crédito
        ver = QLabel("v2.0  ·  Motor heurístico de análisis forense")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color:#484f58; font-size:11px;")
        layout.addWidget(ver)

        layout.addSpacing(12)

        # Aviso de permisos
        if not self.admin_mode:
            warn = QLabel("⚠️  Sin privilegios de Administrador — la mitigación en caliente estará bloqueada.")
            warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn.setWordWrap(True)
            warn.setStyleSheet("""
                background-color:#2d1b00; color:#e3b341;
                border:1px solid #9e6a03; border-radius:6px;
                padding:8px 16px; font-size:12px;
            """)
            layout.addWidget(warn)
        else:
            ok = QLabel("✅  Ejecutando como Administrador — todas las funciones habilitadas.")
            ok.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ok.setStyleSheet("""
                background-color:#0d2a1e; color:#3fb950;
                border:1px solid #238636; border-radius:6px;
                padding:8px 16px; font-size:12px;
            """)
            layout.addWidget(ok)

        layout.addSpacing(10)

        # ── Botón para abrir la carpeta de logs ──────────────────
        logs_row = QHBoxLayout()
        logs_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logs_hint = QLabel("Coloca tus reportes en la carpeta de logs antes de iniciar:")
        logs_hint.setStyleSheet("color:#8b949e; font-size:12px;")
        logs_row.addWidget(logs_hint)

        btn_logs = QPushButton("  📂  Abrir carpeta de logs")
        btn_logs.setFixedHeight(32)
        btn_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_logs.setStyleSheet(BTN_SECONDARY)
        btn_logs.clicked.connect(self._open_logs_folder)
        logs_row.addWidget(btn_logs)

        layout.addLayout(logs_row)
        layout.addSpacing(20)

        # ── Botón principal INICIAR ANÁLISIS ─────────────────────
        self.btn_start = QPushButton("  🔍  INICIAR ANÁLISIS")
        self.btn_start.setFixedSize(240, 52)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setStyleSheet(BTN_PRIMARY_GLOW)
        self.btn_start.clicked.connect(self._on_start_clicked)
        layout.addWidget(self.btn_start, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def _open_logs_folder(self):
        """Crea la carpeta si no existe y la abre en el Explorador de Windows."""
        logs_path = Path(__file__).parent.parent / "logs"
        logs_path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(logs_path))

    def _on_start_clicked(self):
        """Deshabilita el botón y emite la señal con un pequeño delay para sentir la transición."""
        self.btn_start.setEnabled(False)
        self.btn_start.setText("  ⏳  Iniciando...")
        self.btn_start.setStyleSheet(BTN_DISABLED)
        QTimer.singleShot(400, self.start_analysis.emit)

# ─────────────────────────────────────────────────────────
#  PANTALLA DE CARGA / ANÁLISIS
# ─────────────────────────────────────────────────────────
class LoadingScreen(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        spin = QLabel("⚙️")
        spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        spin.setStyleSheet("font-size:64px;")
        layout.addWidget(spin)

        self.status_label = QLabel("Inicializando motor de análisis...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color:#8b949e; font-size:14px;")
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # Modo indeterminado (animado)
        self.progress.setFixedWidth(340)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { background:#21262d; border-radius:3px; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1f6feb, stop:1 #58a6ff); border-radius:3px; }
        """)
        layout.addWidget(self.progress, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

        # Animación de mensajes
        self._messages = [
            "Leyendo reportes de SecurityToolkit...",
            "Correlacionando procesos y eventos de Defender...",
            "Aplicando reglas heurísticas...",
            "Evaluando árbol de procesos del sistema...",
            "Preparando resultados...",
        ]
        self._msg_idx = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._cycle_message)
        self._timer.start(900)

    def _cycle_message(self):
        self.status_label.setText(self._messages[self._msg_idx % len(self._messages)])
        self._msg_idx += 1

# ─────────────────────────────────────────────────────────
#  PANTALLA DE RESULTADOS (DASHBOARD)
# ─────────────────────────────────────────────────────────
class ResultsScreen(QWidget):
    def __init__(self, threats, admin_mode, mitigator, guide):
        super().__init__()
        self.threats = threats
        self.admin_mode = admin_mode
        self.mitigator = mitigator
        self.guide = guide
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(16, 12, 16, 12)

        # ─── Encabezado de resultados ───
        header_row = QHBoxLayout()

        icon = QLabel("🛡️")
        icon.setStyleSheet("font-size:22px;")
        header_row.addWidget(icon)

        title = QLabel("Amenazas Detectadas")
        title.setStyleSheet("color:#e6edf3; font-size:17px; font-weight:bold;")
        header_row.addWidget(title)
        header_row.addStretch()

        # Badges de conteo
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for t in self.threats:
            sev = t.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1

        badge_styles = {
            "Critical": ("#ff000033", "#ff6b6b"),
            "High":     ("#ff7b0030", "#ffa657"),
            "Medium":   ("#9e6a0330", "#e3b341"),
            "Low":      ("#1f6feb30", "#79c0ff"),
        }
        for sev, (bg, fg) in badge_styles.items():
            if counts[sev] > 0:
                b = QLabel(f"  {sev}: {counts[sev]}  ")
                b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid {fg}; border-radius:10px; font-size:11px; padding:2px 4px;")
                header_row.addWidget(b)
                header_row.addSpacing(4)

        layout.addLayout(header_row)

        hint = QLabel("💡 Doble clic en cualquier fila para ver el reporte forense RAW")
        hint.setStyleSheet("color:#484f58; font-size:11px; font-style:italic;")
        layout.addWidget(hint)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#21262d;")
        layout.addWidget(sep)

        # ─── Tabla ───
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severidad", "Tipo", "Nombre / Identificador", "Descripción", "Estado"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setStyleSheet(TABLE_STYLE)
        self.table.itemDoubleClicked.connect(self._show_details)
        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 200)
        self.table.setColumnWidth(4, 120)
        layout.addWidget(self.table)

        self._populate_table()

        # ─── Barra inferior ───
        footer = QHBoxLayout()

        total_lbl = QLabel(f"Total de hallazgos: <b style='color:#58a6ff'>{len(self.threats)}</b>")
        total_lbl.setTextFormat(Qt.TextFormat.RichText)
        total_lbl.setStyleSheet("color:#8b949e; font-size:12px;")
        footer.addWidget(total_lbl)
        footer.addStretch()

        self.btn_mitigate = QPushButton("  ⚡  Comenzar Mitigación")
        self.btn_mitigate.setFixedHeight(40)
        self.btn_mitigate.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mitigate.setStyleSheet(BTN_PRIMARY_GLOW)
        self.btn_mitigate.clicked.connect(self._run_mitigation)

        if not self.admin_mode:
            self.btn_mitigate.setEnabled(False)
            self.btn_mitigate.setToolTip("Requiere ejecutar como Administrador")
            self.btn_mitigate.setStyleSheet(BTN_DISABLED)

        footer.addWidget(self.btn_mitigate)
        layout.addLayout(footer)

        self.setLayout(layout)

    def _sev_badge(self, severity):
        colors = {
            "Critical": ("#ff6b6b", "#1a0000"),
            "High":     ("#ffa657", "#1a0a00"),
            "Medium":   ("#e3b341", "#1a1000"),
            "Low":      ("#79c0ff", "#00101a"),
        }
        fg, bg = colors.get(severity, ("#8b949e", "#161b22"))
        return fg, bg

    def _populate_table(self):
        self.table.setRowCount(len(self.threats))
        for row, threat in enumerate(self.threats):
            sev = threat.get("severity", "Low")
            fg, bg = self._sev_badge(sev)

            # Columna 0: Severity badge
            sev_item = QTableWidgetItem(f"  {sev}")
            sev_item.setForeground(QColor(fg))
            sev_item.setBackground(QColor(bg))
            self.table.setItem(row, 0, sev_item)

            for col, key in enumerate(["type", "name", "desc"], start=1):
                item = QTableWidgetItem(threat.get(key, ""))
                item.setForeground(QColor("#e6edf3"))
                self.table.setItem(row, col, item)

            status_item = QTableWidgetItem("  Pendiente")
            status_item.setForeground(QColor("#8b949e"))
            self.table.setItem(row, 4, status_item)

            self.table.setRowHeight(row, 34)

    def _show_details(self, item):
        row = item.row()
        if row < len(self.threats):
            threat = self.threats[row]
            dlg = ThreatDetailsDialog(threat["name"], threat.get("raw_data", {}), self)
            dlg.exec()

    def _run_mitigation(self):
        reply = QMessageBox.question(
            self, "⚠️ Confirmación de Seguridad",
            "¿Confirmas que deseas ejecutar la mitigación?\n"
            "Esta acción modificará procesos, tareas y archivos del sistema operativo.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.No:
            return

        for row in range(self.table.rowCount()):
            t_type = self.threats[row]["type"]
            t_name = self.threats[row]["name"]
            t_sev  = self.threats[row]["severity"]

            if t_sev == "Critical" or t_type == "Kernel":
                QMessageBox.critical(
                    self, "🚨 Asistente de Bajo Nivel Requerido",
                    f"Amenaza crítica detectada:\n<b>{t_name}</b>\n\n"
                    "Esta amenaza afecta el núcleo del sistema. Mitigarla en caliente "
                    "causaría un Pantallazo Azul (BSOD).\n\n"
                    "Se generará un script seguro para Modo Seguro."
                )
                ok, path = self.guide.generate_safe_mode_script(t_name, t_type)
                msg = f"Script → {path}" if ok else "Error al generar script"
                self._set_status(row, msg, "#e3b341")
                continue

            success, msg = False, ""
            if t_type == "Process":
                success, msg = self.mitigator.mitigate_process(t_name)
            elif t_type == "ScheduledTask":
                success, msg = self.mitigator.mitigate_task(t_name)
            elif t_type == "File":
                success, msg = self.mitigator.mitigate_file(t_name)

            color = "#3fb950" if success else "#f85149"
            self._set_status(row, ("✅ " if success else "❌ ") + msg, color)

        QMessageBox.information(self, "✅ Proceso Finalizado",
                                "Mitigación completada. Revisa la columna Estado para ver los resultados.")

    def _set_status(self, row, text, color):
        item = QTableWidgetItem(f"  {text}")
        item.setForeground(QColor(color))
        self.table.setItem(row, 4, item)

# ─────────────────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ─────────────────────────────────────────────────────────
class Dashboard(QMainWindow):
    def __init__(self, admin_mode=False):
        super().__init__()
        self.admin_mode = admin_mode
        self.analyzer = ThreatAnalyzer()
        self.mitigator = Mitigator()
        self.guide = LowLevelGuide()

        self.setWindowTitle("Davenlab Security Remediation Tool")
        self.setMinimumSize(860, 560)
        self.setStyleSheet(STYLE_DARK)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Pantalla 1: Bienvenida
        self.welcome = WelcomeScreen(admin_mode)
        self.welcome.start_analysis.connect(self._begin_analysis)
        self.stack.addWidget(self.welcome)

        # Pantalla 2: Carga
        self.loading = LoadingScreen()
        self.stack.addWidget(self.loading)

        # La pantalla 3 (resultados) se añade dinámicamente

    def _fade_to(self, new_widget):
        """Hace un fade-out de la pantalla actual y fade-in de la nueva."""
        from PyQt6.QtWidgets import QGraphicsOpacityEffect
        from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

        # Mostrar la nueva pantalla
        self.stack.addWidget(new_widget)
        self.stack.setCurrentWidget(new_widget)

        # Fade-in sobre la nueva pantalla
        effect = QGraphicsOpacityEffect(new_widget)
        new_widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(380)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()
        # Mantener referencia para que no sea recolectado por el GC
        self._current_anim = anim

    def _begin_analysis(self):
        self._fade_to(self.loading)
        self.worker = AnalysisWorker(self.analyzer)
        self.worker.finished.connect(self._show_results)
        self.worker.start()

    def _show_results(self, threats):
        results = ResultsScreen(threats, self.admin_mode, self.mitigator, self.guide)
        # Pequeño delay para que la pantalla de carga sea visible al menos un momento
        QTimer.singleShot(600, lambda: self._fade_to(results))


# ─────────────────────────────────────────────────────────
#  ESTILOS GLOBALES
# ─────────────────────────────────────────────────────────
STYLE_DARK = """
    QMainWindow, QWidget {
        background-color: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', sans-serif;
        font-size: 13px;
    }
    QDialog {
        background-color: #161b22;
    }
    QScrollBar:vertical {
        background:#161b22; width:8px; border-radius:4px;
    }
    QScrollBar::handle:vertical {
        background:#30363d; border-radius:4px; min-height:20px;
    }
"""

BTN_PRIMARY_GLOW = """
    QPushButton {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1f6feb, stop:1 #388bfd);
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 13px;
        font-weight: bold;
        padding: 0 20px;
    }
    QPushButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #388bfd, stop:1 #58a6ff);
    }
    QPushButton:pressed {
        background: #1f6feb;
    }
"""

BTN_SECONDARY = """
    QPushButton {
        background:#21262d; color:#8b949e;
        border:1px solid #30363d; border-radius:6px;
        padding:0 16px; font-size:12px;
    }
    QPushButton:hover { background:#30363d; color:#e6edf3; }
"""

BTN_DISABLED = """
    QPushButton {
        background:#161b22; color:#484f58;
        border:1px solid #21262d; border-radius:8px;
        font-size:13px; padding:0 20px;
    }
"""

TABLE_STYLE = """
    QTableWidget {
        background-color: #161b22;
        alternate-background-color: #1a1f27;
        border: 1px solid #21262d;
        border-radius: 8px;
        gridline-color: transparent;
        color: #e6edf3;
        selection-background-color: #1f6feb55;
        outline: none;
    }
    QHeaderView::section {
        background-color: #0d1117;
        color: #8b949e;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding: 6px 8px;
        border: none;
        border-bottom: 1px solid #21262d;
    }
    QTableWidget::item {
        padding: 4px 8px;
        border-bottom: 1px solid #21262d11;
    }
    QTableWidget::item:selected {
        background-color: #1f6feb33;
        color: #e6edf3;
    }
"""
