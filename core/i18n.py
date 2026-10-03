"""
i18n.py — Sistema de internacionalización (i18n) basado en diccionarios.

Idiomas soportados: 'es' (Español), 'en' (English)
Uso:
    from core.i18n import t, set_language
    set_language('en')
    print(t('app_title'))
"""

_CURRENT_LANG = 'es'

STRINGS = {
    # ── Generales ─────────────────────────────────────────────────
    'app_title': {
        'es': 'Davenlab Security Remediation Tool',
        'en': 'Davenlab Security Remediation Tool',
    },
    'app_subtitle': {
        'es': 'Análisis forense y mitigación guiada para Windows',
        'en': 'Forensic analysis and guided mitigation for Windows',
    },
    'app_version_label': {
        'es': 'v{version}  ·  Motor heurístico de análisis forense',
        'en': 'v{version}  ·  Heuristic forensic analysis engine',
    },

    # ── Pantalla de bienvenida ────────────────────────────────────
    'no_admin_warning': {
        'es': '⚠️  Sin privilegios de Administrador — la mitigación en caliente estará bloqueada.',
        'en': '⚠️  No Administrator privileges — hot mitigation will be disabled.',
    },
    'admin_ok': {
        'es': '✅  Ejecutando como Administrador — todas las funciones habilitadas.',
        'en': '✅  Running as Administrator — all features enabled.',
    },
    'logs_hint': {
        'es': 'Coloca tus reportes en la carpeta de logs antes de iniciar:',
        'en': 'Place your reports in the logs folder before starting:',
    },
    'open_logs_folder': {
        'es': '  📂  Abrir carpeta de logs',
        'en': '  📂  Open logs folder',
    },
    'btn_start': {
        'es': '  🔍  INICIAR ANÁLISIS',
        'en': '  🔍  START ANALYSIS',
    },
    'btn_starting': {
        'es': '  ⏳  Iniciando...',
        'en': '  ⏳  Starting...',
    },
    'language_label': {
        'es': 'Idioma / Language:',
        'en': 'Language / Idioma:',
    },

    # ── Pantalla de carga ─────────────────────────────────────────
    'loading_init': {
        'es': 'Inicializando motor de análisis...',
        'en': 'Initializing analysis engine...',
    },

    # ── Dashboard de resultados ───────────────────────────────────
    'dashboard_title': {
        'es': 'Amenazas Detectadas',
        'en': 'Detected Threats',
    },
    'dbl_click_hint': {
        'es': '💡 Doble clic en cualquier fila para ver el reporte forense RAW',
        'en': '💡 Double-click any row to view the raw forensic report',
    },
    'col_severity': {
        'es': 'Severidad',
        'en': 'Severity',
    },
    'col_type': {
        'es': 'Tipo',
        'en': 'Type',
    },
    'col_name': {
        'es': 'Nombre / Identificador',
        'en': 'Name / Identifier',
    },
    'col_desc': {
        'es': 'Descripción',
        'en': 'Description',
    },
    'col_status': {
        'es': 'Estado',
        'en': 'Status',
    },
    'total_findings': {
        'es': 'Total de hallazgos: <b style=\'color:#58a6ff\'>{n}</b>',
        'en': 'Total findings: <b style=\'color:#58a6ff\'>{n}</b>',
    },
    'btn_mitigate': {
        'es': '  ⚡  Comenzar Mitigación',
        'en': '  ⚡  Start Mitigation',
    },
    'btn_mitigate_disabled_tooltip': {
        'es': 'Requiere ejecutar como Administrador',
        'en': 'Requires running as Administrator',
    },

    # ── Mitigación ────────────────────────────────────────────────
    'confirm_mitigation_title': {
        'es': '⚠️ Confirmación de Seguridad',
        'en': '⚠️ Security Confirmation',
    },
    'confirm_mitigation_body': {
        'es': '¿Confirmas que deseas ejecutar la mitigación?\nEsta acción modificará procesos, tareas y archivos del sistema operativo.',
        'en': 'Do you confirm you want to run mitigation?\nThis action will modify OS processes, tasks and files.',
    },
    'critical_threat_title': {
        'es': '🚨 Asistente de Bajo Nivel Requerido',
        'en': '🚨 Low-Level Assistant Required',
    },
    'critical_threat_body': {
        'es': 'Amenaza crítica detectada:\n{name}\n\nEsta amenaza afecta el núcleo del sistema. Mitigarla en caliente causaría un Pantallazo Azul (BSOD).\n\nSe generará un script seguro para Modo Seguro.',
        'en': 'Critical threat detected:\n{name}\n\nThis threat affects the system kernel. Hot mitigation would cause a Blue Screen (BSOD).\n\nA safe-mode script will be generated.',
    },
    'safe_mode_ready_title': {
        'es': '🛡️ Modo Seguro Preparado',
        'en': '🛡️ Safe Mode Ready',
    },
    'safe_mode_ready_body': {
        'es': 'Reinicie el equipo en Modo Seguro y ejecute:\n{path}',
        'en': 'Restart in Safe Mode and execute:\n{path}',
    },
    'mitigation_done_title': {
        'es': '✅ Proceso Finalizado',
        'en': '✅ Process Complete',
    },
    'mitigation_done_body': {
        'es': 'Mitigación completada. Revisa la columna Estado para ver los resultados.',
        'en': 'Mitigation complete. Check the Status column for results.',
    },
    'status_pending': {
        'es': '  Pendiente',
        'en': '  Pending',
    },

    # ── Detalles RAW ──────────────────────────────────────────────
    'raw_dialog_title': {
        'es': '🔍 Detalles Forenses — {name}',
        'en': '🔍 Forensic Details — {name}',
    },
    'raw_dialog_header': {
        'es': '📋 RAW Data — {name}',
        'en': '📋 RAW Data — {name}',
    },
    'raw_no_data': {
        'es': 'Sin datos RAW disponibles para esta amenaza.',
        'en': 'No RAW data available for this threat.',
    },
    'btn_close': {
        'es': 'Cerrar',
        'en': 'Close',
    },

    # ── Updater ───────────────────────────────────────────────────
    'update_available_title': {
        'es': '🆕 Actualización Disponible',
        'en': '🆕 Update Available',
    },
    'update_available_body': {
        'es': 'Nueva versión disponible: <b>{new}</b> (tienes la {current}).<br>¿Deseas descargar e instalar la actualización ahora?',
        'en': 'New version available: <b>{new}</b> (you have {current}).<br>Do you want to download and install the update now?',
    },
    'update_downloading': {
        'es': 'Descargando actualización {version}...',
        'en': 'Downloading update {version}...',
    },
    'update_restart_title': {
        'es': '✅ Descarga Completa',
        'en': '✅ Download Complete',
    },
    'update_restart_body': {
        'es': 'La actualización está lista. La aplicación se reiniciará para aplicarla.',
        'en': 'The update is ready. The application will restart to apply it.',
    },
    'update_error_title': {
        'es': 'Error de Actualización',
        'en': 'Update Error',
    },
    'update_check_failed': {
        'es': 'No se pudo verificar actualizaciones.',
        'en': 'Could not check for updates.',
    },
    'update_no_update': {
        'es': 'Ya tienes la versión más reciente ({version}).',
        'en': 'You already have the latest version ({version}).',
    },

    # ── Resumen de Mitigación y Restauración ──────────────────────
    'summary_dialog_title': {
        'es': '📋 Resumen de Acciones',
        'en': '📋 Action Summary',
    },
    'summary_dialog_header': {
        'es': 'Revisa el plan de mitigación antes de proceder',
        'en': 'Review the mitigation plan before proceeding',
    },
    'action_kill': {
        'es': '🔴 Terminar proceso',
        'en': '🔴 Kill process',
    },
    'action_delete_task': {
        'es': '🗑️ Eliminar tarea',
        'en': '🗑️ Delete task',
    },
    'action_delete_file': {
        'es': '🗑️ Eliminar archivo',
        'en': '🗑️ Delete file',
    },
    'action_safe_mode': {
        'es': '🛡️ Script Modo Seguro (No en caliente)',
        'en': '🛡️ Safe Mode Script (No hot mitig)',
    },
    'action_info_only': {
        'es': 'ℹ️ Solo información (Sin acción)',
        'en': 'ℹ️ Info only (No action)',
    },
    'action_manual_reg': {
        'es': '⚠️ Borrar clave requiere acción manual',
        'en': '⚠️ Key deletion requires manual action',
    },
    'creating_restore_point': {
        'es': 'Creando Punto de Restauración del Sistema (puede tardar un minuto)...',
        'en': 'Creating System Restore Point (may take a minute)...',
    },
    'restore_point_failed': {
        'es': '⚠️ No se pudo crear el Punto de Restauración.\n{error}\n\n¿Continuar con la mitigación de todos modos?',
        'en': '⚠️ Could not create Restore Point.\n{error}\n\nContinue with mitigation anyway?',
    },
    'btn_proceed': {
        'es': 'Proceder',
        'en': 'Proceed',
    },
    'btn_cancel': {
        'es': 'Cancelar',
        'en': 'Cancel',
    },
    'info_skipped': {
        'es': 'ℹ️ Saltado (Solo información)',
        'en': 'ℹ️ Skipped (Info only)',
    },
    'manual_skipped': {
        'es': '⚠️ Requiere limpieza manual (regedit)',
        'en': '⚠️ Requires manual cleanup (regedit)',
    },
}


def set_language(lang: str):
    """Establece el idioma activo. Acepta 'es' o 'en'."""
    global _CURRENT_LANG
    if lang in ('es', 'en'):
        _CURRENT_LANG = lang


def get_language() -> str:
    return _CURRENT_LANG


def t(key: str, **kwargs) -> str:
    """
    Traduce una clave al idioma activo.
    Soporta interpolación de variables: t('total_findings', n=5)
    """
    entry = STRINGS.get(key)
    if not entry:
        return f"[{key}]"
    text = entry.get(_CURRENT_LANG, entry.get('es', f"[{key}]"))
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass
    return text
