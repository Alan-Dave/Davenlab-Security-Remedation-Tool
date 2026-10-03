"""
collector.py — Motor de recolección en vivo del sistema.

Realiza el mismo análisis que SecurityToolkit directamente sobre el sistema:
  1. ProcessCollector   — Lista procesos y valida árboles padre-hijo
  2. DefenderCollector  — Lee eventos de Windows Defender (1011, 1013, 1015)
  3. TaskCollector      — Audita tareas programadas sospechosas
  4. PersistenceCollector — Revisa claves de registro y carpetas de inicio

Cada colector retorna una lista de dicts con las claves:
  id, type, name, severity, desc, raw_data
"""

import subprocess
import json
import logging
import re
import psutil
from datetime import datetime

# ─── Árboles de procesos esperados (línea de base legítima de Windows) ───────
EXPECTED_PARENTS = {
    "wininit.exe":   ["smss.exe"],
    "csrss.exe":     ["smss.exe"],
    "services.exe":  ["wininit.exe"],
    "lsass.exe":     ["wininit.exe"],
    "winlogon.exe":  ["smss.exe"],
    "explorer.exe":  ["userinit.exe", "winlogon.exe"],
    "taskhost.exe":  ["services.exe"],
    "taskhostw.exe": ["services.exe"],
}

# Procesos del sistema que nunca deberían ejecutarse desde fuera de System32
SYSTEM_PROCS_PATHS = [
    "wininit.exe", "csrss.exe", "smss.exe",
    "services.exe", "lsass.exe", "winlogon.exe"
]

# ─── PowerShell helper ───────────────────────────────────────────────────────
def _run_ps(command: str) -> str | None:
    """Ejecuta un comando PowerShell y retorna stdout o None si falla."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as e:
        logging.warning(f"[PowerShell] Error ejecutando comando: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. COLECTOR DE PROCESOS
# ─────────────────────────────────────────────────────────────────────────────
class ProcessCollector:
    def collect(self) -> list[dict]:
        findings = []
        
        # Construir mapa pid → nombre para validar padres
        pid_to_name = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid_to_name[proc.info['pid']] = proc.info['name'].lower()
            except Exception:
                pass

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'cmdline']):
            try:
                info    = proc.info
                pid     = info['pid']
                name    = (info['name'] or "").lower()
                exe     = info.get('exe') or ""
                ppid    = info.get('ppid', 0)
                cmdline = " ".join(info.get('cmdline') or [])
                parent_name = pid_to_name.get(ppid, "unknown").lower()

                severity = None
                reason   = ""

                # Regla 1: Proceso crítico con padre inesperado (Rootkit / Process Spoofing)
                if name in EXPECTED_PARENTS:
                    expected = EXPECTED_PARENTS[name]
                    if parent_name not in expected and parent_name != "unknown":
                        severity = "High"
                        reason = (
                            f"'{name}' fue lanzado por un padre inesperado "
                            f"('{parent_name}'), se esperaba uno de: {expected}."
                        )

                # Regla 2: Proceso sin firma ejecutándose desde Temp / Downloads / AppData
                if not severity and exe:
                    exe_lower = exe.lower()
                    suspicious_dirs = ["\\temp\\", "\\tmp\\", "\\downloads\\",
                                       "\\appdata\\local\\temp\\", "\\users\\public\\"]
                    if any(d in exe_lower for d in suspicious_dirs):
                        is_signed = self._check_signature(exe)
                        if not is_signed:
                            severity = "High"
                            reason = (
                                f"Proceso sin firma ejecutándose desde directorio sospechoso: {exe}"
                            )

                # Regla 3: PowerShell con argumentos ofuscados (-enc / -encodedcommand)
                if not severity and "powershell" in name:
                    if re.search(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", cmdline, re.IGNORECASE):
                        severity = "High"
                        reason = "PowerShell ejecutándose con comando codificado en Base64 (posible ejecución maliciosa)."

                if severity:
                    findings.append({
                        "id":       f"PROC-{pid}",
                        "type":     "Process",
                        "name":     f"PID {pid} {info['name']} ({exe or 'ruta desconocida'})",
                        "severity": severity,
                        "desc":     reason,
                        "raw_data": {
                            "pid": pid, "name": info['name'], "exe": exe,
                            "ppid": ppid, "parent_name": parent_name,
                            "cmdline": cmdline, "username": info.get('username'),
                        }
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return findings

    def _check_signature(self, exe_path: str) -> bool:
        """Verifica si un ejecutable tiene firma digital válida vía PowerShell."""
        out = _run_ps(
            f"(Get-AuthenticodeSignature '{exe_path}').Status"
        )
        return out is not None and "Valid" in out


# ─────────────────────────────────────────────────────────────────────────────
# 2. COLECTOR DE EVENTOS DE WINDOWS DEFENDER
# ─────────────────────────────────────────────────────────────────────────────
class DefenderCollector:
    # IDs de eventos de interés
    INTERESTING_IDS = {
        1006: ("High",   "Detección de malware por Defender"),
        1007: ("High",   "Acción de remediación tomada por Defender"),
        1008: ("Medium", "Remediación fallida por Defender"),
        1009: ("Low",    "Elemento restaurado desde cuarentena"),
        1011: ("Medium", "Detección de malware registrada por Defender"),
        1013: ("Medium", "Detección/remediación de malware registrada por Defender"),
        1015: ("High",   "Comportamiento sospechoso detectado (Behavior:*)"),
        1116: ("High",   "Malware o software no deseado detectado"),
        1117: ("High",   "Acción de protección ejecutada contra malware"),
    }

    def collect(self) -> list[dict]:
        findings = []
        id_filter = ",".join(str(k) for k in self.INTERESTING_IDS)

        ps_cmd = f"""
$events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' `
    -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -in @({id_filter}) }} |
    Select-Object -First 60
$events | ForEach-Object {{
    [PSCustomObject]@{{
        Id          = $_.Id
        TimeCreated = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
        Message     = $_.Message -replace '\\s+', ' '
    }}
}} | ConvertTo-Json -Depth 3
"""
        raw = _run_ps(ps_cmd)
        if not raw:
            return findings

        try:
            events = json.loads(raw)
            if isinstance(events, dict):  # Sólo un evento → envolver en lista
                events = [events]

            for ev in events:
                eid  = int(ev.get("Id", 0))
                time = ev.get("TimeCreated", "")
                msg  = ev.get("Message", "")

                severity, base_desc = self.INTERESTING_IDS.get(eid, ("Medium", "Evento de Defender"))

                # Elevar si hay mención de Boot Record o Rootkit
                if any(kw in msg for kw in ["ModifiedBootRecord", "Rootkit", "Bootkit", "MBR"]):
                    severity = "Critical"

                # Extraer nombre del threat si está en el mensaje
                threat_match = re.search(r"(PUA\w+|Behavior:\w+|Trojan\w*|Ransom\w*|Exploit\w*):\w+\/\w+", msg)
                threat_name  = threat_match.group(0) if threat_match else "Amenaza desconocida"

                findings.append({
                    "id":       f"DEF-{eid}-{time[-8:].replace(':','')}",
                    "type":     "DefenderLog",
                    "name":     f"Defender Event {eid} @ {time}",
                    "severity": severity,
                    "desc":     f"Evento {eid}: {base_desc} ({threat_name}).",
                    "raw_data": {"event_id": eid, "timestamp": time, "message": msg[:400]}
                })

        except json.JSONDecodeError:
            logging.warning("[DefenderCollector] No se pudo parsear JSON de eventos.")

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 3. COLECTOR DE TAREAS PROGRAMADAS
# ─────────────────────────────────────────────────────────────────────────────
class TaskCollector:
    def collect(self) -> list[dict]:
        findings = []
        ps_cmd = """
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
ForEach-Object {
    $action = $_.Actions | Select-Object -First 1
    [PSCustomObject]@{
        Name    = $_.TaskName
        Path    = $_.TaskPath
        Command = $action.Execute
        Args    = $action.Arguments
        Author  = $_.Principal.UserId
        State   = $_.State
    }
} | ConvertTo-Json -Depth 3
"""
        raw = _run_ps(ps_cmd)
        if not raw:
            return findings

        try:
            tasks = json.loads(raw)
            if isinstance(tasks, dict):
                tasks = [tasks]

            for task in tasks:
                name    = task.get("Name", "")
                command = (task.get("Command") or "").lower()
                args    = (task.get("Args") or "").lower()
                full_cmd = f"{command} {args}"

                severity = None
                reason   = ""

                # Regla 1: PowerShell ofuscado (Base64 / -enc)
                if "powershell" in command and re.search(r"-(e(nc)?|encodedcommand)\s+\S{20,}", args, re.IGNORECASE):
                    severity = "Critical"
                    reason   = "Tarea con PowerShell ofuscado en Base64 (técnica de evasión de defensa)."

                # Regla 2: Ejecuta desde ruta sospechosa
                elif any(d in command for d in ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\"]):
                    severity = "High"
                    reason   = f"Tarea programada ejecuta binario desde ruta sospechosa: {command}"

                # Regla 3: Usa mshta, wscript, cscript, regsvr32 (LOLBins)
                elif any(lb in command for lb in ["mshta", "wscript", "cscript", "regsvr32", "rundll32", "certutil"]):
                    severity = "High"
                    reason   = f"Tarea usa binario nativo de Windows para ejecución (LOLBin): {command}"

                if severity:
                    findings.append({
                        "id":       f"TASK-{name[:12].replace(' ','_')}",
                        "type":     "ScheduledTask",
                        "name":     name,
                        "severity": severity,
                        "desc":     reason,
                        "raw_data": task
                    })

        except json.JSONDecodeError:
            logging.warning("[TaskCollector] No se pudo parsear JSON de tareas.")

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# 4. COLECTOR DE PERSISTENCIA (Registro + Startup)
# ─────────────────────────────────────────────────────────────────────────────
class PersistenceCollector:
    RUN_KEYS = [
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    def collect(self) -> list[dict]:
        findings = []

        # Claves de registro Run
        for key in self.RUN_KEYS:
            ps_cmd = f"""
try {{
    Get-ItemProperty -Path '{key}' -ErrorAction Stop |
    Get-Member -MemberType NoteProperty |
    Where-Object {{ $_.Name -notlike 'PS*' }} |
    ForEach-Object {{
        $val = (Get-ItemProperty '{key}').$($_.Name)
        [PSCustomObject]@{{ Key='{key}'; Name=$_.Name; Value=$val }}
    }} | ConvertTo-Json -Depth 2
}} catch {{ '[]' }}
"""
            raw = _run_ps(ps_cmd)
            if not raw or raw == "[]":
                continue

            try:
                entries = json.loads(raw)
                if isinstance(entries, dict):
                    entries = [entries]

                for entry in entries:
                    val = (entry.get("Value") or "").lower()
                    name = entry.get("Name", "")

                    severity = None
                    reason   = ""

                    if any(d in val for d in ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]):
                        severity = "High"
                        reason   = f"Entrada de inicio automático apunta a ruta sospechosa: {val}"
                    elif any(lb in val for lb in ["mshta", "wscript", "cscript", "powershell", "regsvr32"]):
                        severity = "High"
                        reason   = f"Persistencia vía LOLBin en registro: {val}"

                    if severity:
                        findings.append({
                            "id":       f"PERS-{name[:12].replace(' ','_')}",
                            "type":     "Persistence",
                            "name":     f"[Registro] {name}",
                            "severity": severity,
                            "desc":     reason,
                            "raw_data": entry
                        })
            except Exception:
                continue

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# ORQUESTADOR PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
class LiveCollector:
    """
    Orquesta todos los colectores y retorna una lista unificada de hallazgos,
    con un callback opcional para reportar progreso a la UI.
    """

    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback or (lambda msg, pct: None)

    def _report(self, msg: str, pct: int):
        self.progress_callback(msg, pct)

    def collect_all(self) -> list[dict]:
        all_findings = []

        self._report("Analizando procesos en ejecución...", 10)
        try:
            all_findings += ProcessCollector().collect()
        except Exception as e:
            logging.error(f"[ProcessCollector] {e}")

        self._report("Leyendo eventos de Windows Defender...", 35)
        try:
            all_findings += DefenderCollector().collect()
        except Exception as e:
            logging.error(f"[DefenderCollector] {e}")

        self._report("Auditando tareas programadas...", 60)
        try:
            all_findings += TaskCollector().collect()
        except Exception as e:
            logging.error(f"[TaskCollector] {e}")

        self._report("Revisando claves de persistencia...", 80)
        try:
            all_findings += PersistenceCollector().collect()
        except Exception as e:
            logging.error(f"[PersistenceCollector] {e}")

        self._report("Preparando resultados...", 95)
        return all_findings
