"""
analyzer.py — Motor de análisis y correlación heurística.

Fuentes de datos (se combinan automáticamente):
  1. Escaneo EN VIVO del sistema (collector.py)
  2. Archivos de log en la carpeta logs/ (.json y .txt)

Los resultados de ambas fuentes se normalizan, se deduplicican
y se les aplican reglas heurísticas de elevación de severidad.
"""

import json
import logging
import re
from pathlib import Path

from core.collector import LiveCollector

log = logging.getLogger(__name__)


class ThreatAnalyzer:
    def __init__(self, log_dir="logs", progress_callback=None):
        base_path = Path(__file__).parent.parent
        self.log_dir = base_path / log_dir
        self.progress_callback = progress_callback or (lambda msg, pct: None)

    # ─── Parsers de archivos ──────────────────────────────────────────────────

    def _parse_json_log(self, file_path: Path) -> list[dict]:
        threats = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for finding in data.get("findings", []):
                threats.append({
                    "id":       finding.get("finding_id", "UNKNOWN"),
                    "type":     finding.get("category", "Unknown"),
                    "name":     finding.get("name", "Unknown"),
                    "severity": finding.get("severity", "Low"),
                    "desc":     finding.get("description", ""),
                    "raw_data": finding,
                    "source":   f"Log: {file_path.name}"
                })
        except Exception as e:
            log.error(f"Error JSON {file_path.name}: {e}")
        return threats

    def _parse_txt_log(self, file_path: Path) -> list[dict]:
        threats = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            pattern = re.compile(
                r'\[(HIGH|MEDIUM|LOW|CRITICAL)\]\s+(.*?)\n\s+Motivo:\s+(.*?)(?=\n\[|\Z)',
                re.MULTILINE | re.DOTALL
            )
            for i, (severity, title, reason) in enumerate(pattern.findall(content)):
                t_type = "Unknown"
                if "PID" in title:
                    t_type = "Kernel" if any(p in title.lower()
                        for p in ["wininit", "csrss", "smss", "lsass"]) else "Process"
                elif "Defender Event" in title:
                    t_type = "DefenderLog"

                name_clean = title.strip()
                threats.append({
                    "id":       f"LOG-{i+1}",
                    "type":     t_type,
                    "name":     name_clean[:50] + ("..." if len(name_clean) > 50 else ""),
                    "severity": severity.capitalize() if severity != "HIGH" else "High",
                    "desc":     reason.strip(),
                    "raw_data": {"log_entry": title.strip(), "reason": reason.strip()},
                    "source":   f"Log: {file_path.name}"
                })
        except Exception as e:
            log.error(f"Error TXT {file_path.name}: {e}")
        return threats

    # ─── Correlación y enriquecimiento heurístico ─────────────────────────────

    def _apply_heuristics(self, threats: list[dict]) -> list[dict]:
        for t in threats:
            desc = (t.get("desc") or "").lower()
            raw  = t.get("raw_data", {})

            # ① Boot Record modificado → siempre Critical
            if "modifiedbootrecord" in desc or "mbr" in desc or "bootkit" in desc:
                t["severity"] = "Critical"
                t["type"]     = "Kernel"
                t["desc"]     = "🚨 [BOOTKIT] " + t["desc"] + \
                                " — MBR alterado. No mitigar en caliente."

            # ② Proceso crítico con padre inesperado → Critical (BSOD si se mata)
            elif t["type"] in ("Kernel", "Process") and "padre inesperado" in desc:
                t["severity"] = "Critical"
                t["desc"]     = "🚨 [ROOTKIT] " + t["desc"] + \
                                " — No terminar en caliente (riesgo de BSOD)."

            # ③ Proceso sin firma en Temp → elevar a Critical
            elif t["type"] == "Process":
                path = (raw.get("exe") or raw.get("path") or "").lower()
                signed = raw.get("is_signed", True)
                if "temp" in path and not signed:
                    t["severity"] = "Critical"
                    t["desc"] += " [CORRELACIÓN: No firmado en Temp → Critical]"

            # ④ Tarea con PS ofuscado → Critical
            elif t["type"] == "ScheduledTask":
                cmd = (raw.get("command") or raw.get("Args") or "").lower()
                if "powershell" in cmd and re.search(r"-(e(nc)?|encodedcommand)", cmd):
                    t["severity"] = "Critical"
                    t["desc"] += " [CORRELACIÓN: PowerShell ofuscado Base64]"

        return threats

    # ─── Deduplicación ────────────────────────────────────────────────────────

    def _deduplicate(self, threats: list[dict]) -> list[dict]:
        seen = set()
        unique = []
        for t in threats:
            # Clave: tipo + nombre normalizado
            key = (t["type"], t["name"].lower().strip())
            if key not in seen:
                seen.add(key)
                unique.append(t)
        return unique

    # ─── Punto de entrada principal ───────────────────────────────────────────

    def analyze(self) -> list[dict]:
        all_threats = []

        # 1 ── Escaneo en vivo del sistema
        self.progress_callback("Iniciando escaneo en vivo del sistema...", 5)
        try:
            live = LiveCollector(progress_callback=self.progress_callback)
            live_findings = live.collect_all()
            for t in live_findings:
                t.setdefault("source", "Escaneo en vivo")
            all_threats.extend(live_findings)
        except Exception as e:
            log.error(f"[LiveCollector] {e}")

        # 2 ── Leer logs de archivos (si existen)
        self.progress_callback("Leyendo archivos de log...", 90)
        if self.log_dir.exists():
            for f in self.log_dir.glob("*.json"):
                all_threats.extend(self._parse_json_log(f))
            for f in self.log_dir.glob("*.txt"):
                all_threats.extend(self._parse_txt_log(f))

        # 3 ── Correlación heurística
        self.progress_callback("Aplicando correlación heurística...", 95)
        all_threats = self._apply_heuristics(all_threats)

        # 4 ── Deduplicar y ordenar por severidad
        all_threats = self._deduplicate(all_threats)
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        all_threats.sort(key=lambda t: order.get(t["severity"], 9))

        self.progress_callback("Análisis completado.", 100)
        return all_threats
