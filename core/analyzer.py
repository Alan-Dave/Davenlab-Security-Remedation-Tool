import json
import logging
import re
from pathlib import Path

class ThreatAnalyzer:
    def __init__(self, log_dir="logs"):
        base_path = Path(__file__).parent.parent
        self.log_dir = base_path / log_dir

    def _parse_json_log(self, file_path):
        threats = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for finding in data.get("findings", []):
                threats.append({
                    "id": finding.get("finding_id", "UNKNOWN"),
                    "type": finding.get("category", "Unknown"),
                    "name": finding.get("name", "Unknown"),
                    "severity": finding.get("severity", "Low"),
                    "desc": finding.get("description", ""),
                    "raw_data": finding
                })
        except Exception:
            pass
        return threats

    def _parse_txt_log(self, file_path):
        """Parsea reportes en texto plano como el de SecurityToolkit."""
        threats = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Expresión regular para capturar el formato: [SEVERITY] Nombre \n Motivo: Detalle
            pattern = re.compile(r'\[(HIGH|MEDIUM|LOW)\]\s+(.*?)\n\s+Motivo:\s+(.*?)(?=\n\[|\Z)', re.MULTILINE | re.DOTALL)
            matches = pattern.findall(content)
            
            for i, (severity, title, reason) in enumerate(matches):
                t_type = "Unknown"
                name_clean = title.strip()
                
                # Clasificar el tipo de amenaza basándonos en el título
                if "PID" in title:
                    if "wininit" in title.lower() or "csrss" in title.lower() or "smss" in title.lower():
                        t_type = "Kernel"
                    else:
                        t_type = "Process"
                elif "Defender Event" in title:
                    t_type = "DefenderLog"
                    
                threat = {
                    "id": f"REAL-{i+1}",
                    "type": t_type,
                    "name": name_clean[:40] + "..." if len(name_clean) > 40 else name_clean,
                    "severity": "High" if severity == "HIGH" else severity.capitalize(),
                    "desc": reason.strip(),
                    "raw_data": {"log_entry": title.strip(), "reason": reason.strip()}
                }
                threats.append(threat)
        except Exception as e:
            logging.error(f"Error al leer log txt {file_path.name}: {e}")
            
        return threats

    def analyze(self):
        all_threats = []
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True, exist_ok=True)
            return all_threats
            
        # 1. Ingesta
        for log_file in self.log_dir.glob("*.json"):
            all_threats.extend(self._parse_json_log(log_file))
            
        for log_file in self.log_dir.glob("*.txt"):
            all_threats.extend(self._parse_txt_log(log_file))
            
        # 2. Correlación y Detección de Casos Críticos (Tu caso real)
        for t in all_threats:
            desc = t["desc"].lower()
            
            # 🚨 Alerta de MBR modificado (Bootkit)
            if "modifiedbootrecord" in desc:
                t["severity"] = "Critical"
                t["type"] = "Kernel" # Forzar tipo Kernel para bloquear mitigación en caliente
                t["desc"] = "🚨 [PELIGRO BOOTKIT] " + t["desc"] + " (El disco fue alterado. Mitigación en caliente deshabilitada)"
                
            # 🚨 Alerta de Rootkit / Falsificación de procesos
            if t["type"] == "Kernel" and "padre inesperado" in desc:
                t["severity"] = "Critical"
                t["desc"] = "🚨 [PELIGRO ROOTKIT] " + t["desc"] + " (No mitigar en caliente o habrá Pantallazo Azul)"
                
        return all_threats
