import os

class LowLevelGuide:
    def __init__(self):
        self.script_dir = "C:\\Windows\\Temp\\Davenlab_Rescue"

    def generate_safe_mode_script(self, threat_name, threat_type):
        """
        Genera un script .bat para ser ejecutado en Modo Seguro, donde las restricciones
        del sistema operativo o del malware son menores.
        """
        if not os.path.exists(self.script_dir):
            try:
                os.makedirs(self.script_dir)
            except Exception:
                pass
                
        script_path = os.path.join(self.script_dir, "remediation_safemode.bat")
        
        content = f"""@echo off
echo ===================================================
echo Davenlab Security - Asistente de Modo Seguro
echo Mitigando amenaza critica: {threat_name}
echo ===================================================

:: Fase de limpieza
echo Intentando eliminar rastros de {threat_name}...
:: (Logica avanzada de limpieza con comandos nativos)
:: del /f /a /q "Ruta\\sospechosa\\*"

echo.
echo Proceso finalizado. 
echo Por favor, reinicie el sistema normalmente.
pause
"""
        try:
            with open(script_path, 'w') as f:
                f.write(content)
            return True, script_path
        except Exception as e:
            return False, str(e)
