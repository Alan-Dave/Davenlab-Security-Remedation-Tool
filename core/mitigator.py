import subprocess
import logging
import os

logging.basicConfig(level=logging.INFO)

class Mitigator:
    def __init__(self):
        # Lista blanca y protección de procesos del sistema para evitar BSOD (Loop de Auditoría)
        self.critical_procs = ["wininit.exe", "csrss.exe", "smss.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"]

    def mitigate_process(self, process_name):
        """Termina un proceso malicioso, asegurando que no sea del sistema."""
        if process_name.lower() in self.critical_procs:
            return False, f"[SEGURIDAD] Intento bloqueado: No se puede terminar el proceso crítico '{process_name}' en caliente."
            
        try:
            # check=True y captura de stdout/stderr para control de errores (Loop de Auditoría)
            result = subprocess.run(
                ["taskkill", "/F", "/IM", process_name], 
                capture_output=True, text=True, check=True
            )
            logging.info(f"Proceso {process_name} terminado exitosamente.")
            return True, "Proceso terminado exitosamente."
        except subprocess.CalledProcessError as e:
            logging.error(f"Error al terminar {process_name}: {e.stderr}")
            return False, f"Fallo al terminar: {e.stderr.strip() or 'Acceso Denegado'}"
        except Exception as e:
            return False, f"Error inesperado: {str(e)}"

    def mitigate_task(self, task_name):
        """Elimina una tarea programada maliciosa."""
        try:
            result = subprocess.run(
                ["schtasks", "/Delete", "/TN", task_name, "/F"], 
                capture_output=True, text=True, check=True
            )
            return True, "Tarea eliminada exitosamente."
        except subprocess.CalledProcessError as e:
            return False, f"Fallo al eliminar tarea: {e.stderr.strip()}"

    def mitigate_file(self, file_path):
        """Elimina un archivo malicioso, verificando que exista y tengamos permisos."""
        if not os.path.exists(file_path):
            return False, "El archivo ya no existe."
            
        try:
            os.remove(file_path)
            return True, "Archivo eliminado."
        except PermissionError:
            return False, "Permiso denegado al eliminar el archivo. Puede estar en uso."
        except Exception as e:
            return False, f"Error al eliminar: {str(e)}"
