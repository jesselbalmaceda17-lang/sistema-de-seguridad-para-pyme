# Respaldo y recuperación de SQLite

Los comandos se ejecutan desde la carpeta de esta entrega, con el entorno instalado. Sustituir rutas si se usa `SIPYMES_DATABASE_PATH`. No aplicar estos comandos a las bases del proyecto de investigación.

## Respaldar

Detener Streamlit con Ctrl+C. Crear una carpeta de respaldos locales fuera de los archivos que se compartirán y elegir un nombre nuevo:

```powershell
New-Item -ItemType Directory -Path .\respaldos_locales
.\.venv\Scripts\python.exe -B herramientas/sqlite_respaldo.py backup data/processed/security_analysis.sqlite3 respaldos_locales/historial-01.sqlite3
Get-FileHash -Algorithm SHA256 -LiteralPath .\respaldos_locales\historial-01.sqlite3
```

Si la carpeta existe, no repetir `New-Item`; usar otro nombre de archivo para cada respaldo. La herramienta abre el origen en lectura, ejecuta `integrity_check`, utiliza la API de backup de SQLite y verifica la copia. Imprime su SHA-256 y rechaza destinos existentes. No copiar solamente el archivo principal mientras la aplicación escribe, pues SQLite puede mantener un journal o WAL. Guardar el respaldo y su hash en un lugar confiable con los permisos adecuados para el historial.

## Probar la recuperación sin reemplazar el historial

```powershell
.\.venv\Scripts\python.exe -B herramientas/sqlite_respaldo.py restore respaldos_locales/historial-01.sqlite3 data/processed/historial-restaurado.sqlite3
$env:SIPYMES_DATABASE_PATH = 'data/processed/historial-restaurado.sqlite3'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

El destino debe ser nuevo. Consultar en la interfaz los análisis y revisiones esperados; detener el servidor al terminar. Este procedimiento deja intacto el archivo anterior. Para seguir usando la restauración, conservar el override en la sesión de inicio. Para volver a la predeterminada, iniciar desde una sesión nueva sin ese override. No borrar ni sobrescribir una base dañada antes de preservar evidencia y disponer de una restauración verificada.

## Fallos frecuentes

| Síntoma | Comprobación y recuperación |
|---|---|
| Python o módulo ausente | Revisar la ruta del intérprete; ejecutar `pip check` con el Python de este entorno. Si el entorno está incompleto, crear otro entorno nuevo e instalar los mismos requisitos. No mezclar paquetes del entorno de desarrollo. |
| Instalación sin red o certificado rechazado | Se requiere HTTPS a PyPI y su servidor de archivos para obtener las versiones fijadas. Conservar el log, revisar conectividad/certificados con el administrador y reintentar en un entorno nuevo. No usar `--trusted-host` ni desactivar TLS. No se entrega un instalador offline. |
| Hash o modelo diferente | Detener el arranque y recuperar los archivos de una copia confiable de esta entrega. No editar el manifiesto para aceptar un artefacto desconocido ni cargar modelos de terceros. |
| Error SQLite o permisos | Detener el servidor, conservar la base y cualquier journal/WAL. Verificar directorio escribible y override. Si existe un respaldo íntegro, restaurar a un destino nuevo y comprobar historial. No declarar recuperados datos posteriores al respaldo. |
| Puerto ocupado | Usar otro puerto local, por ejemplo `iniciar.ps1 -Port 8527`; no finalizar procesos ajenos. |
| CSV rechazado | Corregir estructura, codificación, 42 columnas, identificadores y datos finitos según el mensaje. No editar el modelo ni convertir el rechazo en predicción. |
| Lote lento o consumo excesivo | Interrumpir con Ctrl+C, conservar evidencia y reiniciar. Verificar historial antes de repetir: una interrupción no garantiza que no se haya persistido una ejecución. Usar un lote más pequeño; no se cambia el límite interno ni el modelo. |

La herramienta de copia verifica integridad SQLite; no garantiza que el contenido del respaldo represente el momento deseado ni recupera datos ausentes de él. El procedimiento de restauración fue probado con historial sintético, incluidos estado manual y predicción original.
