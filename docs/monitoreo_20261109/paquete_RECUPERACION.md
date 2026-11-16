# Respaldo y recuperación

Detener monitoreo con su botón y esperar el estado detenido. Cerrar Streamlit con Ctrl+C antes de realizar una copia operativa completa. No eliminar una base o captura dañada para ocultar el incidente.

Las bases son independientes:

- Monitoreo por reglas: `data/monitoring/history.sqlite3`; sus PCAPNG y configuraciones están en `data/monitoring/sessions/`.
- Análisis CSV: `data/processed/security_analysis.sqlite3`.

Desde la carpeta del paquete, crear una carpeta de respaldos locales si todavía no existe y elegir nombres nuevos:

```powershell
New-Item -ItemType Directory -Path respaldos_locales
.\.venv\Scripts\python.exe -B herramientas/sqlite_respaldo.py backup data/monitoring/history.sqlite3 respaldos_locales/monitoreo-01.sqlite3
.\.venv\Scripts\python.exe -B herramientas/sqlite_respaldo.py backup data/processed/security_analysis.sqlite3 respaldos_locales/csv-01.sqlite3
```

Respaldar solamente las bases que ya existan. La herramienta abre el origen en lectura, comprueba `integrity_check`, usa la API de backup SQLite, verifica la copia y muestra su SHA-256. Rechaza destinos existentes. Después de detener captura, copiar también las carpetas de sesiones a una ubicación protegida si se necesita conservar la evidencia PCAPNG; no compartirlas como parte del paquete limpio.

Para probar una recuperación de monitoreo sin sobrescribir el historial anterior, crear otro directorio vacío:

```powershell
New-Item -ItemType Directory -Path recuperacion_monitoreo
.\.venv\Scripts\python.exe -B herramientas/sqlite_respaldo.py restore respaldos_locales/monitoreo-01.sqlite3 recuperacion_monitoreo/history.sqlite3
$env:SIPYMES_MONITOR_DIR = 'recuperacion_monitoreo'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

Consultar sesiones y revisiones. Si se copiaron capturas, conservar su relación con la sesión; la ruta de captura almacenada es evidencia del origen y no se reescribe automáticamente al trasladarla. Una recuperación de SQLite permite consultar alertas aun sin trasladar el PCAPNG. El backup no recupera datos posteriores a su fecha.

Para CSV, restaurar a un archivo nuevo y definir `SIPYMES_DATABASE_PATH` con esa ruta. Para volver a las rutas predeterminadas, iniciar desde una PowerShell nueva sin overrides heredados. Nunca restaurar sobre las bases de investigación originales.

| Problema | Acción |
|---|---|
| TShark/Npcap ausente o sin permiso | Revisar instalación oficial y permisos de captura de Npcap. La aplicación no instala drivers ni eleva automáticamente; no basta instalar paquetes pip. |
| Interfaz desconectada o sin tráfico | Revisar conexión, selección y alcance IPv4 TCP/UDP. Actualizar la lista; ausencia de paquetes no equivale a red segura. Una interfaz retirada provoca un error controlado y cierre. |
| Límite de memoria, cola o almacenamiento | Detener y conservar sesión parcial/errores. Respaldar historial/capturas y decidir expresamente cómo liberar espacio; no se elimina automáticamente. No interpretar registros incompletos como cobertura total. |
| Cierre abrupto | En Windows, el Job Object termina TShark/dumpcap al desaparecer su dueño. Al iniciar otra captura, las sesiones de dueños muertos se marcan interrumpidas. El PCAPNG puede ser incompleto; se conservan los checkpoints previos y no se inventan paquetes. |
| SQLite dañada o ruta sin permisos | Conservar los archivos y cualquier journal/WAL. Restaurar un backup íntegro a otro directorio escribible y comprobar historial antes de seguir. |
| Modelo o hash diferente | No cargarlo ni editar el manifiesto para aceptarlo. Recuperar el modelo CSV original desde una copia confiable de la distribución. |
| Error de instalación Python | Usar un entorno nuevo, los requisitos exactos y `pip check`; no mezclar paquetes de otros entornos ni desactivar TLS. |

Las comprobaciones de hashes no autentican al proveedor. La captura en vivo se verificó con loopback local; permisos y visibilidad de una NIC física requieren comprobación autorizada en ese entorno.
