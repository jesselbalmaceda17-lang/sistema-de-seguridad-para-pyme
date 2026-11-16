# Cierre técnico del monitoreo — 2026-11-09

## ESTADO FINAL

**APROBADO para el alcance local comprobado.** Se terminó la verificación de la última versión y su ZIP, sin cambios nuevos en el código de aplicación, reentrenamiento de modelos existentes ni respaldo masivo nuevo. La única diferencia frente al respaldo anterior al monitoreo es la integración del panel que ya estaba implementada. La entrega CSV anterior se conserva íntegra.

## PRUEBAS APROBADAS

| Tipo | Resultado y evidencia |
|---|---|
| Simulaciones de monitoreo | **38/38** después de los últimos cambios: [resultado](cierre_001/monitoreo.json), [log](cierre_001/monitoreo.log). Transporte simulado, reglas, límites, errores, SQLite y AppTest. |
| Suite completa | **273/273**, incluidas las 38 anteriores: [resultado](cierre_001/suite_completa.json), [log](cierre_001/suite_completa.log). Las pruebas de entrenamiento generan únicamente fixtures y modelos temporales de prueba; los modelos del proyecto no se reentrenaron. |
| Archivos CSV y modelo real | **7/7** desde copia independiente: [aceptación](cierre_001/csv_independiente/resultados.json). Ocho predicciones y cuatro alertas, scores iguales al oráculo original, exportaciones, revisión, rechazo de entradas inválidas y recuperación. AppTest simula el transporte de carga/descarga. |
| **En vivo desde Streamlit** | Botones reales de inicio/detención, interfaz loopback, TShark/Npcap reales y generador de servicios propios: **8.103 paquetes, 14 conexiones, 45 segmentos, 4 alertas de las tres reglas**. Incluye tráfico local de fondo, además de los 13 flujos del generador. Falso positivo guardado desde la interfaz. Sesión y contadores persistidos coinciden en `stopped`, sin cierre forzado ni parcialidad. [Resultado](cierre_001/streamlit_en_vivo.json), [interfaz](cierre_001/streamlit_final.txt), [PCAPNG](cierre_001/browser_evidencias/capture.pcapng), [SQLite aislada](cierre_001/browser_evidencias/history.sqlite3). |
| PCAP por archivo | CLI independiente sobre el PCAP Ethernet sintético: **2 paquetes, 1 flujo, 38 características**. [Extracción](cierre_001/browser_evidencias/extraccion_sintetica.json). No se confunde con captura en vivo. |
| Evidencia previa reutilizada | [Integración existente](integracion_003/resultados.json): 142 paquetes/13 conexiones/3 alertas, replay de las mismas características, reinicio por duración y cierre abrupto con limpieza de hijos. Se volvió a verificar el hash del PCAP. Estas pruebas previas no se presentan como ejecutadas otra vez. |
| Integridad | [Auditoría](cierre_001/integridad.json): **2.521 archivos sin alteraciones y ninguno ausente** de 2.522 registrados; diferencia esperada: integración del panel. Incluye 5 archivos de modelos y 228 de experimentos PCAP. Las 3 bases originales mantienen sus hashes y su integridad SQLite. Respaldo existente: SHA-256 y CRC válidos; restauración anterior de 778 archivos reutilizada. Modelos y bases originales comprobados otra vez al cerrar el ZIP. |
| Paquete independiente | [ZIP final](cierre_001/zip_final.json): **35 archivos del manifiesto + manifiesto**, CRC válido, extracción idéntica byte a byte fuera de desarrollo, ruta con espacios, launcher HTTP 200 y CSV original 8/4 otra vez. Módulos idénticos a los probados en vivo. Se reutilizó el entorno limpio y se verificaron sus 41 versiones y `pip check`; no se repitieron descargas. |

El servidor anterior ya no existía; su PID 10564 pertenecía a Chrome y se dejó intacto. Los dos servidores propios de esta verificación se cerraron verificando identidad y descendencia. **No quedan procesos TShark/dumpcap de las pruebas.** El PCAP actual contiene solo loopback y excluye el puerto de control 8531.

## DEFECTOS PENDIENTES

**Ningún defecto reproducible pendiente dentro del alcance probado.** Sigue sin verificarse: otro equipo físico e instalación nueva de Npcap en él, NIC Wi-Fi/Ethernet y red de una PYME, carga sostenida, eficacia de detección en producción y transporte HTTP real de carga/descarga CSV. IPv6, VLAN y fragmentación quedan fuera del alcance implementado. Cierre abrupto: evidencia previa reutilizada; límites y errores: principalmente simulaciones. Las reglas transparentes no son inteligencia artificial ni confirman ataques.

## UBICACIÓN DEL ZIP

[SeguridadInteligentePYMES-monitoreo-20261109.zip](../../dist/SeguridadInteligentePYMES-monitoreo-20261109.zip)

Ruta exacta: `C:\Users\Ideapad15-itl6\Desktop\SeguridadInteligentePYMES\dist\SeguridadInteligentePYMES-monitoreo-20261109.zip`

Tamaño: **8.048.846 bytes**. SHA-256: `e83267ecf1d6bd43f0bdafd77b27c4cfdcbd434e20d254aefc7fb564f2e33259`. [Archivo SHA-256](../../dist/SeguridadInteligentePYMES-monitoreo-20261109.zip.sha256).

El ZIP limpio contiene requisitos, instrucciones de instalación y configuración de TShark/Npcap, guía de demostración, recuperación y verificación. No incluye historiales ni capturas reales de prueba. El modelo CSV original conserva SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`.

## CÓMO DEMOSTRARLO

Extraer el ZIP. Abrir PowerShell dentro de la carpeta extraída. Instalar Python 3.14 x64, TShark y Npcap si faltan; detalles en el [README del paquete](../../dist/SeguridadInteligentePYMES-monitoreo-20261109/README.md).

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip --isolated install --no-cache-dir -r requirements-lock.txt -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -B herramientas/verificar_paquete.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

Abrir <http://127.0.0.1:8501>. Seleccionar **Adapter for loopback traffic capture**, confirmar autorización y configurar **SYN=5, puertos=4, volumen=1 KiB**. Iniciar monitoreo. En otra PowerShell, desde la misma carpeta:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.monitor_demo
```

Comprobar paquetes/conexiones, las tres reglas y su evidencia. Guardar una revisión manual, pulsar **Detener monitoreo** y esperar **Monitoreo detenido**. Para demostrar el CSV original, cargar el [CSV sintético incluido](../../dist/SeguridadInteligentePYMES-monitoreo-20261109/demo/demostracion_sintetica.csv): se esperan 8 registros y 4 alertas. Las comunicaciones de demostración son benignas y solo usan servicios locales propios.
