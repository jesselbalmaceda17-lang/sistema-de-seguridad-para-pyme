# Seguridad Inteligente PYMES — entrega técnica CSV

Aplicación local para clasificar lotes CSV con el modelo UNSW-NB15 original, generar alertas del modelo, revisarlas manualmente y conservar historial SQLite. No realiza captura en vivo ni incorpora el detector PCAP experimental. Las predicciones sospechosas requieren revisión: no confirman incidentes ni demuestran precisión en una red real.

## Requisitos e instalación

Windows 11 de 64 bits; Python 3.14 de 64 bits (verificado con 3.14.6). Se necesitan permisos de escritura en la carpeta de trabajo y conexión HTTPS a PyPI y su servidor de archivos durante la instalación. No se incluyen Python, wheels ni el entorno virtual. El entorno base debe ofrecer `venv` y `pip`; no se requiere Wireshark, TShark ni Npcap para esta entrega CSV.

Copiar toda esta carpeta a una ubicación escribible, abrir PowerShell en ella y ejecutar:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip --isolated install --no-cache-dir --disable-pip-version-check -r requirements-lock.txt -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -B herramientas/verificar_paquete.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

Si no está instalado el lanzador `py`, sustituir solamente el primer comando por la ruta de un Python 3.14 de 64 bits: `& 'ruta\python.exe' -m venv .venv`. No se necesita activar el entorno ni cambiar permanentemente la política de ejecución. La opción `Bypass` del ejemplo solo afecta ese proceso local de PowerShell; una política corporativa puede impedir scripts. En tal caso, ejecutar directamente:

```powershell
$env:SIPYMES_MODEL_PATH = 'models/unsw_nb15_random_forest.joblib'
.\.venv\Scripts\python.exe -B -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

Abrir <http://127.0.0.1:8501>. Mantener la escucha local. Si el puerto está ocupado, iniciar con `iniciar.ps1 -Port 8527` y usar esa dirección. El script cambia temporalmente a su propia carpeta y permite un entorno externo mediante `-PythonPath 'ruta\Scripts\python.exe'`. No contiene rutas del equipo de desarrollo.

Las 41 versiones fijadas proceden de los requisitos existentes. Los hashes del [manifiesto](manifest.sha256.json) comprueban los archivos entregados; no autentican por sí solos a su editor. El lock existente no fija hashes de wheels. No rebajar versiones ni sustituir modelos para resolver fallos de instalación: conservar el log y consultar las [instrucciones de recuperación](RECUPERACION.md).

## Demostración y uso

1. Cargar [demostracion_sintetica.csv](demo/demostracion_sintetica.csv) y ejecutar el análisis. Se esperan ocho registros, cuatro normales, cuatro sospechosos y cuatro alertas. Clases y puntuaciones exactas están en [resultados_esperados.json](demo/resultados_esperados.json).
2. Revisar tabla, gráfico y alertas; descargar resultados CSV y reporte JSON. El fixture es sintético y sus predicciones esperadas son un oráculo de consistencia de software, no etiquetas verdaderas de ataques.
3. En el historial seleccionar una alerta, guardar revisión pendiente, confirmada o falso positivo. Reiniciar con Ctrl+C y el mismo comando: las ejecuciones y revisiones persistidas deben conservarse. El resultado actual en pantalla pertenece a la sesión; el historial pertenece a SQLite.

El CSV debe ser UTF-8, contener las 42 características del modelo, números finitos y no tener campos requeridos vacíos. `id` es opcional, pero si aparece debe ser único y no vacío. `label` y `attack_cat` no son predictores. Los mensajes de validación explican rechazos; no deben interpretarse como análisis completados.

La aplicación acepta como máximo 100 MiB de entrada. Ese tope de validación no garantiza memoria o tiempo aceptables para cualquier archivo. El historial muestra hasta 100 ejecuciones y 10.000 alertas recientes. Los filtros y las descargas históricas operan sobre esa ventana. En el reporte JSON del análisis actual, `alerts_total`, `alerts_returned`, `alerts_limit` y `alerts_truncated` declaran la cobertura de la lista de alertas; los resultados por registro conservan todas las predicciones del lote.

## Persistencia y recuperación

La base se crea nueva en `data/processed/security_analysis.sqlite3` al iniciar; no se entrega ninguna base histórica. Usar [RECUPERACION.md](RECUPERACION.md) para respaldar y restaurar a un destino nuevo. Antes del arranque, comprobar si existe `SIPYMES_DATABASE_PATH`: un valor heredado dirige el historial a otra base. Para usar la predeterminada, abrir una sesión nueva sin ese override. No compartir la misma base entre distintas copias en pruebas sin intención explícita.

## Artefactos y límites

El único modelo distribuido es [el original CSV](models/unsw_nb15_random_forest.joblib), SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. **Joblib puede ejecutar código al cargar: usar exclusivamente modelos de procedencia confiable.** El arranque fija ese artefacto mediante la configuración preexistente; no distribuye el estudio opcional de umbral CSV ni modelos PCAP. La regla del original sigue siendo `predict`.

Los módulos de entrenamiento e ingestión se conservan porque el cargador existente los importa. No se distribuyen datasets ni instrucciones para entrenar. No ejecutar sus CLI de entrenamiento para operar la aplicación. El paquete no depende del proyecto de investigación, de sus resultados ni de sus bases de datos.

No hay autenticación, soporte demostrado de múltiples usuarios ni prueba en otro equipo físico. Las dependencias no incluyen un análisis de vulnerabilidades. Los resultados comprobados y las mediciones, con sus límites, se registran en [VERIFICACION.md](VERIFICACION.md). Para detalles de versiones observar [VERSIONES.json](VERSIONES.json), [requirements.txt](requirements.txt) y [requirements-lock.txt](requirements-lock.txt).
