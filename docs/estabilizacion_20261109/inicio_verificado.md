# Arranque y uso local comprobados en Windows 11

Procedimiento verificado en el equipo actual con Python 3.14.6, las 41 versiones del [lock](../../requirements-lock.txt), Streamlit 1.66.0 y el [modelo CSV original](../../models/unsw_nb15_random_forest.joblib). La instalación desde cero en otro equipo sigue pendiente. No es necesario activar el entorno: los comandos usan su intérprete explícito.

## Iniciar

Abrir PowerShell y ejecutar desde la raíz del proyecto. Las rutas predeterminadas de modelos y SQLite son relativas al directorio actual.

```powershell
Set-Location 'C:\Users\Ideapad15-itl6\Desktop\SeguridadInteligentePYMES'
.\.venv\Scripts\python.exe -B -m pip check
.\.venv\Scripts\python.exe -B -m streamlit run app.py --server.address 127.0.0.1 --server.port 8517 --server.headless true --browser.gatherUsageStats false
```

Abrir <http://127.0.0.1:8517>. El puerto debe estar libre; el servidor de las pruebas quedó detenido. El arranque anterior devuelve HTTP 200 en `/_stcore/health`. Detener con Ctrl+C al terminar.

Sin overrides, el historial se guarda en la [base principal](../../data/processed/security_analysis.sqlite3): clasificar o revisar alertas allí modifica ese historial de forma normal. Para probar sin tocarla, abrir otra sesión de PowerShell y definir antes del arranque una ruta **nueva** de prueba:

```powershell
$env:SIPYMES_DATABASE_PATH = "$PWD\docs\estabilizacion_20261109\mi_prueba_local.sqlite3"
```

Esta variable solo afecta los procesos iniciados desde esa sesión. No definir `SIPYMES_MODEL_PATH` para el uso normal: se conserva el selector original. Si el entorno ya contiene overrides, revisarlos antes de iniciar; el modelo original es la opción predeterminada. El override de modelo acepta únicamente artefactos locales confiables: joblib no es seguro para cargar modelos de terceros.

## Analizar y revisar

1. Conservar la opción predeterminada del modelo CSV UNSW-NB15. Su esquema requiere 42 características y utiliza la regla original `predict`. La alternativa preexistente del estudio de umbral también es CSV, con regla conservada `>= 0.65`; no corresponde al Random Forest PCAP.
2. Cargar un CSV UTF-8 de hasta 100 MiB con las columnas requeridas por el artefacto. La interfaz muestra ese esquema. `id` es opcional, pero si se incluye debe identificar filas sin duplicados ni faltantes; `label` y `attack_cat` no se usan como predictores. Valores numéricos deben ser finitos. Archivo vacío, estructura incoherente y datos faltantes se rechazan.
3. Para una comprobación controlada usar [valido.csv](fixtures/valido.csv). Pulsar el botón de análisis. Deben mostrarse ocho registros, cuatro predicciones normales, cuatro sospechosas y cuatro alertas. Son resultados de software reproducibles, no ocho observaciones con etiquetas verdaderas.
4. Contrastar tabla, gráfico y conteos; descargar predicciones CSV y reporte JSON. El JSON declara `alerts_total`, `alerts_returned`, `alerts_limit` y `alerts_truncated`. Si hay más de 10.000 alertas, la lista de alertas es parcial y se avisa; los resultados por registro conservan las predicciones de ese análisis.
5. En el historial, filtrar y seleccionar una alerta. Guardar revisión pendiente, confirmada o falso positivo. La revisión cambia su estado manual y conserva la clase/puntuación emitida. Reiniciar el servidor conserva el historial SQLite; la tabla de resultados del análisis actual pertenece a la sesión de Streamlit.

El historial consulta como máximo las 100 ejecuciones y 10.000 alertas más recientes. Sus filtros y exportaciones operan sobre esa ventana, según el aviso visible. Las predicciones sospechosas no son confirmación de un ataque. No se validó acceso remoto ni uso multiusuario: mantener la escucha local comprobada.

Si falta el modelo, hay una ruta incorrecta, SQLite está dañada o el CSV es inválido, atender el mensaje mostrado. No regenerar ni reentrenar artefactos para resolver un error de arranque. Las bases originales no deben reemplazarse por las bases negativas usadas en las pruebas.

## Repetir las verificaciones

Desde la raíz, sin overrides de administrador que alteren el entorno de las pruebas:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B docs/estabilizacion_20261109/integrales.py integral_run_002
.\.venv\Scripts\python.exe -B docs/estabilizacion_20261109/verificar_cierre.py
```

La suite final registrada es 235/235. El [harness integral](integrales.py) exige un nombre de salida nuevo: cambiar `integral_run_002` si ya existe; no sobrescribe evidencias y usa SQLite aisladas. Ejecuta 20 casos con los modelos existentes y fixtures controlados; AppTest sustituye solo transporte de subida y widgets de descarga, no inferencia ni persistencia. Las comprobaciones del navegador real se conservan en la [matriz](matriz_pruebas.csv) y sus evidencias; no se automatizan con estos tres comandos. El [verificador de cierre](verificar_cierre.py) espera que las tres bases originales no hayan recibido nuevas operaciones desde el cierre, por lo que debe ejecutarse antes de usarlas normalmente o con la aplicación configurada para otra base.

## Extracción PCAP offline existente

Requiere TShark instalado; en el equipo se verificó 4.6.9. No requiere Npcap para leer archivos ni permisos de captura. Se comprobó el CLI con esta captura sintética ya disponible:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.pcap_extract docs/estabilizacion_20261109/integral_run_001/controlled.pcap --output docs/estabilizacion_20261109/extraccion_controlada_nueva.json
```

La salida debe ser nueva y su directorio debe existir. Deben resultar dos paquetes y un flujo bidireccional UDP con 38 características. Puede repetirse con el [PCAPNG sintético](integral_run_001/controlled.pcapng) y otro nombre de salida. El extractor rechaza sobreescrituras y fallos; no aumentar sus límites ni timeouts. La extracción no clasifica ataques, no crea alertas y no se conecta al modelo CSV ni a Streamlit. No utilizar estos comandos para capturar interfaces ni procesar nuevas adquisiciones fuera del alcance autorizado.

Los resultados completos, restricciones y pendientes de portabilidad/recursos/distribución constan en el [informe técnico](informe_estabilizacion.md).
