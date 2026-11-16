# Arquitectura implementada

## Módulos y responsabilidades

| Módulo | Responsabilidad actual |
| --- | --- |
| `seguridad_pymes.ingestion` | Leer CSV, validar encabezados, etiqueta, faltantes, duplicados y tipos, y preparar los datos de UNSW-NB15. |
| `seguridad_pymes.preprocessing` | Funciones de preparación reutilizables para columnas y esquema. |
| `seguridad_pymes.training` | Entrenar el Pipeline Random Forest y guardar el artefacto y sus metadatos. |
| `seguridad_pymes.evaluation` | Evaluar el artefacto guardado en el split de prueba reservado, sin ajuste; guardar métricas y gráficos. |
| `seguridad_pymes.inference` | Aplicar una política de modelo seleccionada a un lote y persistir ejecuciones y alertas. |
| `seguridad_pymes.alerts` | Helpers del ciclo de alertas y su revisión manual. |
| `seguridad_pymes.detection` | Componentes de coordinación auxiliares; no implementa captura o monitoreo de red. |
| `seguridad_pymes.database` | Migrar aditivamente y consultar ejecuciones/alertas en SQLite. |
| `seguridad_pymes.resources` | Medir duración y RSS de operaciones. |
| `seguridad_pymes.dashboard` | Validar carga CSV, ejecutar análisis por lotes, mostrar resultados, historial y revisión de alertas, y descargar reportes. |
| `app.py` | Punto de entrada Streamlit. |

## Dirección de dependencias

El flujo de datos implementado es:

`ingestion` → `preprocessing` → `training` → `evaluation`

`ingestion` → `preprocessing` → `inference` → `database` → `dashboard`

`resources` mide operaciones invocadas por los componentes de análisis.
`detection` no introduce captura de tráfico ni una ruta paralela de inferencia.
El punto de entrada `app.py` delega en el panel.

`ingestion` inspecciona los encabezados de los archivos en ejecución; los
predictores se derivan de las columnas presentes, excluyendo `label`, `id` y
`attack_cat` (si aparecen). Los CSV de entrenamiento y prueba deben compartir
encabezado y orden. Se eliminan registros con duplicados exactos, valores
faltantes, etiquetas distintas de 0/1 o valores no numéricos en columnas
numéricas identificadas a partir de entrenamiento. Cada causa se contabiliza
por partición. Valores categóricos nuevos en prueba se registran, pero no se
descartan.

`prepare_unsw_nb15` prepara el `Pipeline` que contiene un `ColumnTransformer`
exclusivamente con `X_train`; `X_test` solo recibe `transform`. Los archivos
locales del conjunto UNSW-NB15 existen en este espacio de trabajo, pero están
excluidos por `.gitignore`; un checkout limpio no los contiene automáticamente.
La lista real de columnas se valida al cargar los archivos.

El módulo `training` utiliza exclusivamente `load_unsw_training`; no abre el
archivo oficial de prueba. La selección usa cuatro combinaciones muestreadas de
una cuadrícula pequeña y `StratifiedKFold` con tres folds por defecto, barajado y
semilla fija 42, maximizando F1 para la etiqueta de ataque `1`. Búsqueda y
clasificador se ejecutan con `n_jobs=1` para limitar la presión de memoria. El
Pipeline completo (preprocesamiento ajustado y Random Forest) se serializa con
joblib; el archivo JSON contiguo registra versiones, parámetros, hash SHA-256
del CSV de entrenamiento, nombres de características, conteos y el F1 de CV
calculado durante la ejecución. El artefacto definitivo existente registra el
perfil `final-fixed`: se ajustó con 175 341 filas válidas del entrenamiento
oficial y parámetros seleccionados previamente con validación cruzada sobre
una muestra piloto estratificada de ese mismo split. Los resultados del
artefacto se informan desde el reporte de evaluación guardado, no se vuelven a
calcular aquí.

`evaluation` carga el Pipeline entrenado y toma del preprocesador guardado las
características y columnas numéricas esperadas. Lee únicamente el CSV de prueba,
descarta inválidos con conteos explícitos y no ejecuta `fit` ni `fit_transform`.
Calcula matriz de confusión en orden de clases `[0, 1]`, precision, recall y F1
para ataque (1), tasa de falsos positivos `FP/(FP+TN)` y tiempo medido para una
llamada de `predict` sobre el lote retenido. Guarda métricas/metodología/calidad
en JSON, la matriz en CSV y gráficos SVG sin requerir bibliotecas adicionales.
Los resultados corresponden al benchmark y no prueban generalización a redes
PYME; el tiempo medido no es latencia en tiempo real.

`inference.run_model_analysis` recibe predictores y sus IDs por separado,
carga el Pipeline seleccionado y persiste una ejecución. Solo las predicciones
de clase 1 se insertan en `alerts`; si está disponible, se guarda el score de
clase 1 de `predict_proba`, que no necesariamente es una probabilidad calibrada.
SQLite relaciona las alertas con la ejecución mediante clave foránea y valida
clase, score, estado de revisión y unicidad de ID por ejecución. Las consultas
de valores son parametrizadas. Errores de inferencia se propagan.

El panel permite elegir entre `production_random_forest`, que conserva
exactamente `Pipeline.predict`, y `threshold_study_random_forest`, que usa
exclusivamente el artefacto de estudio y clasifica como clase 1 cuando el score
de `predict_proba` para clase 1 es >= 0.65. Antes de ofrecer ambas opciones se
validan sus 42 características de entrada, su orden y la separación
numérica/categórica; un artefacto inválido no provoca fallback silencioso. El
modelo definitivo queda seleccionado por defecto. Un `SIPYMES_MODEL_PATH`
explícito tiene precedencia: si apunta a uno de esos artefactos se aplica su
política correspondiente; si apunta a otro, se conserva `predict` como modelo
personalizado y el selector se desactiva.

`analysis_runs` guarda además `model_id`, `decision_rule`,
`decision_threshold` y `model_sha256`, sin sustituir `model_reference`. Una
migración aditiva agrega las columnas faltantes; los datos históricos mantienen
NULL en la metadata que no puede inferirse. Las métricas del estudio experimental
se originan en su partición de validación, donde también se eligió 0.65; no se
atribuyen al modelo definitivo ni constituyen una evaluación independiente o
una afirmación de mejor rendimiento general.
La base predeterminada, `data/processed/security_analysis.sqlite3`, se crea de
forma no destructiva mediante `initialize_database`; `list_analysis_runs` y
`list_alerts` permiten consultar ejecuciones y alertas, y
`update_alert_review_state` modifica el estado de revisión entre `pending`,
`confirmed` y `false_positive`. `confirmed` es una revisión manual; no modifica
la predicción del modelo ni prueba que el registro corresponda a un ataque real.
Al inicializar, las bases anteriores migran `confirmed_attack` a `confirmed`
sin recrear las alertas.

El panel `dashboard` verifica que exista y pueda cargarse el Pipeline, acepta
solo CSV con esquema compatible y pasa los IDs de fila por separado de los
predictores. Muestra conteos y gráficos calculados de los resultados, historial y
alertas leídos de SQLite, descarga de reportes y la sección «Gestión de alertas»
para consultar y actualizar su estado. Un archivo cargado es un análisis por
lotes; no existe captura ni monitoreo continuo de red.
La base y el modelo pueden configurarse para el punto de entrada con las
variables `SIPYMES_DATABASE_PATH` y `SIPYMES_MODEL_PATH`.

`list_alerts` une `alerts` con `analysis_runs` mediante `LEFT JOIN` para exponer
por alerta la fuente, el modelo, la regla, el umbral y datos de ejecución sin
añadir columnas a SQLite ni perder alertas antiguas con metadata nula. La
interfaz ofrece filtros de modelo, ejecución y estado, búsqueda por ID de
registro, exportación de las alertas visibles y un detalle de la selección. Los
scores se presentan como «Score del modelo (clase 1)», no como probabilidades
necesariamente calibradas. `detected_at` se describe como momento de registro
SQLite, no necesariamente como hora del evento de red. La vista aclara que
«confirmed» es revisión manual y que no hay explicabilidad que permita afirmar
la causa de una predicción. En el reporte principal, el nombre interno
`probabilidad_ataque` se conserva para compatibilidad con consumidores Python;
la tabla visible y las exportaciones CSV/JSON usan el encabezado
«Score del modelo (clase 1)», acompañado en la interfaz por la aclaración de que
no es necesariamente una probabilidad calibrada ni confirma un ataque.

El historial del dashboard consulta hasta 100 ejecuciones y 10 000 alertas más
recientes; los filtros de alertas se aplican a ese subconjunto y la interfaz lo
advierte para que «Todas» no se interprete como una consulta ilimitada. Para
ejecuciones `failed`, `error_message` se conserva en SQLite y se presenta solo
como una descripción segura basada en una lista permitida de tipos de error.
Las exportaciones del historial reemplazan el mensaje interno por ese resumen y
no revelan trazas, rutas ni detalles crudos. Los registros históricos sin error
asociado muestran una descripción genérica.

`resources.measure_operation` mide una operación con `perf_counter` y RSS
muestreado periódicamente por `psutil`; `benchmark_inference` mide tamaños
configurables sobre un CSV compatible y no entrena ni calcula eficacia. Las
pruebas ejercitan tamaños temporales 1, 2 y 4 como verificación instrumental,
sin representatividad de tráfico real. Para un benchmark del modelo científico
se requieren el artefacto y los CSV oficiales.

## Controles metodológicos

- Separar entrenamiento y prueba antes de ajustar transformaciones o modelos;
  ajustar cualquier transformación únicamente con los datos de entrenamiento.
- Mantener la etiqueta como objetivo y excluirla de las características.
- Revisar el esquema y la documentación de UNSW-NB15 para excluir identificadores
  y campos que permitan fuga de información antes de definir predictores.
- Informar precisión, recall, F1-score, matriz de confusión y tasa de falsos
  positivos sobre datos de prueba no usados durante el entrenamiento.
- Identificar los análisis CSV como procesamiento por lotes, no como captura ni
  monitoreo de red en tiempo real.

En el espacio de trabajo existe un reporte oficial del modelo definitivo en
`data/processed/evaluation/metrics.json`. Registra 82 332 filas retenidas,
matriz de confusión `[[26415, 10585], [465, 44867]]`, precision 0.809114,
recall 0.989742, F1 0.890360 y FPR 0.286081. El JSON registra los hashes del
modelo, sus metadatos y el archivo de prueba; estos resultados describen
únicamente el benchmark UNSW-NB15 y no validan desempeño en PYMES reales.

El reporte del estudio de umbral corresponde a un Pipeline experimental
distinto, ajustado con el 80 % de una partición estratificada del conjunto de
entrenamiento. El umbral 0.65 fue seleccionado y medido sobre el 20 % restante:
TN 10 666, FP 534, FN 1 153, TP 22 716, precision 0.977032, recall 0.951695,
F1 0.964197 y FPR 0.047679. Al ser la misma partición para selección y medición,
no es una estimación independiente posterior a la selección y no debe
atribuirse al modelo definitivo ni usarse para afirmar mejor rendimiento
general.

Los archivos de datos, modelos y reportes están excluidos por `.gitignore`; su
presencia en el espacio de trabajo no significa que estén en una entrega limpia
o que los datos oficiales puedan redistribuirse. `requirements.txt` conserva
las seis dependencias directas y `requirements-lock.txt` fija las 41
distribuciones de aplicación observadas en `.venv` de Windows/Python 3.14.6
(seis directas y 35 transitivas/runtime). El lock se validó sintácticamente y
contra el entorno actual, pero no contiene hashes y no se probó en una
instalación limpia. No se detectó repositorio Git, por lo que todavía no existe
commit/tag que identifique la entrega.

Las pruebas unitarias verifican el comportamiento del software con fixtures
temporales, no la eficacia de los modelos ni resultados empresariales.
