# Seguridad Inteligente PYMES

Prototipo académico para clasificar registros de tráfico como normal o ataque y
facilitar su revisión. La investigación se orienta a PYMES de Chichigalpa,
Chinandega y Somotillo, Nicaragua, durante 2027. No se afirma que el sistema haya
sido probado en empresas.

## Reconocimiento de contribuciones

- [isaias-2025](https://github.com/isaias-2025) aportó la sección «Detalle de
  la alerta» del panel, que presenta el contexto de la predicción y los datos
  para su revisión.

> **Alcance operativo:** cargar un CSV es análisis por lotes de un archivo
> histórico. El proyecto no captura paquetes ni monitorea una red en tiempo
> real.

## Estado comprobado

### Implementado

- Inspección de encabezado CSV, carga, validación y conteo de filas descartadas
  por duplicados, valores faltantes, etiqueta binaria inválida y valores
  numéricos no válidos.
- Descubrimiento de características a partir de los CSV reales; exclusión de
  `label`, `id` y `attack_cat` de los predictores.
- Pipeline de preprocesamiento con `ColumnTransformer`, codificación de
  categorías y ajuste únicamente con entrenamiento.
- Entrenamiento reproducible con `RandomForestClassifier`, búsqueda acotada por
  validación cruzada interna del conjunto de entrenamiento, semilla fija y
  ejecución de un solo proceso.
- Serialización del Pipeline y archivo JSON con versiones, parámetros,
  características, hash del CSV de entrenamiento y F1 de validación cruzada
  calculado durante la ejecución.
- Carga segura de esquema y predicción mediante Pipeline previamente guardado;
  persistencia SQLite de ejecuciones y alertas exclusivamente para predicciones
  reales de clase ataque.
- Evaluador del holdout que no ajusta el modelo y genera matriz de confusión,
  métricas, tiempo de inferencia y gráficos SVG.
- Panel Streamlit para cargar CSV compatible, mostrar resultados, consultar
  historial y alertas SQLite, gestionar estados `pending`, `confirmed` y
  `false_positive` mediante revisión manual, y descargar reportes. `confirmed`
  describe la revisión humana; no altera la predicción ni declara por sí solo un
  ataque real.
- Selector del Random Forest definitivo (predeterminado, `predict`) o del
  artefacto experimental del estudio (solo `predict_proba` clase 1 >= 0.65).
  Cada ejecución registra en SQLite el identificador, la regla, el umbral y el
  SHA-256 del artefacto. `SIPYMES_MODEL_PATH`, si está definido, prevalece y
  fija el artefacto efectivo; la interfaz desactiva el selector para evitar
  mostrar una opción distinta de la cargada.
- Gestión de alertas con modelo, regla, umbral, archivo de origen y fecha de
  registro obtenidos mediante `LEFT JOIN` con la ejecución SQLite. La tabla
  permite filtrar por modelo, ejecución y estado, y buscar por identificador;
  incluye detalle y exportación CSV de las alertas visibles. El score se rotula
  como score del modelo (clase 1), no como probabilidad calibrada, y la interfaz
  aclara que no explica la causa de la predicción ni confirma un ataque. En el
  reporte principal, la columna interna `probabilidad_ataque` se conserva por
  compatibilidad; su etiqueta visible y el encabezado exportado en CSV/JSON son
  `Score del modelo (clase 1)`. La interfaz advierte que el score no es
  necesariamente una probabilidad calibrada ni confirma un ataque.
- Historial acotado a las 100 ejecuciones y 10 000 alertas más recientes. La
  interfaz lo indica; filtros, búsqueda y «Todas» se aplican solo al conjunto
  cargado. Las ejecuciones fallidas permiten consultar un resumen seguro del
  error almacenado; los detalles internos no se exponen en pantalla ni en el
  CSV del historial.
- Instrumentación con `psutil` para tiempo y RSS de inferencia por lote.
- Pruebas automatizadas con archivos, modelos y bases de datos temporales para
  validar comportamiento normal y errores frecuentes.

### Pendiente antes de una entrega o uso de campo

- Confirmar y documentar las condiciones de licencia y redistribución de los
  archivos UNSW-NB15 antes de incluirlos en un paquete.
- Preparar una entrega limpia que incorpore los modelos y reportes requeridos:
  los datos, modelos y resultados actualmente presentes en este espacio de
  trabajo están excluidos por `.gitignore` y no se copian automáticamente a un
  checkout limpio.
- Validar generalización, tasas de falsas alarmas y utilidad operacional en
  tráfico representativo de PYMES con autorización y evidencia de campo. No se
  afirma validación en empresas reales.
- Captura de red, bloqueo de ataques y monitoreo continuo/tiempo real no forman
  parte de este prototipo y no son funciones pendientes de la versión actual.

### Resultados medidos en esta revisión

- Se ejecutó `unittest discover`: **55 pruebas aprobadas** (resultado de esta
  suite completa en este cierre; algunas pruebas usan únicamente fixtures
  temporales y las pruebas de software no son métricas del clasificador).
- Se comprobó el render del panel con Streamlit `AppTest` sin modelo disponible
  y con base temporal: sin excepciones. Esto verifica el estado vacío, no una
  sesión de usuario real con datos.
- Los resultados científicos descritos aquí se leen de los reportes ya
  guardados. Durante este cierre documental no se evaluó UNSW-NB15 ni se
  reentrenó un modelo. El reporte del estudio contiene métricas de validación
  para el modelo experimental; el umbral se seleccionó y midió en esa misma
  partición y esos resultados no son una estimación independiente ni se
  atribuyen al modelo definitivo.
- El umbral 0.65 y sus métricas pertenecen al modelo experimental y a su
  partición de validación del conjunto de entrenamiento; el umbral se eligió y
  midió en esa misma partición. No son métricas del modelo definitivo ni una
  estimación independiente de rendimiento general.
- El reporte oficial existente `data/processed/evaluation/metrics.json`
  corresponde al modelo definitivo, su regla `predict()` y el holdout oficial
  UNSW-NB15. Registra 82 332 filas retenidas, matriz de confusión
  `[[26415, 10585], [465, 44867]]`, precision 0.809114, recall 0.989742,
  F1 0.890360 y FPR 0.286081. El reporte conserva hashes del modelo,
  metadatos y CSV de prueba que permiten verificar su procedencia. Es un
  benchmark de ese conjunto, no evidencia de rendimiento en redes de PYMES.
- El informe experimental existente registra para el umbral 0.65: TN 10 666,
  FP 534, FN 1 153, TP 22 716, precision 0.977032, recall 0.951695, F1
  0.964197 y FPR 0.047679 en una partición de validación 80/20 tomada del
  conjunto oficial de entrenamiento. El umbral se seleccionó y midió en esa
  misma partición; estos resultados no son una evaluación independiente ni se
  atribuyen al modelo definitivo.
- Las pruebas de integración usan datos/modelos pequeños temporales solo para
  comprobar código, persistencia e instrumentación. No son evidencia de eficacia
  ni se mezclan con los archivos científicos.
- Se ejecutó una medición instrumental temporal de `Pipeline.predict` con
  `psutil` sobre un modelo y CSV de fixture, tamaños 1, 2 y 4, en este proceso:

  | Filas | Tiempo (s) | ms/fila | RSS pico (MiB) | Delta RSS (MiB) |
  | ---: | ---: | ---: | ---: | ---: |
  | 1 | 0.008220 | 8.219700 | 172.453 | 0.066 |
  | 2 | 0.004552 | 2.275850 | 172.477 | 0.023 |
  | 4 | 0.005149 | 1.287350 | 172.484 | 0.023 |

  Son cifras observadas para comprobar la instrumentación, con fixtures
  artificiales y un modelo pequeño de prueba; **no** representan UNSW-NB15,
  rendimiento de detección ni capacidad de una PYME. El artefacto temporal fue
  eliminado al terminar.

La fuente oficial describe UNSW-NB15 y sus particiones de entrenamiento y
prueba: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
Para uso académico se deben consultar y citar los trabajos indicados por los
autores en esa fuente.

## Requisitos

- Windows 11 de 64 bits.
- Python 3.14.6 recomendado para reproducir el entorno verificado.
- PowerShell y Visual Studio Code (opcional).
- Los paquetes listados en [requirements.txt](requirements.txt).
- Para reproducir las versiones exactas del entorno actual, use
  [requirements-lock.txt](requirements-lock.txt).
- SQLite a través del módulo estándar `sqlite3`; no requiere servidor.
- Archivos oficiales de entrenamiento y prueba UNSW-NB15 para entrenar/evaluar.
  Existen localmente, pero están excluidos por `.gitignore` y no se incluyen en
  un checkout limpio.

Versiones instaladas y comprobadas en el entorno de desarrollo de esta revisión:

| Componente | Versión |
| --- | --- |
| Python | 3.14.6 |
| pandas | 3.0.6 |
| NumPy | 2.5.4 |
| scikit-learn | 1.9.1 |
| Streamlit | 1.66.0 |
| joblib | 1.6.0 |
| psutil | 7.2.2 |
| SQLite | 3.50.4 |

El entorno local tenía estas versiones disponibles; no se instalaron ni
actualizaron paquetes durante la revisión.

## Instalación en Windows 11

Desde PowerShell, situado en la raíz del proyecto:

```powershell
py -3.14 --version
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
```

Si la política de ejecución impide activar el entorno, use el intérprete
directamente sin activarlo:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe verificacion.py
.\.venv\Scripts\python.exe comprobar_bibliotecas.py
```

Los archivos CSV, artefactos de modelo y base SQLite locales se excluyen del
control de versiones mediante `.gitignore`. En el espacio de trabajo actual sí
existen los dos modelos seleccionables, sus metadatos, los CSV oficiales y los
reportes indicados en el manifiesto [delivery-manifest.json](delivery-manifest.json);
su presencia local no implica que se incluyan en un checkout limpio ni que
puedan redistribuirse sin revisar licencias. No sobrescriba archivos personales
al preparar datos.

`requirements.txt` conserva las seis dependencias directas. El nuevo
`requirements-lock.txt` fija las 41 distribuciones de aplicación observadas en
`.venv`: seis directas y 35 dependencias transitivas/runtime. Se comprobó su
sintaxis y coincidencia con el entorno actual, y `pip check` no informó
conflictos. No contiene hashes de wheels y no se probó instalarlo en un entorno
limpio; no debe describirse como una instalación limpia ya verificada. `pip`
(26.2.1 en el entorno inspeccionado) es la herramienta instaladora y no se fija
como dependencia de la aplicación.

Para evitar reutilizar por accidente una base SQLite local, antes del primer
arranque de una copia limpia se puede seleccionar una ruta nueva:

```powershell
$env:SIPYMES_DATABASE_PATH='data\processed\security_analysis_delivery.sqlite3'
Remove-Item Env:SIPYMES_MODEL_PATH -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -B -m streamlit run app.py
```

Al iniciar, la aplicación crea esa base si no existe; no apuntar a la base
activa ni a un respaldo para una demostración nueva.

No se detectó un repositorio Git en el directorio de trabajo. Por tanto, no hay
commit o tag que identifique este estado. Antes de distribuirlo, el responsable
debe aprobar la inicialización de Git, revisar exclusiones/artefactos y crear un
commit y tag de versión; esta documentación no inicializa el repositorio.

## Estructura

```text
.
├── app.py
├── comprobar_bibliotecas.py
├── verificacion.py
├── requirements.txt
├── requirements-lock.txt
├── data/
│   ├── raw/                 # CSV oficiales locales, no versionados
│   └── processed/           # resultados, mediciones y SQLite locales
├── docs/
│   └── arquitectura.md
├── models/                  # Pipeline y metadatos locales, no versionados
├── seguridad_pymes/
│   ├── ingestion.py         # lectura, validación y preprocesamiento
│   ├── training.py          # entrenamiento y selección en entrenamiento
│   ├── evaluation.py        # evaluación del holdout guardado
│   ├── threshold_analysis.py # estudio exploratorio de umbrales
│   ├── inference.py         # predicción y registro de ejecuciones/alertas
│   ├── database.py          # esquema y consultas SQLite parametrizadas
│   ├── resources.py         # medición de tiempo/RSS con psutil
│   ├── dashboard.py         # interfaz Streamlit
│   ├── alerts.py            # punto de extensión para manejo de alertas
│   ├── detection.py         # coordinación futura
│   └── preprocessing.py     # punto de extensión de preparación
└── tests/
    ├── test_dashboard.py
    ├── test_database.py
    ├── test_evaluation.py
    ├── test_inference_persistence.py
    ├── test_ingestion.py
    └── test_training.py
```

## Datos, metodología y prevención de fuga

1. Obtener los archivos oficiales `UNSW_NB15_training-set.csv` y
   `UNSW_NB15_testing-set.csv` de la fuente UNSW indicada arriba y guardarlos
   localmente en `data/raw/`. Confirmar su procedencia, integridad, licencia y
   esquema antes de analizarlos.
2. La carga inspecciona encabezados reales y requiere que entrenamiento y prueba
   tengan los mismos nombres y orden. La etiqueta objetivo es `label` (0 normal,
   1 ataque). Las columnas `id`, `attack_cat` y `label` no son predictores.
3. Se informan filas descartadas por duplicado exacto, valores faltantes,
   etiqueta fuera de 0/1 y valor inválido en características numéricas
   identificadas en entrenamiento. Las categorías se detectan a partir del
   entrenamiento; categorías nuevas en prueba se ignoran por el encoder y se
   informan.
4. El Pipeline incluye transformaciones y Random Forest. Cada fold de
   validación ajusta sus transformaciones solo con el fold de entrenamiento. La
   búsqueda de hiperparámetros usa exclusivamente el CSV oficial de
   entrenamiento. El CSV de prueba no se lee en entrenamiento.
5. La evaluación posterior carga el Pipeline ya serializado y predice el holdout
   sin `fit` ni ajuste de parámetros. Precision, recall y F1 se calculan para
   ataque (1); también se registran matriz de confusión y tasa de falsos
   positivos `FP / (FP + TN)`.

Un resultado del benchmark no garantiza rendimiento en las PYMES objetivo. La
prevalencia, calidad de etiquetas, topología, equipos, tráfico local y cambios
temporales pueden ser distintos. No se deben presentar validación cruzada o
pruebas de software como evaluación empresarial.

## Comandos de ejecución y reproducción

Todos los comandos usan PowerShell desde la raíz.

### 1. Verificar entorno e imports

```powershell
.\.venv\Scripts\python.exe verificacion.py
.\.venv\Scripts\python.exe comprobar_bibliotecas.py
.\.venv\Scripts\python.exe -B -c "import seguridad_pymes.ingestion, seguridad_pymes.training, seguridad_pymes.evaluation, seguridad_pymes.inference, seguridad_pymes.database, seguridad_pymes.resources, seguridad_pymes.dashboard, app; print('Importaciones correctas')"
```

### 2. Ejecutar pruebas automatizadas

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Las pruebas usan `TemporaryDirectory`; no escriben modelos, bases ni CSV sobre
los datos del proyecto.

### 3. Entrenar

Con el archivo oficial ya verificado en `data/raw/`:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.training
```

El artefacto se guarda como
`models/unsw_nb15_random_forest.joblib` y sus parámetros/versiones como
`models/unsw_nb15_random_forest.joblib.metadata.json`. Por defecto, la búsqueda
usa `RandomizedSearchCV`, F1 de ataque, `StratifiedKFold` de 3 folds, semilla
42, 4 combinaciones de una cuadrícula pequeña y `n_jobs=1`. La puntuación se
calcula al ejecutar; no hay puntuación del proyecto reportada aquí.

Para una prueba piloto separada, reproducible y limitada a 20 000 filas válidas
estratificadas del archivo de entrenamiento:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.training --profile pilot --sample-rows 20000 --random-state 42
```

El perfil piloto usa 2 folds, 2 iteraciones y el mismo preprocesamiento dentro
del Pipeline. Guarda el artefacto en
`models/unsw_nb15_random_forest_pilot.joblib` y sus metadatos junto a él; no usa
ni abre el CSV oficial de prueba. Los metadatos registran conteos, distribución
de clases, semilla, parámetros probados y elegidos y el tiempo de `fit`. La
muestra se toma después de cargar y limpiar el CSV de entrenamiento, por lo que
la prueba piloto reduce los datos usados por los modelos, pero no evita el costo
de memoria de cargar y validar el archivo completo. No es la evaluación final ni
reemplaza el entrenamiento definitivo.

Para entrenar el perfil definitivo con todos los registros válidos del archivo
oficial de entrenamiento y los hiperparámetros seleccionados en la validación
cruzada de la muestra piloto:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.training --profile final-fixed
```

Este perfil usa `n_estimators=80`, `max_depth=24`, `min_samples_leaf=2`,
`max_features="sqrt"` y `random_state=42`. Ajusta el Pipeline con todo el
entrenamiento válido, sin búsqueda adicional y sin abrir el CSV oficial de
prueba. Guarda en `models/unsw_nb15_random_forest.joblib` y se niega a
sobrescribir artefactos existentes. Sus metadatos indican que la selección se
originó en validación cruzada estratificada sobre la muestra piloto; el modelo
debe evaluarse posteriormente con el holdout reservado.

### 4. Cargar y predecir

La interfaz carga el modelo seleccionado al iniciar el análisis. Para una
comprobación manual de la instalación se puede predecir el CSV pequeño de
demostración (derivado del conjunto de entrenamiento):

```powershell
.\.venv\Scripts\python.exe -B -m streamlit run app.py
```

En Streamlit, carga `data/processed/demo_20_registros.csv` y selecciona cada
modelo. El archivo contiene 20 filas etiquetadas y sirve solo para comprobar el
flujo de la aplicación; al derivarse del conjunto de entrenamiento, no estima
generalización. El conjunto oficial de prueba se reserva para la evaluación
documentada, no para demostraciones ni selección de parámetros.

No cargue modelos joblib de fuentes no confiables; deserializarlos puede
ejecutar código.

### 5. Evaluar el holdout

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.evaluation
```

Genera `data/processed/evaluation/metrics.json`,
`confusion_matrix.csv` y gráficos SVG con valores efectivamente calculados.
Incluye número exacto de filas retenidas, descartes, hashes de archivos y
versiones. El tiempo es una medición de `Pipeline.predict` por lote en el equipo
actual, no latencia por paquete. La medición sobre el CSV de demostración es
solo una comprobación instrumental, no un benchmark de eficacia ni de
generalización. El comando de evaluación oficial es el único ejemplo que usa
`UNSW_NB15_testing-set.csv`.

### Estudio exploratorio de umbrales (separado de la evaluación oficial)

Este estudio es opcional y usa **solo** el CSV oficial de entrenamiento. Divide
sus filas válidas mediante una partición estratificada 80/20 con semilla 42,
ajusta un Pipeline de estudio solo con el 80 % de entrenamiento y compara
umbrales de 0.50 a 0.95. La regla predeclarada selecciona, entre umbrales con
recall de validación de al menos 95 %, el de menor FPR; los desempates se
resuelven por mayor recall y luego menor umbral. Si ninguno cumple, no selecciona
ninguno.

Ejecutar desde PowerShell en la raíz:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.threshold_analysis
```

El estudio crea una carpeta nueva `data/processed/threshold_study/` con un
Pipeline separado, metadatos, tabla CSV de métricas por umbral e informe JSON.
Falla si esa carpeta ya existe. No modifica el modelo definitivo, sus
metadatos, la evaluación oficial ni el comportamiento de inferencia/alertas.
Las métricas de validación se usan para escoger el umbral y por ello no son una
estimación independiente del rendimiento posterior a la selección. Este análisis
no abre ni utiliza el CSV oficial de prueba y no debe confundirse con su
evaluación independiente.

### 6. Medir procesamiento y memoria

Para comprobar la instrumentación con el CSV de demostración y un modelo
compatible, medir hasta cuatro filas:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.resources --model models/unsw_nb15_random_forest.joblib --csv data/processed/demo_20_registros.csv --sample-sizes 1 2 4 --output data/processed/inference_resources_demo.csv
```

El CSV se carga y valida antes de medir; el informe mide `Pipeline.predict` en
las primeras N filas y guarda tiempo total, ms por registro, RSS base, RSS pico
y delta de RSS en MiB. RSS pico se muestrea con `psutil` cada 10 ms, así que
puede no capturar asignaciones más breves. El consumo base ya incluye el modelo,
el proceso y el CSV cargado; el delta es aproximado. Los resultados dependen de
hardware, sistema operativo, carga del equipo y datos. La función falla si no
hay suficientes filas para el tamaño máximo solicitado.
Para evitar sobrescrituras, el comando falla si el archivo de salida ya existe;
elija una ruta nueva para cada medición. El entrenamiento y la evaluación
también rechazan destinos con artefactos/resultados existentes.

La medición no incluye calentamiento previo; especialmente en lotes pequeños el
costo inicial de la primera llamada puede dominar. El panel mide el tiempo de la
predicción (incluida la probabilidad si está disponible), no carga del archivo
ni escritura SQLite.

`run_model_analysis`, usado por el panel, también registra tiempo y RSS
aproximado de la predicción por lote que acaba de ejecutarse.

### 7. Inicializar y consultar SQLite

```powershell
.\.venv\Scripts\python.exe -B -c "from seguridad_pymes.database import initialize_database; print(initialize_database())"
.\.venv\Scripts\python.exe -B -c "from seguridad_pymes.database import list_analysis_runs, list_alerts; print(list_analysis_runs()); print(list_alerts())"
```

Ruta predeterminada: `data/processed/security_analysis.sqlite3`. Puede
configurarse el modelo y la base del panel por variables de entorno:

```powershell
$env:SIPYMES_MODEL_PATH='models\unsw_nb15_random_forest.joblib'
$env:SIPYMES_DATABASE_PATH='data\processed\security_analysis.sqlite3'
```

### 8. Iniciar Streamlit

```powershell
.\.venv\Scripts\python.exe -B -m streamlit run app.py
```

El panel acepta CSV UTF-8 de hasta 100 MB con las características esperadas por
el modelo. `id` puede identificar filas y no se usa como característica; si no
está, se crea una referencia por nombre de archivo y posición. `label` y
`attack_cat` se ignoran. CSV vacío, encabezados duplicados, esquema incompatible,
IDs repetidos y características faltantes producen mensajes de error. Las
predicciones se muestran y persisten solo después de una inferencia real.

## Interpretación y limitaciones

- **Matriz de confusión:** TN, FP, FN y TP; filas = etiqueta real, columnas =
  predicción.
- **Precision de ataque:** proporción de predicciones de ataque que son
  verdaderas. Depende de prevalencia; un falso positivo puede generar trabajo
  de revisión.
- **Recall de ataque:** proporción de ataques etiquetados que se detectan. No
  representa la severidad del incidente y no mide clases ausentes.
- **F1:** equilibrio armónico de precision y recall; no modela costos locales.
- **Tasa de falsos positivos:** `FP/(FP+TN)`. Una tasa pequeña puede originar
  muchas alertas cuando el volumen benigno es grande.
- **Tiempo y memoria:** medidas del equipo donde se ejecutan, no garantías de
  capacidad ni latencia en tiempo real.
- **Score del modelo (clase 1):** puntuación de salida de `predict_proba` cuando
  está disponible; no es necesariamente una probabilidad calibrada, no confirma
  un ataque y no explica la causa de la predicción.
- `confirmed` significa que una persona confirmó manualmente la revisión de la
  alerta; no es evidencia técnica concluyente ni cambia la predicción.
- El panel procesa lotes de CSV de flujos de red sin conexión. No captura
  paquetes, no bloquea ataques ni monitorea continuamente una red.
- No se ha validado el sistema en redes reales de PYMES. Los resultados
  UNSW-NB15 son un benchmark de conjunto de datos y no predicen directamente el
  desempeño operacional local.

## Artefactos y modelos disponibles

El modelo definitivo `models/unsw_nb15_random_forest.joblib` es el
comportamiento predeterminado y clasifica con `model.predict()`. El artefacto
experimental `data/processed/threshold_study/threshold_study_random_forest.joblib`
es otro Pipeline ajustado, no una variante de umbral del modelo definitivo:
clasifica como ataque si `predict_proba` para clase 1 es >= 0.65. Ambos tienen
metadatos y se validan frente al mismo esquema de 42 características. Si
`SIPYMES_MODEL_PATH` está definido, ese override explícito tiene precedencia y
la interfaz refleja/desactiva la selección para no indicar un modelo distinto
del cargado.

Los valores de validación del estudio experimental se eligieron y midieron en
la misma partición y no son una estimación independiente. No se deben comparar
como si fueran métricas del modelo definitivo ni afirmar que el modelo
experimental tiene mejor rendimiento general.

## Qué revisar antes de presentar resultados

1. Conservar fuente y hash de ambos CSV y metadatos del artefacto.
2. Entrenar solo con el split de entrenamiento y evaluar el test una única vez,
   después de congelar Pipeline e hiperparámetros.
3. Informar filas leídas, descartes por causa y número exacto de muestras
   evaluadas.
4. Reportar métricas, matriz de confusión, tiempo y hardware junto con límites.
5. Separar claramente pruebas unitarias, métricas del benchmark y cualquier
   validación futura con empresas.
6. Confirmar licencias antes de redistribuir los CSV oficiales; revisar el
    [manifiesto de entrega](delivery-manifest.json) y completar la identificación
    de versión mediante Git una vez aprobada su inicialización.
