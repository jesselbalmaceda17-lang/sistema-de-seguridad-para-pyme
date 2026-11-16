# Verificación funcional y estabilización local — 9 de noviembre de 2026

La aplicación existente completó la validación local de CSV, inferencia, alertas, revisión manual, historial y exportaciones. Se corrigieron cuatro defectos reproducibles con cambios limitados a [dashboard.py](../../seguridad_pymes/dashboard.py). La suite pasó de 229 a 235 pruebas aprobadas; además se ejecutaron 20 casos integrales y nueve comprobaciones en navegador real. Esto verifica el comportamiento observado del software; no demuestra precisión de detección ni ausencia de errores.

No se descargaron capturas, no se capturaron interfaces y no se entrenaron modelos del proyecto. Los modelos, datasets, umbrales, particiones y resultados previos permanecen intactos. El Random Forest PCAP continúa fuera de la detección operativa.

## Inventario comprobado

| Funcionalidad | Implementación y conexión real | Estado y evidencia |
|---|---|---|
| Inicio de Streamlit | [app.py](../../app.py) invoca [dashboard.py](../../seguridad_pymes/dashboard.py). | Arranque real en Windows 11, HTTP 200, carga y ejecución desde navegador; [verificación](browser_verificacion_final.json). |
| Carga y validación de CSV | La interfaz valida UTF-8, estructura, tamaño, columnas requeridas, valores faltantes e identificadores. La inferencia valida valores numéricos y finitos. | Conectada; nueve entradas inválidas sin crear ejecuciones. Defecto de desplazamiento de columnas corregido. |
| Clasificación original CSV | [inference.py](../../seguridad_pymes/inference.py) carga el pipeline UNSW-NB15 de [modelo original](../../models/unsw_nb15_random_forest.joblib), con preprocesamiento y 42 predictores. | Comparación fila por fila con el artefacto almacenado: clases, puntuaciones, métricas, SQLite y exportaciones coinciden. |
| Selector CSV preexistente | Modelo original con `predict`; alternativa del estudio de umbral CSV, 42 predictores y regla original `>= 0.65`. | Política alternativa comprobada por AppTest/API; no se cambió ninguna regla. Ese estudio CSV es distinto del experimento PCAP de 38 características. |
| Alertas | Inferencia crea una alerta por predicción sospechosa y [database.py](../../seguridad_pymes/database.py) la persiste. | Ocho filas controladas producen cuatro alertas; prueba de 10.000 filas persiste las 5.000 esperadas. Son salidas del modelo, no incidentes confirmados. |
| Resumen y resultados visibles | Conteos, gráfico y tabla derivados de las filas procesadas; descargas CSV y JSON. | Navegador real y descargas HTTP contrastados con oráculo y SQLite; reporte grande ahora declara la lista truncada de alertas. |
| Historial, filtros y revisión | Consultas y filtros por ejecución, modelo, estado e identificador; revisión `pending`, `confirmed`, `false_positive`. | Conectados; revisión real sobrevive al reinicio y no altera clase ni puntuación originales. Historial limitado a 100 ejecuciones y 10.000 alertas. |
| Persistencia y errores SQLite | Inicialización, migraciones preexistentes, escritura y consulta en [database.py](../../seguridad_pymes/database.py). | Conexiones independientes comprueban persistencia. Base corrupta y ruta inválida generan errores controlados en la interfaz. Las pruebas usan bases nuevas aisladas. |
| Medición de recursos | [resources.py](../../seguridad_pymes/resources.py) mide tiempo y RSS alrededor de la inferencia. | Disponible y contrastada en carga sintética; no es garantía de recursos para todo archivo aceptable. |
| Extracción PCAP/PCAPNG offline | [pcap_extract.py](../../seguridad_pymes/pcap_extract.py), [pcap_reader.py](../../seguridad_pymes/pcap_reader.py) y [pcap_schema.py](../../seguridad_pymes/pcap_schema.py): TShark, flujos IPv4 TCP/UDP, 38 características y calidad. | CLI/API operativos dentro de límites actuales. Dos paquetes UDP sintéticos, un flujo, ambos sentidos y conteos de bytes independientes; repetición idéntica. Sin clasificación, captura en vivo ni integración Streamlit. |
| Etiquetas y auditoría PCAP | [zeek_labels.py](../../seguridad_pymes/zeek_labels.py), [label_audit.py](../../seguridad_pymes/label_audit.py), resultados de [PCAP v1](../../experiments/pcap_v1). | Herramientas experimentales conservadas. Sus pruebas anteriores siguen aprobadas. No se relajó la auditoría ni se incorporaron conexiones rechazadas. |
| Entrenamiento, evaluación y adquisición | [training.py](../../seguridad_pymes/training.py), [evaluation.py](../../seguridad_pymes/evaluation.py), [threshold_analysis.py](../../seguridad_pymes/threshold_analysis.py), [iot23_sources.py](../../seguridad_pymes/iot23_sources.py). | Herramientas previas, sin ejecución de entrenamiento sobre datos del proyecto ni nuevas adquisiciones en este cierre. Las pruebas unitarias existentes pueden ajustar modelos diminutos temporales. |
| Módulos nominales vacíos | [alerts.py](../../seguridad_pymes/alerts.py), [detection.py](../../seguridad_pymes/detection.py), [preprocessing.py](../../seguridad_pymes/preprocessing.py). | Contienen únicamente documentación; no constituyen APIs implementadas. Sus funciones de producto efectivas están en inferencia, persistencia e ingestión. No se rellenaron ni reorganizaron por estética. |

No se encontró un control visible sin conexión en las rutas funcionales ejercitadas. Sí había discrepancias verificables en el límite mostrado y en la integridad estructural del CSV y del reporte exportado; se describen abajo. La interfaz no ofrece carga PCAP ni captura de red. Las rutas de clasificación CSV dependen del artefacto UNSW-NB15; el historial ya almacenado puede consultarse aunque falle la carga del modelo.

## Defectos y correcciones mínimas

| ID / gravedad | Evidencia antes y causa | Corrección / regresión |
|---|---|---|
| D1 / Alta, integridad de entrada | `a,b\n1,2,3\n` se aceptaba como `a=2,b=3`: pandas infería un índice y desplazaba campos sin cambiar los encabezados. [Diagnóstico](diagnostico_inicial.json), [pruebas rojas](regresion_roja.log). | Rechazar el índice inferido después del parseo. Dos casos malformados rechazados y un CSV válido con comillas y campos multilínea conservado. |
| D2 / Media, estabilidad | Un frame pickle dañado causaba `OverflowError` sin controlar en Streamlit. [Diagnóstico](diagnostico_inicial.json), [prueba roja](regresion_roja.log). | Convertir `OverflowError` y `pickle.UnpicklingError` en el error de validación ya manejado por la interfaz. Prueba AppTest sin excepción de pantalla. No convierte joblib en un formato seguro para archivos no confiables. |
| D3 / Baja, coherencia de interfaz | El componente de carga anunciaba 200 MB; el validador existente limitaba a 100 MiB. [Diagnóstico](diagnostico_limites_exportacion.json), [prueba roja](limites_roja.log). | Asignar al componente el límite existente de 100. Prueba de configuración y comprobación visual real. No se aumentó el límite. |
| D4 / Media, integridad del reporte | Una ejecución con 10.001 alertas exportaba una lista de 10.000 sin declarar truncamiento. [Diagnóstico](diagnostico_limites_exportacion.json), [prueba roja](limites_roja.log). | Conservar el límite y añadir total, cantidad devuelta, límite y bandera de truncamiento al JSON; aviso visible. Prueba de 10.001 alertas y de conservación de todos los resultados por registro. |

El [diff completo](correcciones.diff) contiene exclusivamente estas correcciones. Las [seis regresiones nuevas](../../tests/test_stabilization.py) están incluidas en la suite. [Resultado verde](regresion_completa_verde.log). No hubo refactorización general, cambio de esquema SQL ni modificación de extracción, importación, auditoría o clasificación.

## Pruebas integrales y reproducibilidad

La [matriz de 29 comprobaciones](matriz_pruebas.csv) separa 20 casos de AppTest/API/CLI y nueve verificaciones de navegador. No son 29 pruebas nuevas de la suite: sus denominadores se mantienen separados.

- [Resultados integrales](integral_run_001/resultados.json): 20/20 aprobados. CSV vacío, solo encabezado, columna ausente, número inválido, infinito, dato faltante, ID duplicado, codificación inválida y campos adicionales fueron rechazados sin generar ejecuciones. Se probaron modelo ausente, directorio en vez de modelo, modelo PCAP incompatible, base corrupta, padre de ruta inválido, dependencia TShark ausente y captura inexistente/truncada.
- [Oráculo](oraculo_modelo.json) y [CSV controlado](fixtures/valido.csv): ocho entradas sintéticas con clases originales `0,0,0,0,1,1,1,1`. Las puntuaciones se obtuvieron directamente del modelo almacenado y se contrastaron exactamente. Estas filas no tienen verdad terreno y no sirven para estimar recall, precisión o falsos positivos.
- [Navegador y SQLite](browser_verificacion_final.json): dos análisis reales de ocho filas, ocho alertas acumuladas; primera revisión falsa positiva conservada tras reiniciar. Entradas inválidas no añadieron ejecuciones. [Descargas reales](browser_descargas_verificadas.json): cinco respuestas HTTP 200, con CSV/JSON y contenido contrastado. Se verificó el contenido servido; el diálogo de guardado del sistema operativo no se automatizó.
- [PCAP controlado](integral_run_001/controlled.pcap) y [PCAPNG controlado](integral_run_001/controlled.pcapng): extracción completa mediante CLI y API, 38 características, dos paquetes, un flujo, un paquete por dirección y 31/30 bytes IP. Dos extracciones del mismo archivo producen JSON idéntico. No se infirieron etiquetas ni se ejecutó un clasificador.
- Carga sintética de 10.000 filas: 5.000 alertas, 0,833 s para validación/inferencia/persistencia; inferencia 0,262 s, RSS de base 346,88 MiB y pico 367,08 MiB, incremento 20,20 MiB. El proceso integral completo alcanzó aproximadamente 410,7 MiB. Son mediciones de esta máquina y datos controlados, no un benchmark de operación real.
- [Suite inicial](suite_inicial.log): 229 aprobadas. [Suite final](suite_final_confirmada.log) y [código de salida](suite_final.json): **235 aprobadas, salida 0**, 45,565 s dentro del ejecutor y 49,608 s con descubrimiento. No fallos ni errores.

Para repetir sin alterar el historial original, seguir [inicio y reproducción](inicio_verificado.md). El servidor de prueba fue [detenido](servidor_detenido.json) al terminar para congelar sus evidencias.

## Seguridad, estabilidad y entorno

La inspección de las rutas ejercitadas no encontró construcción de comandos de shell con entradas del usuario: TShark recibe argumentos separados para leer un archivo offline. Las consultas usan parámetros SQL; los identificadores dinámicos corresponden a listas fijas. Se enviaron cadenas de intento de inyección como origen y filtro, comprobando que se tratan como datos y que las tablas siguen consultables. Las exportaciones CSV ya neutralizan fórmulas de hoja de cálculo; se conservaron sus pruebas previas.

Se validaron rutas ausentes/incompatibles, errores de lectura, modelo dañado y dependencia PCAP ausente. El límite CSV se aplica antes del parseo. Los límites y timeouts PCAP permanecieron intactos y no se ensayó eludirlos. El almacenamiento de resultados y la construcción de reportes consumen memoria proporcional al lote; no se verificó el peor caso de 100 MiB ni concurrencia sostenida. No se promete procesamiento fluido de cualquier archivo bajo el límite.

Windows 11 build 26200, Python 3.14.6 y TShark 4.6.9 son el entorno observado. [Verificación de dependencias](entorno_verificado.json): las 41 distribuciones coinciden con [requirements-lock.txt](../../requirements-lock.txt), y `pip check` no encuentra dependencias rotas. Esto comprueba consistencia del entorno instalado; no reemplaza una instalación limpia ni un análisis de vulnerabilidades.

La aplicación se comprobó en `127.0.0.1`. No tiene autenticación ni control de usuarios para exposición remota. Los modelos joblib son artefactos locales confiables: el override de administrador no debe recibir archivos de terceros. Estas son fronteras del producto existente, no nuevas funciones agregadas ni pruebas de seguridad absoluta.

## Respaldo e integridad

Antes de modificar código se creó un [respaldo nuevo](../../_backups/pre-stabilization-20261109T150149Z-1608d5a2.zip) de 450.371.384 bytes y se realizó una [restauración efectiva](../../_backups/restore-stabilization-20261109T150149Z-1608d5a2). Sus 500 archivos se verificaron por SHA-256 y CRC; las SQLite se respaldaron mediante su API y se compararon lógicamente. [Registro inicial](respaldo_inicial.json).

SHA-256 del archivo de respaldo: `b56e2987f689837285f9e7c9b813b11f42aab0f040676e58956d56d099cf7404`.

La [verificación final](integridad_final.json) comprobó 1.160 archivos previos: **1.159 idénticos y únicamente el dashboard modificado de forma autorizada**, sin archivos desaparecidos. La lista incluye respaldos y restauraciones previas; no equivale a 1.160 archivos de código. Se añadió un archivo de seis pruebas y evidencias nuevas en esta carpeta.

- Las cuatro ejecuciones [PCAP v1](../../experiments/pcap_v1) conservan 49 archivos cada una, incluidos 12 modelos por ejecución: 196 archivos y 48 modelos experimentales intactos, además de sus logs previos. Se preservaron las ejecuciones que documentan correcciones numéricas.
- El [modelo CSV original](../../models/unsw_nb15_random_forest.joblib) conserva SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. El resto de modelos, fuentes PCAP, manifiestos y datasets previos también conservan hashes.
- Las tres SQLite originales, [principal](../../data/processed/security_analysis.sqlite3), [respaldo](../../data/processed/security_analysis.backup-20261105T193153Z-e296f770.sqlite3) y [anterior al selector](../../data/processed/security_analysis.pre-model-selector-20261103-0833.sqlite3), mantienen sus bytes originales y devuelven `PRAGMA integrity_check = ok`. Su contenido lógico coincide con la restauración. La serialización de la huella lógica final es la unión de `iterdump()` con LF sin LF final; se compara actual/restaurada con el mismo método.
- Las bases nuevas de prueba están aisladas. Una de ellas está corrupta deliberadamente para la prueba negativa; la afirmación de integridad anterior se refiere exactamente a las tres originales.

El [verificador reproducible](verificar_cierre.py) vuelve a contrastar este inventario. No se integró el modelo PCAP ni se reutilizaron flujos rechazados; Somfy, Muhstik y las reservas de evaluación permanecieron fuera de cualquier selección o entrenamiento nuevo.

## Pendientes exactos y decisión de cierre

No quedó un defecto conocido que bloquee los recorridos locales comprobados después de estas correcciones. La versión puede usarse localmente dentro del alcance CSV y de extracción offline descrito. Para declarar una entrega reproducible en otros equipos todavía falta:

1. **Instalación limpia en otro Windows 11.** Se comprobó el entorno existente, pero no la creación desde cero del entorno, disponibilidad de paquetes y arranque con los artefactos necesarios. Es una validación pendiente de portabilidad.
2. **Aceptar un presupuesto operativo de recursos y validarlo.** Solo se midieron 10.000 filas sintéticas. Falta medir con un lote representativo del uso acordado y comprobar comportamiento cercano al límite de 100 MiB; ese límite es una guarda de entrada, no una capacidad de servicio demostrada.
3. **Verificar el paquete final de distribución.** Confirmar en una copia limpia los archivos que efectivamente se entregan, modelos locales requeridos, dependencias y permisos de escritura del historial. Los hashes y el respaldo de este directorio no sustituyen esa prueba. No se creó un instalador ni se cambió el manifiesto previo.

Los módulos nominales vacíos quedan identificados como tales; no impiden el recorrido implementado ni justifican una refactorización. Autenticación, captura en vivo, procesamiento multiusuario e integración de un detector PCAP no pertenecen a este cierre. La falta de generalización del RF PCAP sigue siendo una limitación investigativa demostrada; no se intenta compensar con nuevos datos, umbrales o mensajes de confianza. No se redactó documentación académica ni material de defensa.
