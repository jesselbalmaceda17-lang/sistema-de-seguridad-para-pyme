# Entrega técnica verificada — Seguridad Inteligente PYMES

9 de noviembre de 2026. El paquete final puede instalarse con los requisitos existentes y ejecutar el recorrido CSV original: predicción, alertas, historial, revisión y exportaciones. Se instaló un entorno nuevo, se comprobó el paquete y se repitió la aceptación desde una extracción fuera de la carpeta de desarrollo. La demostración real produjo ocho predicciones y cuatro alertas esperadas. No se modificó ningún archivo previo del proyecto en esta fase.

Esto verifica funcionamiento y consistencia de software en este Windows 11. No demuestra precisión de detección, ausencia de defectos, rendimiento universal ni funcionamiento en otro equipo físico.

## Entregables

| Entregable | Ubicación |
|---|---|
| Carpeta final, 24 archivos | [Distribución CSV](../../dist/SeguridadInteligentePYMES-entrega-20261109) |
| Copia comprimida verificada, 8.014.733 bytes | [ZIP final](../../dist/SeguridadInteligentePYMES-entrega-20261109.zip) |
| SHA-256 por archivo; el manifiesto excluye su propia huella | [Manifiesto](../../dist/SeguridadInteligentePYMES-entrega-20261109/manifest.sha256.json) |
| Instalación, inicio, uso y requisitos | [Guía del paquete](../../dist/SeguridadInteligentePYMES-entrega-20261109/README.md) |
| Respaldo y recuperación sin sobrescribir bases | [Procedimiento de recuperación](../../dist/SeguridadInteligentePYMES-entrega-20261109/RECUPERACION.md) |
| Versiones y resultados portátiles | [Versiones](../../dist/SeguridadInteligentePYMES-entrega-20261109/VERSIONES.json), [verificación](../../dist/SeguridadInteligentePYMES-entrega-20261109/VERIFICACION.md) |
| Instalación limpia y procedencia de dependencias | [Resultado detallado](pruebas_paquete_001/instalacion_limpia.json), [resumen](resumen_instalacion.json), [reporte de pip](instalacion_paquete_pip.json) |
| Pruebas del paquete | [Aceptación inicial](pruebas_paquete_001/resultados.json), [copia con espacios](pruebas_reubicado_001/resultados.json), [ZIP extraído fuera del proyecto](pruebas_externo_001/resultados.json) |
| Carga controlada | [Resultados finales de rendimiento](rendimiento_003/resultados.json) |
| Protección del proyecto y artefactos finales | [Integridad final](integridad_final.json), [identidad del paquete y ZIP](paquete_final.json) |
| Comandos de reproducción | [Registro del procedimiento](reproduccion.md) |

SHA-256 del ZIP: `f8a481e29675f9960c707b489e65436f187327a543d212dcc5d8b2962bcc3756`.

SHA-256 del manifiesto: `b6149f8172b870b071af1a3908a3c4cdb6e04528b361cdc013d6998f3da19a44`.

## Protección y selección de archivos

Antes de preparar el paquete se verificaron las 79 evidencias del cierre anterior y sus 1.160 archivos protegidos. Se creó un [respaldo nuevo](../../_backups/pre-delivery-20261109T155849Z.zip), se comprobó su CRC y se restauraron efectivamente 581 archivos en una [carpeta independiente](../../_backups/restore-delivery-20261109T155849Z). Todos los hashes de la restauración coinciden. Las tres bases originales se respaldaron por la API SQLite y se verificaron por integridad y equivalencia lógica. [Registro inicial](respaldo_inicial.json).

SHA-256 de ese respaldo: `20ea1c7187b3d542b9ad9bafd7904cbd1d799c689eacf6f61984b5518d4d6b8a`.

La [selección exacta](seleccion_archivos.json) copia sin cambios ocho archivos de código operativo, dos requisitos y el modelo CSV original con sus metadatos: 12 archivos preexistentes idénticos. Se agregan exclusivamente configuración local, demo, información de versiones, manifiesto, guía y herramientas de verificación/recuperación necesarias para la entrega. El cargador del modelo importa entrenamiento e ingestión, por lo que esos módulos se conservan completos; no se refactorizaron para recortarlos ni se ejecutó entrenamiento del proyecto.

| Categoría | Separación mantenida |
|---|---|
| Operación entregable | Solo la [carpeta de distribución](../../dist/SeguridadInteligentePYMES-entrega-20261109), sin entorno virtual ni historial precargado. |
| Investigación | [Datos originales](../../data), [experimentos](../../experiments), [pipeline PCAP](../../pcap_experiment): permanecen en su ubicación, fuera del paquete. |
| Pruebas existentes | [Suite original](../../tests), intacta. |
| Evidencias y nuevas pruebas de entrega | Esta [carpeta técnica](.), separada del producto distribuido. |
| Entornos y copias de validación | [Área de validación](../../_delivery_validation); una extracción adicional se realizó en el directorio temporal permitido, fuera del proyecto. No se distribuyen. |
| Respaldos | [Respaldos originales y nuevos](../../_backups); no se distribuyen ni se movieron los anteriores. |

El paquete contiene un único joblib: el CSV original, SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. El script de inicio usa el override preexistente para fijar ese artefacto y deshabilitar el selector opcional. No se distribuye el estudio alternativo de umbral CSV, ni modelos PCAP, capturas, datasets de investigación, bases personales, contraseñas o respaldos históricos. Se conserva la regla original `predict` y sus 42 características. Las 38 características PCAP y su auditoría permanecen intactas en investigación.

## Instalación realmente aislada de los paquetes anteriores

El entorno final de validación se creó con `py -3.14 -m venv`, usando el Python base 3.14.6 de Windows, en una ruta nueva. Se instalaron por HTTPS y sin caché las versiones de los dos requisitos incluidos en el paquete. No se copiaron `site-packages` ni se empleó el entorno virtual original para ejecutar el paquete. Hubo una instalación preliminar separada; las evidencias finales usan únicamente el entorno nuevo creado con el lanzador base, según el [resumen](resumen_instalacion.json).

- Las **41 versiones coinciden** y `pip check` devuelve `No broken requirements found.`
- La configuración registra `include-system-site-packages = false`; los tests se ejecutaron con `-I`, sin site de usuario ni `PYTHONPATH` del proyecto.
- Se comprobó que código operativo, bibliotecas y modelo provienen respectivamente del paquete y del entorno nuevo. Las rutas del código cargado también se comprobaron en la extracción externa.
- El [log de instalación](instalacion_paquete_pip.log) abarca aproximadamente 274 s. El entorno ocupa 540.648.730 bytes, unos 516 MiB. Son medidas locales y no requisitos mínimos universales.
- Dependencia externa real: `pypi.org` y `files.pythonhosted.org`, además de un Python base previamente instalado con `venv`/`pip`. Los [41 artefactos descargados y sus hashes](../../dist/SeguridadInteligentePYMES-entrega-20261109/DEPENDENCIAS_DESCARGADAS.json) quedan identificados. No se incluyen wheels ni se verificó una instalación sin conexión. El lock existente se mantuvo idéntico; su comentario histórico sobre no haber sido instalado no describe el resultado posterior aquí registrado.

Se comparte el mismo sistema operativo y Python base instalado en este equipo. Es una instalación nueva de las dependencias, no una máquina virtual limpia ni un segundo equipo físico.

## Rendimiento y guardas

Antes de cada lote se exigieron al menos 4 GiB de RAM disponible y, al comenzar, 5 GiB de disco libre. Se fijaron **120 s y 1,5 GiB RSS por árbol de proceso**. El supervisor mide lanzador y descendientes cada 50 ms, y finaliza únicamente su árbol si supera el presupuesto. No se aumentaron límites de la aplicación ni timeouts PCAP. Ningún caso final alcanzó las guardas.

| Filas | Bytes CSV | Carga del modelo (s) | Clasificación y scores (s) | Escritura final SQLite (s) | Reporte CSV/JSON (s) | Pico RSS del árbol (MiB) |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 1.541 | 0,092 | 0,094 | 0,013 | 0,013 | 259,4 |
| 100 | 14.961 | 0,085 | 0,090 | 0,014 | 0,016 | 261,6 |
| 1.000 | 149.258 | 0,134 | 0,158 | 0,021 | 0,049 | 256,6 |
| 10.000 | 1.499.259 | 0,105 | 0,564 | 0,095 | 0,494 | 267,0 |
| 50.000 | 7.539.259 | 0,111 | 1,787 | 0,424 | 1,673 | 380,3 |

Se usaron procesos nuevos por lote, sin purgar las cachés del sistema operativo. El tiempo total del proceso de 50.000 filas, incluidos imports, fue 11,83 s; la inferencia total con carga, validación y persistencia fue 3,64 s. El parseo CSV tomó 0,71 s, la consulta SQLite 0,24 s y la base ocupó 5.455.872 bytes. El JSON generado ocupó 25.823.690 bytes. Los tiempos por etapa no se deben sumar con otros que ya los incluyen.

El arranque del launcher hasta HTTP de salud tardó 2,81 s; el reinicio 2,80 s. La copia del ZIP fuera del proyecto arrancó en 2,26 s. Son tiempos hasta salud HTTP, no una medición completa del navegador hasta terminar el renderizado. La carga del modelo se mide por separado. [Arranque inicial](servidor_inicio.json), [reinicio](servidor_reinicio.json), [arranque externo](arranque_externo.json).

10.000 filas se eligió como lote de referencia offline razonable para este ensayo; no se conoce todavía una carga real de despliegue. 50.000 es exploratorio. Su CSV de 7,2 MiB evita acercarse innecesariamente a 100 MiB. El RSS externo es una suma conservadora de procesos y puede contar memoria compartida; no equivale a memoria física única. La medición de reportes reproduce las funciones y el formato existente, sin medir la transferencia ni el renderizado frontend.

En 50.000 filas se persistieron las **25.000 alertas esperadas**. La lista del JSON contiene las 10.000 permitidas y declara truncamiento; conserva las 50.000 predicciones por registro. Los archivos sintéticos repiten ocho patrones de entrada con IDs nuevos y contrastan clases y scores contra el modelo original. No son tráfico capturado, etiquetas de verdad terreno ni una estimación de recall/precisión.

Se conservaron dos pasos preliminares: [piloto de memoria invalidado](rendimiento_001/NO_USAR_COMO_MEDICION_FINAL.json), que observaba solo el redirector de Python en Windows, y [medición intermedia](rendimiento_002/resultados.json), con RSS corregido y serialización compacta. La [medición definitiva](rendimiento_003/resultados.json) observa el árbol completo y reproduce el formato de reporte de la interfaz. Ninguna corrección afectó al software del proyecto ni a sus resultados anteriores.

## Pruebas del producto distribuido

Se ejecutaron siete pruebas de aceptación en tres ubicaciones: carpeta de entrega, copia con espacios y extracción final fuera del proyecto. Son **los mismos siete casos repetidos**, no 21 casos distintos:

1. Versiones, aislamiento e identidad de rutas de importación.
2. Carga del modelo, dos inferencias reproducibles y SQLite consultada desde otra conexión.
3. Streamlit AppTest con inferencia/persistencia reales, tabla, métricas y CSV/JSON contrastados.
4. CSV vacío, estructura desplazada y esquema incompatible, sin ejecuciones creadas.
5. Backup/restauración de historial y revisión; destino existente rechazado sin sobrescritura.
6. Base corrupta rechazada antes de crear el destino.
7. Manifiesto correcto aceptado y archivo alterado rechazado.

AppTest sustituye exclusivamente el transporte de subida y los widgets de descarga. Las comprobaciones de navegador real no emplean esos mocks: se subió el CSV incluido, se ejecutó y se revisó una alerta. Cuatro exportaciones reales por HTTP —predicciones CSV, reporte JSON, historial CSV y alertas CSV— coinciden con el oráculo y SQLite. La revisión `false_positive` conservó clase y score y sobrevivió al reinicio. El CSV de alertas exporta el estado interno `false_positive`; la pantalla lo presenta como «Falso positivo». [Verificación del navegador](navegador_final.json), [exportaciones](browser_descargas.json), [CSV de alertas tras reinicio](browser_export_alertas_reinicio.csv).

El ZIP definitivo también se extrajo **fuera de la carpeta de desarrollo**, en una ruta con espacios. Se verificaron sus 24 archivos, se ejecutaron los mismos siete casos y se inició su propio launcher desde un directorio externo. Un segundo análisis en navegador confirmó ocho registros, cuatro alertas y la SQLite nueva situada en esa extracción. No se usaron rutas de usuario codificadas en el paquete: el intérprete del entorno nuevo se proporcionó explícitamente mediante el parámetro soportado del launcher. [Resultado externo](pruebas_externo_001/resultados.json), [navegador externo y SQLite](navegador_externo_final.json), [identidad de extracción](paquete_final.json).

La suite completa existente se ejecutó también con el entorno nuevo: **235 aprobadas, salida 0**, 70,55 s incluyendo descubrimiento en esta ejecución. [Log](suite_235.log), [resultado](suite_235.json). Sus pruebas preexistentes pueden ajustar modelos diminutos temporales; no se entrenaron ni reemplazaron artefactos del proyecto. Los servidores de prueba quedaron detenidos y las evidencias conservadas.

## Integridad final y limitaciones

La [verificación final](integridad_final.json) confirmó **1.743 archivos previos idénticos, cero modificados y cero desaparecidos**. Ese inventario incluye respaldos y restauraciones anteriores; no equivale a 1.743 archivos de código. Las tres SQLite originales conservan sus bytes y devuelven `integrity_check = ok`; sus huellas lógicas coinciden con el respaldo. Los cuatro runs PCAP conservan 49 archivos y 12 modelos cada uno: 196 archivos y 48 modelos intactos. Dataset, etiquetas, auditoría, extractor, importador, particiones, umbrales y resultados anteriores permanecen sin cambios.

La entrega técnica satisface el recorrido comprobado en este equipo. Permanecen las siguientes limitaciones explícitas:

- No se probó en otro equipo físico, otro Windows/Python ni bajo políticas corporativas distintas.
- La instalación requiere acceso a los repositorios externos indicados; no es una distribución offline ni incluye el instalador de Python.
- El máximo de entrada de 100 MiB es una validación existente; no se certificaron ese tamaño, concurrencia sostenida, latencia en equipos distintos ni carga real de un despliegue.
- El historial tiene ventanas de consulta y exportación de 100 ejecuciones/10.000 alertas. La lista JSON de alertas puede ser parcial y lo declara.
- Joblib exige procedencia confiable; los hashes detectan cambios, pero no autentican por sí solos al editor. No se realizó un análisis de vulnerabilidades de las dependencias.
- No hay autenticación, captura en vivo ni detector PCAP operativo. El modelo CSV conserva las limitaciones de generalización que tuviera; estas pruebas no vuelven fiables sus predicciones en redes reales.

No quedó un defecto reproducido que impida instalar y demostrar esta entrega en el entorno comprobado. No fue necesario cambiar código operativo en esta fase. No se eliminaron ni movieron archivos originales, no se añadieron funcionalidades de detección y no se redactó documentación académica ni guiones de defensa.
