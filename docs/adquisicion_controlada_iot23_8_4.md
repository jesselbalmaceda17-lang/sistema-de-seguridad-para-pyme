# Adquisición controlada IoT-23: Hakai 8-1 y Philips Hue 4-1

Fecha de ejecución: 8 de noviembre de 2026, horas de las evidencias en UTC.

**Recomendación: resolver primero la compatibilidad de las etiquetas de Philips Hue, con una propuesta revisada antes de tocar la lógica.** La adquisición y el procesamiento completo de ambos PCAP funcionan. Hakai aporta correspondencias verificadas; Philips Hue permanece íntegramente sin etiqueta. No se entrenó un modelo PCAP ni se construyó una tabla definitiva para entrenamiento.

## 1. Protección y alcance

La evidencia anterior contiene 163 pruebas aprobadas, cero fallos y cero omitidas; se verificaron sus hashes y el cierre de su registro. No existe un repositorio Git en el proyecto: no se creó uno ni se simuló un estado limpio. Se cotejaron 109 entradas de las evidencias anteriores, incluidos los cuatro respaldos existentes.

Antes de añadir archivos se creó [el respaldo de esta etapa](../_backups/pre-controlled-iot23-20261108T175432Z-c9e45e9c.zip):

- Tamaño: **36.572.246 bytes**.
- SHA-256: `42945a50a04a92813311795561e9bb84901e8f6b26bf626af95bd7e773976606`.
- 106 archivos previos, excluyendo entorno virtual, cachés y respaldos anteriores, que se conservaron por separado.
- CRC y hashes de todos los contenidos verificados; restauración real en un directorio temporal; integridad de las tres bases SQLite restauradas comprobada.
- SQLite se respaldó mediante su API de copia consistente. La copia de la base principal tiene distinto hash físico, pero el volcado SQL completo de cada una de las tres bases restauradas coincide con el de su fuente. Los originales no cambiaron. No se confunde identidad lógica con identidad binaria.

Evidencias: [respaldo y restauración inicial](validacion_adquisicion_iot23_8_4/respaldo.json), [verificación lógica adicional de SQLite](validacion_adquisicion_iot23_8_4/restauracion_sqlite_logica.json), [integridad final de los 106 originales](validacion_adquisicion_iot23_8_4/integridad.json).

Se mantuvieron el extractor **1.0.1**, el esquema de **38 características**, sus fórmulas, orientación y timeouts, el importador y la auditoría v2. Tampoco se modificaron Streamlit, SQLite, CSV, Random Forest ni los resultados anteriores. No se instalaron dependencias, no se capturó una interfaz y no se adquirieron otros escenarios.

## 2. Procedencia y adquisición limitada

Se contrastaron los índices oficiales de cada escenario y de su subdirectorio de etiquetas, sus README y, para Hue, el informe de captura publicado. Se preservaron textos, URLs, cabeceras HEAD, fechas de consulta y hashes en [preflight](validacion_adquisicion_iot23_8_4/preflight.json). Antes del primer GET de datos, las cuatro URLs respondieron HTTP 200 y confirmaron sus tamaños; había **297.975.226.368 bytes libres**, frente a una reserva preventiva de 512 MiB para esta ejecución pequeña.

La [documentación oficial de IoT-23](https://www.stratosphereips.org/datasets-iot23) identifica los escenarios y señala que las etiquetas finales se distribuyen como `bro/conn.log.labeled`. La referencia bibliográfica es García, Parmisano y Erquiaga, IoT-23, versión 1.0.0, [Zenodo](https://zenodo.org/records/4743746). Se adquirió una instantánea de `IndividualScenarios`; **no se comprobó identidad byte a byte con el archivo completo de Zenodo**, que no se descargó. Los índices públicos pueden cambiar; por eso se fijan los hashes concretos de esta ejecución.

| Escenario / archivo oficial | Tamaño descargado, bytes | Obtención/verificación UTC |
| --- | ---: | --- |
| Hakai [PCAP](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap) | 2.098.362 | 17:59:47 |
| Hakai [etiquetas Zeek](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled) | 1.431.000 | 17:59:50 |
| Hue [PCAP.XZ](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz) | 376.840 | original 17:59:52; nueva verificación 18:01:41 |
| Hue [etiquetas Zeek](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled) | 61.653 | original 17:59:53; nueva verificación 18:01:42 |

Los pares suman **3.967.855 bytes** de datos descargados. Un fallo previo a persistir los metadatos de transporte de Hue requirió volver a obtener sus mismos dos archivos: se verificó igualdad exacta y se conservaron los primeros originales. Fueron **438.493 bytes adicionales**, para **4.406.348 bytes de cuerpos de datos recibidos** en total, sin contar los pequeños documentos e índices de procedencia. No se solicitó ningún otro conjunto de datos.

Hashes SHA-256 completos:

| Contenido conservado | SHA-256 |
| --- | --- |
| Hakai PCAP | `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2` |
| Hakai etiquetas | `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a` |
| Hue XZ original | `bc5a57306d9a5f614b09d9c0976f007667fee5b6de3427fbab094fa3084b9b64` |
| Hue PCAP descomprimido sin cambios | `3fb775c0391b6ad313a3f7845e634a277b07c3f6377346c2486ba63e1c22e90c` |
| Hue etiquetas | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` |

Los manifiestos de [Hakai](../data/raw/iot23_hakai_8_1/provenance.json) y [Hue](../data/raw/iot23_hue_4_1/provenance.json) vinculan el PCAP efectivo, el log original y su procedencia. Hue conserva además [el transporte verificado](../data/raw/iot23_hue_4_1/acquisition_transport.json), el XZ y la derivación del PCAP de **4.594.492 bytes**.

### Descompresión y discrepancia del informe oficial de Hue

El XZ declara un diccionario LZMA2 de **64 MiB**, propiedad `0x1c`. El primer límite de 64 MiB no alcanzó para diccionario más decodificador y produjo `LZMAError: Memory usage limit exceeded`. Se registró y justificó un límite de **96 MiB exclusivamente para descompresión**, con salida máxima de **16 MiB**. Ningún límite del extractor o del auditor cambió. Se exige fin de flujo XZ, ausencia de datos sobrantes o concatenados, integridad del flujo, formato PCAP y hash esperado; no se sobrescriben archivos. Los intentos fallidos no dejaron un PCAP parcial.

El [capinfos oficial de Hue](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.capinfos) anuncia SHA-256 `f770897e6cc3fa45857aee25ef7d3ab39dba39127b5bb813e0e0d48d3b905347` y snaplen 262144. El archivo adquirido declara snaplen 65535. **Se probó criptográficamente que la diferencia se limita a los cuatro bytes del campo snaplen en la cabecera global**: cambiar solo esos bytes en una copia en memoria reproduce exactamente el hash publicado. No se escribió esa copia. El archivo real y todos sus paquetes permanecen sin modificar. Esta prueba permite continuar la lectura de los mismos registros de paquetes sin afirmar identidad binaria de los archivos completos.

El ejecutor nuevo también corrigió una suposición inicial sobre la existencia de un capinfos para Hakai: la URL dio 404 y el índice confirmó que no se publica allí. Se usa su índice y README. Estos incidentes de preparación y sus soluciones están en [incidencias](validacion_adquisicion_iot23_8_4/incidencias.json); no son fallos del extractor ni de las pruebas automatizadas.

## 3. Procesamiento completo y censo

Ambos archivos son **PCAP clásico sobre Ethernet**, admitido por la auditoría v2 sin adaptación. TShark **4.6.9**, invocado por ruta absoluta, leyó todos los frames con código de salida 0 y stderr vacío. Una lectura independiente de números de frame coincide con el total visto por el extractor. Se procesaron las capturas completas, sin filtros para recortarlas.

Se usó la configuración original: TCP idle 120 s, UDP idle 30 s, duración activa 300 s, timeout TShark 120 s, máximo 1.000.000 paquetes, 50.000 flujos activos y 100.000 flujos; lector de evidencia con sus límites originales de 128 MiB y 1.000.000 frames. No fue necesario elevarlos.

Resultados del [censo reproducible](validacion_adquisicion_iot23_8_4/censo.json):

| Medida | Piloto 20-1 anterior | Hakai 8-1 | Hue 4-1 |
| --- | ---: | ---: | ---: |
| Paquetes vistos | 50.156 | 23.623 | 21.664 |
| Paquetes aceptados por extractor | 41.207 | 16.677 | 16.921 |
| Paquetes rechazados por extractor | 8.949 | 6.946 | 4.743 |
| Flujos extraídos | 3.499 | 4.237 | 2.200 |
| Registros Zeek importados | 3.209 | 10.403 | 452 |
| Flujos admitidos con etiqueta | 3.495 | 4.237 | 0 |
| Flujos Benign admitidos | 3.207 | 2.181 | 0 |
| Flujos Malicious admitidos | 288 | 2.056 | 0 |
| Flujos rechazados terminalmente por auditor | 0 | 0 | 0 |
| Flujos pendientes/en cuarentena | 4 | 0 | 2.200 |
| Referencias representadas por admisiones | 3.206 | 10.403 | 0 |
| Cobertura de flujos | 99,8857 % | 100 % | 0 % |
| Paquetes en flujos etiquetados | 40.921 | 16.677 | 0 |
| Cobertura de paquetes aceptados | 99,3059 % | 100 % | 0 % |
| Cobertura de todos los frames | 81,5874 % | 70,5965 % | 0 % |

Todos los rechazos de los tres escenarios son ARP, EtherType 2054, fuera del contrato IPv4 TCP/UDP; no son pérdidas silenciosas ni descartes por etiqueta. La captura de Hakai abarca **86.395,260731 s** y la de Hue **78.846,399363 s**. La pérdida previa a la captura sigue siendo desconocida: un PCAP no demuestra que la red haya sido capturada sin pérdidas.

### Hakai: correspondencia comprobada

La auditoría admite **2.181 coincidencias únicas** y **2.056 particiones completas de varias referencias**. Todas las 10.403 referencias conservan exactamente sus contadores; no hay ambiguas, contradictorias o pendientes. Los 16.677 paquetes aceptados tienen checksum de transporte válido.

No se confundieron 8.222 referencias maliciosas con 8.222 muestras independientes. Las referencias `Malicious / C&C` se agrupan en **2.056 grupos de conexión**; las benignas, en **2.181 grupos**. Por ejemplo, el flujo `a32423d62e2e6c02a36b196587005ff09594141ab26f3c197107fb0af1c03bad` contiene los frames `[488,489,492,495,496,497]`. Su partición preserva los UID originales:

| UID Zeek | Línea | Paquetes origen/respuesta |
| --- | ---: | ---: |
| C3eDKm2wnG96wuJNmc | 122 | 3 / 0 |
| CXvCbu3NTeD2RtprBf | 123 | 1 / 0 |
| CWLEgx2cATV7S4aOs9 | 124 | 1 / 0 |
| Cz9a0Z2la2afXQNJr7 | 125 | 1 / 0 |

La unión es completa y exclusiva, con etiquetas originales y detalladas compatibles. La duración desconocida de las referencias de un solo paquete se conserva como desconocida; su soporte puntual procede del contador de un paquete, según la regla existente.

### Hue: bloqueo de compatibilidad; ninguna etiqueta añadida

Los **452 registros originales** usan literalmente `benign`, no `Benign`. El [importador existente](../seguridad_pymes/zeek_labels.py) reconoce solo `Benign` y `Malicious`; conserva `benign`, señala `unrecognized_label` y devuelve etiqueta binaria nula. No hubo filas rechazadas ni contradicciones detectadas, y el log tiene marcador de cierre. El número 452 es el contenido real importado, no un número ajustado a tablas históricas del dataset.

La auditoría devuelve **2.193 flujos `incomplete_reference` y siete `quarantined_partial_checksum`**. Hay **nueve paquetes** con patrón de checksum parcial, frames `[7755,14676,15673,19636,19642,19690,20640,20954,20955]`, y 16.912 con checksum válido. No se equipara ese patrón parcial con un checksum realmente incorrecto. Todos siguen en el PCAP y en sus características; ningún flujo recibe una etiqueta por ser una captura denominada benigna.

La comprobación diagnóstica de candidatos, sin modificar objetos del auditor ni normalizar etiquetas, encontró **359 referencias cuyos contadores y límites temporales coinciden** y **93 con discrepancias adicionales**. Incluye todos los estados de checksum: **359 no es una proyección de referencias admisibles ni de cobertura recuperable**. El auditor actual no realiza la conservación completa de esas referencias porque la etiqueta ya es desconocida. Véanse [diagnóstico completo de candidatos](validacion_adquisicion_iot23_8_4/diagnostico_hue.json) y [trazas TCP](validacion_adquisicion_iot23_8_4/diagnostico_hue_tcp.json).

Entre las 93 diferencias, 44 carecen de un paquete de origen de 40 bytes en el soporte candidato, 40 de uno de respuesta de 40 bytes y nueve presentan otras diferencias. Esto se midió como «esperado menos observado en candidatos únicos», no como prueba de pérdida de paquetes. Ejemplos:

- UID `CGQf8t1kjdxB5PHXL4`, línea 12, flujo `40a505ceaee251eb7c64a34c33b6c8fd3bda97871bfce1b59e65d4a9d0ce72f8`: Zeek publica fin `1540469831306122000 ns` y contadores 5/3 paquetes, 212/144 bytes IPv4. Los candidatos dentro del soporte suman 4/3 y 172/144. El frame 175 es ACK puro a `1540469831306125000 ns`. Los FIN de los frames 171 y 174 tienen una retransmisión SYN/ACK y otro ACK intermedios; no satisfacen la cadena consecutiva estricta de la regla vigente.
- UID `C0wssT3JKSiAqhCZw`, línea 32, flujo `5e81120a1dd7622dff5e3ee4f8ec1687714d8decc8686dab0d51d66391a9f9c2`: fin Zeek `1540472524941093000 ns`. Esperado 7/7 paquetes, 2139/1823 bytes; candidatos 7/6, 2139/1783. La secuencia es FIN/ACK 874, ACK 875, FIN/ACK 876 y ACK 882 a `1540472524969830000 ns`. La regla existente exige los dos FIN consecutivos para justificar un ACK posterior; aquí hay un ACK intermedio.

Son motivos para una revisión futura, **no autorización para ampliar tolerancias temporales o las reglas FIN/ACK**. No se cambió esa lógica. Las 253 divisiones por duración activa observadas en Hue también se conservaron; no se cambió el timeout de 300 s.

## 4. Diversidad, grupos y sesgo

Distribución **admitida**, no inferida del nombre del escenario:

| Escenario / clase | Flujos TCP | Flujos UDP | Grupos TCP | Grupos UDP |
| --- | ---: | ---: | ---: | ---: |
| Piloto Benign | 1 | 3.206 | 1 | 3.191 |
| Piloto Malicious | 288 | 0 | 6 | 0 |
| Hakai Benign | 2 | 2.179 | 2 | 2.179 |
| Hakai Malicious | 2.056 | 0 | 2.056 | 0 |
| Hue Benign admitido | 0 | 0 | 0 | 0 |
| Hue Malicious admitido | 0 | 0 | 0 | 0 |
| Hue sin etiqueta | 395 | 1.805 | 142 | 310 |

Los 452 registros originales de Hue se reparten en **142 TCP y 310 UDP** y dicen `benign`; ello muestra su interés potencial, pero **no permite incluirlos todavía como ejemplos benignos admitidos**.

El conjunto admitido del piloto y Hakai tiene 5.388 flujos Benign, de los que solo **tres son TCP**, y 2.344 Malicious, todos TCP. Por tanto, la asociación entre protocolo y clase apenas cambia. La cuenta de grupos es 5.373 Benign y 2.062 Malicious, distribuidos entre solo **dos capturas con etiquetas admitidas**. No se calculó desempeño de ningún clasificador.

Además, los **12.334 paquetes maliciosos admitidos de Hakai son SYN sin ACK**, sobre dos pares de hosts. Hay 2.055 flujos de seis paquetes y uno de cuatro. La etiqueta detallada publicada es C&C, pero los paquetes de esta instantánea describen intentos y retransmisiones; no prueban por sí mismos sesiones C&C establecidas. Esto limita qué comportamiento puede aprenderse y qué afirmaciones serían defendibles. Las dos conexiones TCP benignas de Hakai tampoco representan la variedad del TCP normal de una PYME.

[Diversidad y dependencia](validacion_adquisicion_iot23_8_4/diversidad.json) distingue tuplas, pares de hosts, grupos y segmentos. Un grupo de conexión evita separar hermanos, pero **no garantiza independencia estadística**: las conexiones comparten dispositivo, destino, malware, rutina periódica y periodo. Ningún segmento hermano puede cruzar entrenamiento y evaluación. Las capturas completas y, cuando corresponda, familias/dispositivos deben formar particiones externas. En el piloto, dos grupos tienen segmentos admitidos y en cuarentena; sus conteos por estado no se deben sumar como si fueran grupos distintos. No hay grupos con etiquetas binarias admitidas contradictorias en estos tres escenarios.

## 5. Características desconocidas y calidad

Se conservaron las 38 características y sus estados. No se imputó ningún valor. Cada celda `unavailable` continúa como `null` con motivo explícito; los ceros observados válidos siguen siendo ceros.

| Motivo / celdas | Hakai Benign | Hakai Malicious | Hue sin etiqueta |
| --- | ---: | ---: | ---: |
| `not_applicable_to_udp` | 34.864 | 0 | 28.880 |
| `no_packets_in_direction` | 76 | 8.224 | 6.036 |
| `fewer_than_two_packets_in_direction` | 17.448 | 8.224 | 8.408 |

La primera categoría corresponde a banderas TCP no aplicables a UDP; las otras a estadísticas de tamaños sin paquetes en una dirección e intervalos sin dos paquetes. Los motivos se contabilizan por celda, no por flujo. Hay **68.836 celdas desconocidas en Hakai y 43.324 en Hue**, desglosadas por característica, clase y motivo en [el censo](validacion_adquisicion_iot23_8_4/censo.json). Los estados de checksum y las etiquetas desconocidas son calidad del dato/correspondencia, no características añadidas al esquema.

Los campos Zeek ausentes también se preservan: Hakai tiene 6.185 duraciones sin publicar y 2.181 etiquetas detalladas ausentes; Hue tiene una duración ausente y 452 etiquetas detalladas ausentes. Su ausencia no se sustituye por cero ni se trata automáticamente como una contradicción. Las etiquetas proceden del análisis y reglas del autor del dataset; verificar correspondencia no valida de forma independiente su semántica ni las convierte en verdad universal para PYMES.

## 6. Recursos medidos

Entorno real: Windows 11 de 64 bits, Intel i5-1135G7, Python 3.14.6, TShark 4.6.9 y Npcap 1.88. Versiones instaladas preservadas en [entorno](validacion_adquisicion_iot23_8_4/entorno.json). La medición usa procesos Python separados por escenario.

| Recurso | Hakai | Hue |
| --- | ---: | ---: |
| Lectura independiente TShark | 0,6125 s | 0,6447 s |
| Extracción y escritura JSON | 3,1113 s | 2,3145 s |
| Auditoría v2 y escritura JSON | 8,7915 s | 2,4759 s |
| Proceso completo, incluida consulta de versión | 12,7856 s | 5,7123 s |
| CPU del proceso Python | 11,4063 s | 4,4063 s |
| Máximo de working set de Python, medido por Windows | 253.399.040 bytes / 241,66 MiB | 196.190.208 bytes / 187,10 MiB |
| Máximo muestreado de RSS Python + hijos | 219.865.088 bytes | 193.490.944 bytes |
| Almacenamiento raw, incluidos manifiestos y XZ conservado | 3.531.340 bytes | 5.038.549 bytes |
| Almacenamiento procesado | 86.052.682 bytes | 43.477.345 bytes |

El working set máximo del proceso es un contador de máximo del sistema operativo; no incluye memoria de procesos hijos. La suma Python+hijos incluye TShark cuando se observa, con intervalo objetivo de 20 ms: es un **máximo muestreado**, puede omitir picos entre muestras y no debe confundirse con el máximo exacto del árbol. No se midió el máximo de memoria durante la primera descarga. La recuperación/descompresión correcta de Hue registró 42.553.344 bytes de máximo de working set Python y unos 0,0534 s de descompresión; sus intentos anteriores se documentan aparte.

Los tiempos son de una ejecución real, no benchmarks repetidos ni proyecciones para otros tamaños. Los informes JSON de extracción, etiquetas y trazabilidad suman **129.530.027 bytes**: crecen mucho más que el PCAP y son una limitación práctica para corpus grandes. Los nuevos datos y el respaldo suman **174.672.162 bytes**, sin incluir esta documentación y los pequeños registros de validación. No se modificó la representación para optimizar ese tamaño.

Registros completos: [ejecución Hakai](validacion_adquisicion_iot23_8_4/hakai_ejecucion.json), [ejecución Hue](validacion_adquisicion_iot23_8_4/hue_ejecucion.json).

## 7. Pruebas y comprobación final

Se añadieron únicamente [nueve pruebas de compatibilidad y descompresión](../tests/test_iot23_acquisition_compatibility.py):

- Repetición real de extracción y auditoría completa de Hakai y Hue, comparando resultados, 38 definiciones, configuración y todos los registros de correspondencia/paquetes con la ejecución guardada.
- Conservación exclusiva de los frames y particiones de referencias con etiquetas compatibles en Hakai.
- Conservación del literal `benign`, cuarentena completa y nueve checksums parciales en Hue.
- Repetición real de la descompresión Hue y prueba del campo de cabecera que explica el hash oficial.
- XZ válido, truncado, corrupto, concatenado, con basura final, límite de salida, hash incorrecto, contenido no PCAP y prohibición de sobrescribir; pruebas negativas de que el diagnóstico de snaplen no oculta cambios en otros bytes.

Resultados ejecutados en este orden:

| Ejecución | Aprobadas | Fallos | Errores | Omitidas | Duración |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pruebas específicas nuevas | 9 | 0 | 0 | 0 | 9,6385 s |
| Suite completa | **172** | **0** | **0** | **0** | 40,4429 s |

La duración de la tabla incluye descubrimiento e importación de las pruebas. El cronómetro interno de unittest registra 36,638 s para la ejecución de los 172 casos; ambos tiempos figuran en sus evidencias y miden intervalos distintos.

Las nueve están incluidas en las 172; no se suman otra vez. Evidencias: [resultado específico](validacion_adquisicion_iot23_8_4/resultado_especificas.json), [log específico](validacion_adquisicion_iot23_8_4/pruebas_especificas.log), [resultado completo](validacion_adquisicion_iot23_8_4/resultado_completas.json), [log completo](validacion_adquisicion_iot23_8_4/pruebas_completas.log). La suite anterior incluye pruebas de entrenamiento con fixtures pequeños temporales; no se entrenó con las capturas ni se escribió ningún modelo operativo. Una suite verde certifica el comportamiento observado, **no elimina el bloqueo de compatibilidad de Hue ni valida sus etiquetas desconocidas**.

Después de las pruebas se volvieron a verificar los hashes de los **106 archivos originales**, los cuatro respaldos anteriores, el nuevo respaldo y todos los archivos fuente adquiridos. No se modificó ni eliminó ningún original. Las tres bases SQLite superaron `integrity_check` en modo de solo lectura. Entre los componentes protegidos:

| Componente | SHA-256 sin cambios |
| --- | --- |
| [Extractor](../seguridad_pymes/pcap_extract.py) | `0528ed6c3f53d9f88cfcc44a267a690c2fae839757a141ba5d731390610bdd6f` |
| [Esquema y timeouts](../seguridad_pymes/pcap_schema.py) | `e9add5d1d6862bbb12a3c8cb60908e55e8ce95ccefe47f34e0cbb6c9c52e68fb` |
| [Auditor](../seguridad_pymes/label_audit.py) | `151c1c0bc4a6e9644c0524573026269ff8a49a891a9d222360c1d8051d96502c` |
| [Importador Zeek](../seguridad_pymes/zeek_labels.py) | `dbd3c141f1756e6e0819bb9f55c6f0c1ec04970e56558fa3ea88145e6a1e8de6` |
| [Random Forest original](../models/unsw_nb15_random_forest.joblib) | `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9` |

El inventario completo incluye interfaz, CSV, bases, modelos piloto y estudios anteriores. Las pruebas existentes del panel y persistencia pasan; no se levantó una sesión gráfica de Streamlit ni se afirma una validación manual de su interfaz.

## 8. Archivos añadidos, reproducción y reversión

**Archivos preexistentes modificados: ninguno. Eliminados: ninguno.** Se añadieron:

- Este informe y [los ejecutores y evidencias de etapa](validacion_adquisicion_iot23_8_4/).
- [Pruebas nuevas](../tests/test_iot23_acquisition_compatibility.py).
- Los dos pares originales y manifiestos en [raw Hakai](../data/raw/iot23_hakai_8_1/) y [raw Hue](../data/raw/iot23_hue_4_1/), incluido el XZ sin cambios y su PCAP derivado.
- Extracción e informes v2 en [procesado Hakai](../data/processed/iot23_hakai_8_1/) y [procesado Hue](../data/processed/iot23_hue_4_1/).
- El respaldo ya identificado. [Inventario con tamaños y hashes](validacion_adquisicion_iot23_8_4/inventario_final.json) registra cada adición, excluyéndose a sí mismo para evitar un hash autorreferente.

Desde la raíz del proyecto, los comandos realmente utilizados para los pasos completos fueron:

```powershell
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py acquire
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py recover-hue
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py hakai
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/ejecutar_etapa.py hue
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/censar.py
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/pruebas.py especificas
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/pruebas.py completas
.venv\Scripts\python.exe -B docs/validacion_adquisicion_iot23_8_4/cerrar_evidencias.py
```

Las acciones de adquisición inicial y recuperación tuvieron las incidencias descritas, antes de las versiones finales de estos ejecutores. No se ocultan esos intentos. La versión final de adquisición incluye las verificaciones del diccionario y del snaplen; la recuperación solo termina la adquisición interrumpida. **Estos comandos rechazan sobrescribir evidencias**: no se deben ejecutar sobre las mismas salidas esperando reemplazarlas. Para repetir las comprobaciones sobre los datos locales sin descargarlos, ejecutar:

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_iot23_acquisition_compatibility.py -v
.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Para una repetición independiente de adquisición/procesamiento se necesita un directorio de trabajo nuevo con las rutas de salida libres y el entorno disponible. Verificar primero hashes de código, configuración y fuentes; no reutilizar una descarga nueva si difiere de la instantánea fijada sin investigar el cambio. Los ejecutores son de validación de esta etapa, no una nueva funcionalidad del producto.

Reversión: al no haber cambios en originales, no es necesario restaurar ni sobrescribir la base activa. Apartar a una carpeta de conservación únicamente las adiciones del inventario permite retirar esta etapa sin borrar datos. Conservar todos los respaldos. Si se necesita recuperar un original, extraer el respaldo a una carpeta nueva vacía, validar CRC y hashes según su `BACKUP_MANIFEST.json` y comprobar SQLite antes de seleccionar qué restaurar; cerrar la aplicación antes de una eventual sustitución de bases. El entorno virtual y los respaldos anteriores no están dentro del ZIP; permanecen conservados, y las versiones instaladas están documentadas. No se ejecutó ninguna operación destructiva de reversión.

## 9. Decisión técnica y trabajo pendiente

La compatibilidad del lector, extractor y contabilidad de paquetes está demostrada para ambos PCAP clásicos. La correspondencia de Hakai funciona con las reglas existentes. **La compatibilidad de etiquetas de Hue no está resuelta** y la diversidad admitida sigue sesgada hacia UDP benigno y TCP malicioso.

Antes de ampliar el corpus recomiendo:

1. Revisar y autorizar un perfil de importación explícito y versionado que reconozca el literal oficial `benign`, conservando la cadena original, UID, línea, hash y política aplicada. No normalizar cualquier cadena de forma indiscriminada, no inferir etiquetas por IP o escenario y conservar la detección de contradicciones.
2. Reejecutar la auditoría sin cambiar sus reglas. Revisar por frame las 93 diferencias adicionales y los nueve checksums parciales; no prometer recuperación de un número de etiquetas. Mantener en cuarentena lo que no satisfaga la evidencia existente.
3. Si se propone admitir cierres TCP con ACK intermedio o retransmisiones, presentar primero una regla TCP concreta, contraejemplos y conservación de contadores. Su diseño y aprobación son otra etapa; no se implementaron aquí.
4. Solo después de conocer la diversidad realmente admitida de Hue, decidir una ampliación pequeña con tamaños y justificación previos. Mantener intactos los escenarios reservados para prueba final y los grupos/capturas completos al separar evaluaciones.

No hay suficientes capturas etiquetadas diversas para afirmar ahora una evaluación independiente defendible del futuro modelo para PYMES. Tampoco se ha demostrado detección de ataques desde PCAP. Los resultados de esta etapa son una adquisición trazable, un censo comprobado y un diagnóstico que limita expresamente lo que puede usarse como etiqueta.
