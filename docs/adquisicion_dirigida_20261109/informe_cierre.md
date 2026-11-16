# Cierre de adquisición dirigida: Somfy-01 y Muhstik 3-1

9 de noviembre de 2026. Fechas y horas de evidencia en UTC.

**Somfy-01: RECHAZADO. Muhstik 3-1: RECHAZADO. Cero filas incorporadas al corpus y ningún modelo entrenado con estas capturas.** Ambos pares se descargaron completos y se procesaron hasta el final con el extractor, importador y auditor existentes. No hubo que aumentar límites ni dejar una fase pendiente.

La adquisición sí resolvió la incertidumbre de selección: las capturas contienen intercambios TCP, pero estos quedan excluidos por las reglas actuales de integridad. Los datos admitidos no cumplen la diversidad mínima. Conservar decenas de miles de SYN de Muhstik agravaría la concentración observada en Hakai.

## Protección previa y conservación

Antes de cualquier descarga se verificaron los 657 archivos registrados por el cierre anterior y sus **240 comprobaciones de hashes canónicos**. El nuevo inventario protege **658 archivos preexistentes**; excluye únicamente entorno virtual, cachés y las adiciones de esta etapa. Se preservaron las cuatro ejecuciones PCAP v1, con 49 archivos cada una, incluyendo todos los modelos, métricas, manifiestos y la evidencia de corrección numérica.

El [respaldo nuevo](../../_backups/pre-directed-acquisition-20261109T143106Z-550118eb.zip) ocupa **80.846.424 bytes**. SHA-256: `3f966cf4ea7214fb28bd2c16e4bb73834d71d92fed33d052608c4ce5841cd0ba`. Se comprobó CRC y se restauraron realmente **450 archivos** con hashes verificados; los respaldos anteriores permanecen separados y protegidos. Las tres SQLite restauradas pasaron integridad y comparación lógica con sus fuentes. [Evidencia del respaldo](./respaldo_verificado.json).

Se documentó una [incidencia del auxiliar nuevo de respaldo](./incidencia_respaldo.json): una conexión a una SQLite temporal quedó abierta al limpiar el directorio temporal. Se corrigió el cierre explícito de conexiones en ese auxiliar y se restauró/verificó el ZIP ya completo. No se modificó ningún componente original ni se inició una descarga antes de completar la protección.

Había aproximadamente 277 GiB libres en disco y más de 10 GiB de RAM disponible. Antes de Muhstik se comprobaron nuevamente recursos; la pasada completa de conteo estimó **83.609 flujos y un máximo de 299 activos**. Los resultados reales coincidieron. La previsión de memoria fue 5.491.755.500 bytes frente a 11.765.100.544 disponibles; se reservaron 6 GiB de disco para procesamiento y evidencia. Esa reserva de planificación no cambia ningún límite del software. [Viabilidad documentada](./viabilidad_muhstik.json).

Se mantuvieron TCP idle 120 s, UDP idle 30 s, duración activa 300 s, TShark 120 s, un millón de paquetes, 50.000 flujos activos y 100.000 flujos totales. El auditor mantuvo PCAP clásico Ethernet, 128 MiB y un millón de tramas; extractor 1.0.1 y 38 características. TShark: 4.6.9.

## Adquisiciones completas y trazables

Solo se solicitaron cuerpos de datos de los cuatro archivos autorizados, desde los directorios oficiales de [Somfy-01](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/) y [Muhstik 3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/). Las URLs exactas, cabeceras HEAD/GET, ETag, TLS verificado y tamaños están en los manifiestos de [Somfy](../../data/raw/iot23_somfy_7_1_01/provenance.json) y [Muhstik](../../data/raw/iot23_muhstik_3_1/provenance.json). No se descargaron binarios de malware, prefijos ni recortes.

| Archivo | Obtención UTC | Bytes | SHA-256 |
|---|---|---:|---|
| PCAP Somfy-01 | 14:34:44 | 2.094.105 | `0ec756ff0e26fc6c7d985178a35206bd7bc5b8a33cc5c7a23d6bb0b103db2a2a` |
| Etiquetas Somfy-01 | 14:34:45 | 18.024 | `fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830cc` |
| PCAP Muhstik 3-1 | 14:37:14 | 57.919.772 | `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b` |
| Etiquetas Muhstik 3-1 | 14:37:27 | 24.383.537 | `9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0` |

Se exigió igualdad entre tamaños anunciados y recibidos, ETag estable y hashes locales verificados. El lector independiente recorrió los dos PCAP completos hasta EOF: formato Ethernet PCAP 2.4, registros completos y orden temporal válido. La extracción TShark también terminó correctamente sobre todos los paquetes. Esto comprueba el archivo recibido, no ausencia de pérdidas en el sensor original. Tampoco demuestra identidad con el archivo completo de Zenodo, que no se descargó.

Somfy contiene **130 referencias reales**, frente a 139 en el resumen del editor; Muhstik contiene **156.103**, frente a 156.104 en otro resumen. Se conservaron esas discrepancias, sin crear referencias faltantes. El alias original `benign` de Somfy se normalizó con la regla existente.

## Resultados de extracción y auditoría

Las etiquetas admitidas proceden exclusivamente del auditor v2; las anotaciones del editor y los comportamientos físicos de casos excluidos se conservan separados de cualquier etiqueta utilizable.

| Medida | Somfy-01 | Muhstik 3-1 |
|---|---:|---:|
| Paquetes del archivo | 8.276 | 496.959 |
| Paquetes aceptados por el extractor | 6.174 | 489.567 |
| Paquetes fuera de alcance del extractor | 2.102 | 7.392 |
| Flujos extraídos | 36 | 83.609 |
| Grupos de conexión observados | 22 | 82.801 |
| Flujos admitidos Benign / Malicious | 21 / 0 | 13 / 73.385 |
| Grupos admitidos Benign / Malicious | 21 / 0 | 13 / 73.385 |
| Correspondencias rechazadas | 0 | 156 |
| Flujos pendientes o en cuarentena | 15 | 10.055 |
| Referencias Zeek totales | 130 | 156.103 |
| Referencias utilizadas Benign / Malicious | 28 / 0 | 13 / 145.558 |
| Referencias no admitidas | 102 | 10.532 |
| Cobertura global de referencias | 21,54 % | 93,25 % |
| Paquetes con etiqueta admitida | 335 | 290.668 |
| Cobertura de paquetes aceptados por extractor | 5,43 % | 59,37 % |
| Cobertura de todos los paquetes del archivo | 4,05 % | 58,49 % |
| Referencias TCP bidireccionales objetivo | 1 | 5.969 |
| Referencias objetivo verificadas y representadas completamente | 0 | 0 |
| **Cobertura objetivo** | **0 %** | **0 %** |

Los grupos son componentes de referencias definidos por el auditor, no ataques independientes. Una partición puede reunir varias referencias compatibles; una conexión puede producir varios segmentos. No se equiparan filas, referencias Zeek y grupos.

**Somfy:** 19 flujos admitidos son UDP y dos TCP, en 19 y dos grupos respectivamente. Los dos TCP solo contienen 18 paquetes FIN/ACK unidireccionales, sin payload. La cuarentena comprende un segmento con checksum de transporte parcial y otros 14 segmentos de su mismo grupo que no satisfacen la conservación completa de la referencia. De las referencias no admitidas, 101 son ajenas al alcance IPv4 TCP/UDP y una presenta `partial_omission_not_demonstrated`. El extractor excluyó 2.012 paquetes por payload Ethernet no soportado, 85 por enlace no soportado y cinco por protocolo de transporte.

**Muhstik:** los 73.385 flujos/grupos Malicious admitidos son todos TCP SYN puro; los 13 Benign son UDP unidireccionales. Hay 10.048 flujos en `quarantined_incorrect_checksum`, siete en `counter_mismatch`, 41 correspondencias contradictorias o con etiquetas de referencia incompatibles y 115 sin referencia encontrada. Las referencias no admitidas se desglosan en 9.277 con `incorrect_checksum_evidence`, 1.207 fuera de alcance y **48 verificadas que no terminan en flujos admitidos**. Verificación de referencia y admisión de un flujo no son equivalentes. El extractor excluyó 5.658 paquetes por payload Ethernet no soportado y 1.734 por protocolo de transporte.

## Banderas, establecimiento y sesgo de exclusión

Conteos de paquetes TCP dentro del alcance del extractor, separados de los admitidos:

| Captura / vista | Paquetes TCP | SYN | ACK | FIN | RST |
|---|---:|---:|---:|---:|---:|
| Somfy observado | 5.857 | 4 | 5.855 | 18 | 0 |
| Somfy admitido | 18 | 0 | 18 | 18 | 0 |
| Muhstik observado | 488.060 | 306.278 | 187.057 | 12.515 | 3.402 |
| Muhstik admitido | 290.643 | 290.643 | 0 | 0 | 0 |

Un paquete puede tener varias banderas; las columnas no son clases exclusivas. Payload significa longitud observada de datos TCP, incluidos bytes cifrados, sin inferir éxito de aplicación.

La conexión excluida de Somfy contiene **5.839 paquetes**, con 3.137/2.702 por dirección y **949.928/358.214 bytes de payload**. Se observa una secuencia SYN/SYN-ACK/ACK compatible y datos; los frames de apertura conservados son 437/439/440. Aun así, la evidencia no permite omitir el paquete parcial conservando la referencia según la política actual. No se admitió ninguno de sus 15 segmentos.

En Muhstik quedan fuera **8.561 grupos TCP bidireccionales**; 6.077 presentan payload en ambos sentidos y 6.101 muestran establecimiento observado seguido de datos. Estos conteos describen bytes excluidos, sin convertirlos en ejemplos etiquetados. **Las 5.969 referencias Malicious bidireccionales objetivo tienen estado `incorrect_checksum_evidence`.**

Una [comprobación independiente de las cabeceras IPv4](./diagnostico_checksum_ipv4_muhstik.json) recorrió todo el PCAP y confirmó **102.973 paquetes con checksum IPv4 inválido, todos con valor almacenado cero**. El resumen de checksums de transporte registra 489.549 válidos y 18 parciales: eso no implica validez de la cabecera IPv4. No puede distinguirse únicamente con estos bytes entre offloading, transformación de captura o corrupción en origen. No se repararon bytes, características ni etiquetas.

Este es el sesgo decisivo: la auditoría excluye precisamente el intercambio que se buscaba y conserva los SYN fáciles. La cobertura global del 93,25 % en Muhstik encubre una cobertura objetivo del 0 %. El denominador dirigido incluye todas las referencias TCP de la clase objetivo con paquetes reportados y observados en ambas direcciones, aunque fallen la auditoría. No hubo referencias objetivo de dirección indeterminable; ninguna se eliminó para mejorar la tasa.

## Decisiones independientes

| Criterio | Somfy-01 | Muhstik 3-1 |
|---|---|---|
| Archivo completo y procesamiento viable sin cambios | Sí | Sí |
| Cinco grupos TCP benignos bidireccionales admitidos | **0: falla** | No es su criterio de aceptación |
| Un grupo benigno con payload en ambos sentidos | **0: falla** | No es su criterio de aceptación |
| Cinco grupos maliciosos distintos de SYN puro | No aplica | **0: falla** |
| Tres grupos maliciosos bidireccionales | No aplica | **0: falla** |
| Uno con establecimiento e intercambio de datos admitidos | No aplica | **0: falla** |
| Cobertura objetivo mínima del 80 % | **0 %: falla** | **0 %: falla** |
| **Decisión** | **RECHAZADO** | **RECHAZADO** |

Somfy se cerró a las 14:36 UTC aproximadamente, antes de decidir la descarga de Muhstik a las 14:36:50 UTC. Las decisiones y sus grupos/referencias completos están en [Somfy](./decision_somfy.json) y [Muhstik](./decision_muhstik.json). Ambos tienen `corpus_rows_added: 0`; los informes admitidos se conservan como diagnóstico, no como una ampliación aprobada.

Comparación con PCAP v1, por grupos TCP admitidos:

| Captura | Benign bidireccional | Benign payload en ambos sentidos | Malicious SYN puro | Malicious otro comportamiento |
|---|---:|---:|---:|---:|
| Torii 20-1 | 0 | 0 | 4 | 2 |
| Hakai 8-1 | 0 | 0 | 2.056 | 0 |
| Hue 4-1 | 49 | 7 | 0 | 0 |
| Somfy-01, diagnóstico rechazado | 0 | 0 | 0 | 0 |
| Muhstik 3-1, diagnóstico rechazado | 0 | 0 | 73.385 | 0 |

Ningún candidato resuelve A o B con datos admitidos. Muhstik repetiría y multiplicaría la limitación de Hakai. El RF de PCAP v1 conserva su resultado negativo y no queda justificada su integración como detector.

## Recursos, pruebas y cierre

| Medida | Somfy-01 | Muhstik 3-1 |
|---|---:|---:|
| Adquisición s | 4,99 | 37,79 |
| Validación íntegra e importación s | 0,31 | 29,88 |
| Conteo previo s | 0,91, validado contra extracción ya terminada | 23,01, antes de extracción |
| Extracción + auditoría s | 5,66 | 168,62 |
| Análisis y decisión s | 0,19 | 30,11 |
| Pico RSS muestreado del proceso/árbol durante extracción y auditoría | 46,0 / 135,0 MiB | 3,41 / 3,41 GiB |
| Pico de working set del SO durante análisis | 57,3 MiB | 3,74 GiB |
| Archivos raw, con procedencia | 2.118.289 B | 82.309.301 B |
| Extracción + importación + auditoría | 11.037.002 B | 1.715.591.732 B |

Las muestras RSS se tomaron con intervalo objetivo de 20 ms: no son un pico exacto. Working set del SO y máximo RSS muestreado son medidas distintas. El análisis detallado e importación previa conservan evidencia adicional en esta carpeta; el inventario final incluye su espacio y hashes. El tiempo de TShark de la extracción mantuvo su límite de 120 s; los 168,62 s incluyen además serialización y auditoría Python, que no tienen ese timeout.

**145 pruebas específicas y 229 de la suite completa aprobadas**, cero fallos, errores u omisiones. Las específicas incluyen 13 comprobaciones nuevas del análisis, adquisición completa y criterios de exclusión; el resto prueba los componentes existentes. Los conteos se solapan con la suite completa y no deben sumarse como pruebas distintas. [Resultados específicos](./pruebas_specific.json), [suite completa](./pruebas_full.json). La suite original contiene ajustes sobre fixtures sintéticos temporales; no se entrenaron modelos con datos reales del proyecto o con las nuevas capturas y no se reemplazó ningún modelo conservado.

La [verificación final](./integridad_final.json) comprueba nuevamente los **658 archivos protegidos**, las 240 comprobaciones canónicas, el respaldo y su restauración, los hashes de los pares nuevos y sus resultados, y las tres SQLite en modo de solo lectura. Mantiene intactos el umbral 0,5, particiones, métricas anteriores, 38 características, extractor, importador, auditor, Streamlit y modelo CSV. Mirai 34-1 y Amazon Echo 5-1 no se solicitaron ni utilizaron.

**Se cierra la selección autorizada con dos candidatos rechazados. No adquirir más escenarios ni incorporar estos flujos al corpus.** El paso justificable es continuar las pruebas y estabilización del sistema con su alcance existente, manteniendo este RF fuera de la integración como detector. Cualquier revisión futura del tratamiento de checksums o de la verdad de referencia sería otro experimento, con autorización y validación independientes; esta etapa no la implementa.
