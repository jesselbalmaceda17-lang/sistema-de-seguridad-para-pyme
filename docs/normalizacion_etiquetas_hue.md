# Compatibilidad de etiquetas de Philips Hue: corrección mínima y validación

Ejecución: 8 de noviembre de 2026. Los registros usan UTC.

**La normalización documentada recuperó 2.107 flujos Benign de Hue, correspondientes a 359 referencias originales y 15.942 paquetes. Las 93 referencias con discrepancias siguen sin correspondencia admitida. No cambió ninguna regla de la auditoría v2.**

## 1. Respaldo y estado inicial comprobados

Se verificaron los hashes de las evidencias anteriores y el registro de **172 pruebas aprobadas, cero fallos y cero omitidas**. El proyecto sigue sin repositorio Git; no se creó uno ni se simuló un estado limpio.

Antes de modificar archivos se creó [un respaldo recuperable](../_backups/pre-hue-normalization-20261108T190312Z-008f13fb.zip):

- 46.417.122 bytes; SHA-256 `238d0306c576b5edfd8b87cb0aae857388f6a0fa85abf7ae87d35d9e9c45bd0e`.
- 143 archivos previos, excluidos entorno virtual, cachés y respaldos anteriores. Los cinco respaldos anteriores permanecen conservados y verificados.
- CRC y hashes de los contenidos comprobados; extracción real a un directorio temporal y verificación de todos los archivos restaurados.
- Las tres bases SQLite se copiaron mediante su API de respaldo consistente. Su restauración pasó `integrity_check` y el hash del volcado SQL completo coincide con la fuente. La identidad lógica se verificó aparte de los hashes físicos del archivo serializado.

La evidencia completa está en [respaldo](validacion_normalizacion_hue/respaldo.json). No se descargaron datos ni se modificaron PCAP, XZ, etiquetas originales o informes históricos.

## 2. Diagnóstico del importador y corrección aplicada

El [importador](../seguridad_pymes/zeek_labels.py) tenía `LABELS = {"Benign": 0, "Malicious": 1}`. En `_record`, la llamada `LABELS.get(record["label_original"])` devolvía `None` para `benign` y registraba `field_problems["label"] = "unrecognized_label"`. Era una incompatibilidad de vocabulario exacto; no un error en los tiempos o paquetes del extractor.

Se inspeccionaron los tres logs originales disponibles:

| Escenario | Literales de etiqueta principal encontrados |
| --- | --- |
| Piloto 20-1 | `Benign`: 3.193; `Malicious`: 16 |
| Hakai 8-1 | `Benign`: 2.181; `Malicious`: 8.222 |
| Philips Hue 4-1 | `benign`: 452 |

[Variantes originales](validacion_normalizacion_hue/variantes_originales.json) conserva sus rutas, hashes y distribuciones anteriores a la modificación. La lista permitida queda limitada a:

| Literal exacto de origen | `label_normalized` | `binary_label` |
| --- | --- | ---: |
| `Benign` | `Benign` | 0 |
| `benign` | `Benign` | 0 |
| `Malicious` | `Malicious` | 1 |

Se mantiene `label_original` y el texto de `raw_fields`. No se aplican `lower`, `casefold`, eliminación de espacios ni reconocimiento aproximado. `BENIGN`, `MALICIOUS`, `malicious`, mezclas arbitrarias de mayúsculas/minúsculas, valores desconocidos y cadenas con espacios adicionales **siguen siendo desconocidos**, porque no están documentados en las fuentes retenidas. Los campos vacíos o no establecidos conservan su motivo y su representación original en `raw_fields`.

El formato de importación pasa a **`sipymes.zeek-labels.v1.1`**. El informe importado añade la política **`sipymes.iot23.label-aliases.v1`**, su mapa explícito y una distribución normalizada, manteniendo la distribución textual original. Las etiquetas detalladas, los UID, líneas, identificadores, tiempos, contadores y detección de contradicciones conservan su tratamiento anterior. No se fusionan registros duplicados por compartir una etiqueta normalizada.

Reconocer la etiqueta de una referencia **no admite automáticamente un flujo**: el auditor sigue exigiendo evidencia por frame, soporte temporal, orientación, exclusividad y conservación exacta. Una etiqueta principal benigna con detalle contradictorio, o referencias solapadas de clases distintas, continúa excluida.

## 3. Nueva importación y auditoría de Hue

Se reutilizó [la extracción original 1.0.1](../data/processed/iot23_hue_4_1/extraction.json), sin modificar sus 38 características ni volver a calcularlas con otras fórmulas. La auditoría leyó nuevamente el PCAP real, vinculado por hash a la extracción y a la procedencia. La repetición mediante las pruebas también volvió a ejecutar TShark y comparó la extracción completa con la original.

Resultados reales de [la nueva auditoría](validacion_normalizacion_hue/audit_v2_hue/label_audit.json):

| Medida de Hue | Antes | Después |
| --- | ---: | ---: |
| Frames totales | 21.664 | 21.664 |
| Paquetes aceptados por extractor | 16.921 | 16.921 |
| Paquetes fuera del contrato, ARP | 4.743 | 4.743 |
| Flujos extraídos | 2.200 | 2.200 |
| Referencias originales importadas | 452 | 452 |
| Etiquetas principales reconocidas | 0 | 452 |
| Referencias representadas por flujos admitidos | 0 | **359** |
| Referencias sin correspondencia admitida | 452 | **93** |
| Flujos Benign admitidos | 0 | **2.107** |
| Flujos Malicious admitidos | 0 | **0** |
| Flujos pendientes/en cuarentena | 2.200 | **93** |
| Rechazos terminales del auditor | 0 | 0 |
| Paquetes en flujos admitidos | 0 | **15.942** |
| Cobertura de flujos | 0 % | **95,7727 %** |
| Cobertura de paquetes aceptados | 0 % | **94,2143 %** |
| Cobertura de todos los frames | 0 % | **73,5875 %** |
| Referencias representadas / 452 | 0 % | **79,4248 %** |

Los estados finales de flujo son 1.762 `admitted_sibling_segment`, 298 `admitted_unique`, 47 `admitted_tcp_closure`, 86 `segmentation_mismatch` y siete `quarantined_partial_checksum`. Las 47 admisiones de cierre TCP usan la regla exacta que ya existía; no se añadió una tolerancia temporal ni una nueva interpretación de FIN/ACK.

Entre las 452 referencias hay **361 con contabilidad verificada**, pero solo **359 representadas por flujos admitidos**. Las otras dos verificadas pertenecen a flujos que contienen checksum parcial y continúan en cuarentena. Las 91 referencias restantes tienen `counter_mismatch`. Por tanto, ni 452 etiquetas reconocidas ni 361 referencias verificadas deben presentarse como 452 o 361 referencias utilizables.

[Referencias de Hue](validacion_normalizacion_hue/referencias_hue.json) enumera las 452, con UID, línea, etiqueta original y normalizada, estado, contadores, frames, flujos asociados y motivos pendientes. Se comprobó que el conjunto de 93 referencias no admitidas es **exactamente el conjunto diagnosticado antes de normalizar**. No se recuperó ninguna de ellas por cambiar su escritura.

## 4. Las 93 discrepancias, agrupadas por evidencia

[Diagnóstico por referencia y paquete](validacion_normalizacion_hue/diagnostico_93.json) conserva los 93 casos completos. Se elaboró a partir de los informes anteriores a la normalización, sin cambiar asignaciones ni reglas. La agrupación describe patrones observados; no afirma haber reproducido internamente la configuración histórica de Zeek.

| Grupo | Referencias | Evidencia observada | Resultado actual |
| --- | ---: | --- | --- |
| Un ACK posterior al fin publicado | 84 | Un ACK puro de 40 bytes IPv4 fuera del soporte; contadores completos del flujo coinciden al incluirlo; FIN con paquetes intermedios | Cuarentena por segmentación |
| Varios ACK posteriores | 2 | Dos ACK fuera del soporte; cierre simultáneo o retransmisión/intercalación que no cumple la cadena estricta | Cuarentena por segmentación |
| Checksum parcial y ACK posterior | 5 | Patrón parcial más ACK fuera del soporte; diferencias de paquetes/bytes combinadas | Cuarentena por checksum parcial |
| Checksum parcial sin ACK posterior pendiente | 2 | Cuatro frames parciales entre ambas; la contabilidad restante se verifica | Cuarentena del flujo por checksum parcial |
| **Total** | **93** | | **Ninguna admitida** |

La última fila de causa contiene cuatro de los nueve frames parciales; los otros cinco pertenecen al grupo precedente. Todos los paquetes siguen presentes y sus características extraídas siguen intactas. No hay checksum realmente incorrecto entre los paquetes aceptados de Hue: 16.912 tienen checksum válido y nueve presentan el patrón parcial.

### Ejemplos de ACK fuera del soporte

1. **UID `CGQf8t1kjdxB5PHXL4`, línea 12**, flujo `40a505ceaee251eb7c64a34c33b6c8fd3bda97871bfce1b59e65d4a9d0ce72f8`. Fin Zeek `1540469831306122000 ns`. Esperado: 5/3 paquetes y 212/144 bytes IPv4 en origen/respuesta. Candidatos dentro del soporte: 4/3 y 172/144. El ACK puro del frame 175 está en `1540469831306125000 ns`. Entre los FIN 171 y 174 hay un SYN/ACK retransmitido y otro ACK: la relación de secuencias de FIN es compatible, pero no cumple la consecutividad requerida por v2. No se extendió la duración publicada.

2. **UID `CSiLuw4nkxF0s73csc`, línea 105**. Esperado: 8/7 paquetes y 1927/469 bytes; candidatos: 7/6 y 1887/429. FIN 3840 y FIN 3841, seguidos de ACK 3842 y ACK 3843 fuera del fin `1540483327221765000 ns`. El segundo FIN no reconoce `seq(primer FIN)+1`; es un patrón compatible con cierre simultáneo. Añadir únicamente un ACK no conserva los contadores completos. Requiere otra regla de estado TCP, no una tolerancia de milisegundos.

3. **UID `CPYxQE4uDhjh3JrYj5`, línea 353**. Esperado: 5/3 paquetes, 212/144 bytes; candidatos: 3/3, 132/144. Los ACK 16938 y 16939 siguen al fin publicado `1540531041040494000 ns`; hay una retransmisión SYN/ACK 16936 entre FIN 16935 y FIN 16937. Solo el segundo ACK reconoce el FIN remoto. La evidencia no se reduce a «añadir el último paquete».

En los 84 casos de un solo ACK se comprobaron relaciones de secuencia entre los FIN compatibles con el cierre, pero todos tienen paquetes intermedios. Esto explica por qué la regla actual los excluye; **no los convierte en correspondencias válidas bajo esa regla**.

### Ejemplos de checksum parcial y contadores

- **UID `CG5VXMR4xMjAr5ual`, línea 182**: el frame 7755 tiene patrón parcial y 1.539 bytes de payload; el historial contiene `c` y `missed_bytes=1539`. Además, el ACK 7765 queda después del fin publicado. Incluir el paquete parcial y omitir el ACK puede compensar el número de paquetes, pero no los bytes. Ese aparente equilibrio nunca se usa para admitir la referencia.
- **UID `CnLHQd2NrE3dd5Zmzg`, línea 399**: frames parciales 19636 y 19642, payload total 4.006 bytes. El historial y `missed_bytes` respaldan la omisión en la contabilidad Zeek conforme a la regla existente. Los contadores restantes coinciden exactamente: origen 10 paquetes/3314 bytes; respuesta 4/1429. El flujo sigue sin etiqueta por contener paquetes parciales.
- **UID `CTFUS34mv0hiX64tAd`, línea 440**: frames parciales 20954 y 20955, payload total 7.363 bytes. La contabilidad verificada es 6/10 paquetes y 1712/594 bytes IPv4. También permanece en cuarentena.

Para las siete referencias con patrón parcial, el historial tiene la marca de dirección pertinente y `missed_bytes` coincide con la suma de payload parcial. Esto es evidencia de compatibilidad con los contadores publicados; no demuestra ausencia de pérdida previa a la captura ni autoriza a etiquetar sus flujos.

No se encontró evidencia de que fuera necesario corregir las fórmulas, orientación o timeouts del extractor. Las diferencias documentadas son limitaciones de cobertura de la reconciliación conservadora ante estos patrones TCP y de checksum. No se afirma que cada diferencia sea un error de implementación de Zeek o del auditor.

## 5. Comparación de los tres escenarios

Se ejecutaron de nuevo importación y auditoría por paquete para los tres. [Las regresiones](validacion_normalizacion_hue/regresiones.json) confirman igualdad estructural de **todos los campos devueltos por el auditor** con los informes anteriores de Hakai y el piloto, además de igualdad de los campos originales de sus registros importados, incluidos etiquetas binarias y UID. Hue reproduce su nuevo informe por separado. Los informes históricos no se sobrescribieron.

| Escenario | Benign admitidos | Malicious admitidos | Grupos Benign | Grupos Malicious | Flujos pendientes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Piloto 20-1 | 3.207 | 288 | 3.192 | 6 | 4 |
| Hakai 8-1 | 2.181 | 2.056 | 2.181 | 2.056 | 0 |
| Hue 4-1 | 2.107 | 0 | 359 | 0 | 93 |
| **Total admitido** | **7.495** | **2.344** | **5.732** | **2.062** | **97 pendientes** |

La última columna suma pendientes de los tres escenarios; no son parte del total admitido. Algunos grupos del piloto contienen segmentos admitidos y en cuarentena, por lo que no se deben sumar conteos de grupos por estado como si fueran conjuntos disjuntos.

### Protocolos por clase admitida

| Escenario / clase | Flujos TCP | Flujos UDP | Grupos TCP | Grupos UDP |
| --- | ---: | ---: | ---: | ---: |
| Piloto Benign | 1 | 3.206 | 1 | 3.191 |
| Piloto Malicious | 288 | 0 | 6 | 0 |
| Hakai Benign | 2 | 2.179 | 2 | 2.179 |
| Hakai Malicious | 2.056 | 0 | 2.056 | 0 |
| Hue Benign | **302** | 1.805 | **49** | 310 |
| Hue Malicious | 0 | 0 | 0 | 0 |

Antes de recuperar Hue había solo tres flujos TCP benignos admitidos. Ahora hay **305 TCP benignos frente a 2.344 TCP maliciosos**, pero son **52 frente a 2.062 grupos**, respectivamente. Los **7.190 flujos UDP admitidos son todos Benign**; no se dispone de ejemplos UDP maliciosos admitidos.

La cobertura de filas de Hue, 95,77 %, oculta un sesgo de selección: solo **49 de sus 142 referencias TCP** están representadas; las otras 93 TCP siguen excluidas. No se debe extrapolar el comportamiento de las admitidas a todas las conexiones benignas posibles.

### Banderas TCP observadas

Número de **paquetes TCP con cada bandera** en los flujos admitidos. Un paquete puede tener varias banderas, por ejemplo FIN+ACK; las columnas no se suman como categorías exclusivas. UDP no se trata como si tuviera banderas TCP en cero.

| Escenario / clase | Paquetes TCP | SYN | ACK | FIN | RST |
| --- | ---: | ---: | ---: | ---: | ---: |
| Piloto Benign | 1 | 0 | 1 | 0 | 0 |
| Piloto Malicious | 34.925 | 20 | 34.905 | 2 | 0 |
| Hakai Benign | 2 | 0 | 2 | 0 | 0 |
| Hakai Malicious | 12.334 | 12.334 | 0 | 0 | 0 |
| Hue Benign | 6.301 | 99 | 6.249 | 95 | 1 |
| Hue Malicious | 0 | 0 | 0 | 0 | 0 |

En términos de **flujos TCP que contienen la bandera**, Hue Benign tiene SYN en 48, ACK en 302, FIN en 48 y RST en uno. El piloto Malicious tiene SYN en cuatro, ACK en 284 y FIN en uno; Hakai Malicious tiene SYN en sus 2.056 flujos y ninguna de las otras tres banderas. El [censo completo](validacion_normalizacion_hue/censo_comparativo.json) incluye también PSH, URG, ECE, CWR, combinaciones de bits, conteos de flujos y estados desconocidos.

### Dependencia y riesgo de atajos

- Hue aporta tráfico TCP bidireccional con ACK, payload/PSH y cierres FIN/RST; mejora la variedad frente a los escasos paquetes TCP benignos anteriores. Sin embargo, **254 de sus 302 flujos TCP benignos proceden de una sola referencia**, UID `CkHQfG3B034MyvP3W`, línea 459: 5.958 paquetes conservados en un grupo. No son 254 conexiones independientes.
- Otro UID de Hue, `ClZeN63S7LbgEs2ZNk`, línea 460, produce 1.354 segmentos UDP a partir de 8.124 paquetes. Es una referencia original y un grupo, no 1.354 muestras independientes. Estos dos grupos reúnen **1.608 de los 2.107 flujos admitidos de Hue**.
- Hay **2.060 flujos y 2.060 grupos maliciosos de SYN puro**, frente a cero benignos de ese patrón en las admisiones disponibles. La mayor parte procede de Hakai, de una captura y solo dos pares de hosts. El nombre C&C de su etiqueta detallada no prueba sesiones C&C establecidas: los paquetes muestran intentos SYN sin ACK.
- Los restantes grupos maliciosos con intercambio ACK/payload proceden de las conexiones largas del piloto. Su gran número de segmentos tampoco crea nuevas infecciones o campañas independientes.
- Un clasificador podría explotar «UDP», «SYN sin ACK», tamaños, falta de dirección de respuesta o valores no aplicables de banderas. Estas asociaciones describen este corpus y sus filtros de admisión; no son reglas universales de ataque. En una PYME, un SYN sin respuesta puede ser normal, y un ataque puede usar UDP o una sesión TCP establecida.

Este análisis contiene **conteos y relaciones descriptivas**, no exactitud, recall, F1, una matriz de confusión ni una evaluación de detección mediante reglas. No se generó ningún clasificador ni una tabla definitiva de entrenamiento. Los grupos de conexión y capturas completas deben conservarse al separar futuras particiones; distintos grupos del mismo dispositivo/captura siguen siendo dependientes. Solo tres escenarios, con dos capturas que contienen etiquetas maliciosas, no demuestran generalización a una red PYME.

## 6. Pruebas ejecutadas e integridad

Se añadieron **diez pruebas** en [normalización Zeek](../tests/test_zeek_label_normalization.py). Cubren los tres literales permitidos, conservación de originales y política, mayúsculas/minúsculas no documentadas, desconocidos, campos vacíos/no establecidos, contradicción principal/detalle, clases solapadas, UID duplicado con texto distinto y la imposibilidad de que un alias eluda fallos de contadores, duración, tiempos, orientación, protocolo o checksum. También comparan todos los campos anteriores de los registros de Hakai y del piloto.

Se actualizó únicamente la expectativa vigente de Hue en [la prueba de adquisición](../tests/test_iot23_acquisition_compatibility.py): compara con el informe normalizado nuevo y mantiene el anterior como evidencia. Siguen verificándose la lectura completa, las 38 características, los hashes, las particiones y la cuarentena de todos los paquetes parciales.

| Ejecución | Aprobadas | Fallos | Errores | Omitidas | Tiempo de proceso, incluido descubrimiento |
| --- | ---: | ---: | ---: | ---: | ---: |
| Específicas: importador, auditor y tres capturas | **83** | **0** | **0** | **0** | 23,5897 s |
| Suite completa | **182** | **0** | **0** | **0** | 46,9135 s |

Las 83 están incluidas en las 182, no se suman. Unittest registra 43,164 s para ejecutar los 182 casos, sin el tiempo de descubrimiento/importación. Registros: [resultado específico](validacion_normalizacion_hue/resultado_especificas.json), [log específico](validacion_normalizacion_hue/pruebas_especificas.log), [resultado completo](validacion_normalizacion_hue/resultado_completas.json), [log completo](validacion_normalizacion_hue/pruebas_completas.log). Las pruebas heredadas de entrenamiento usan fixtures temporales; no se entrenó con los PCAP ni se escribió un Random Forest operativo.

La [comprobación final de integridad](validacion_normalizacion_hue/integridad.json) verifica:

- **141 de los 143 archivos previos sin cambios**. Los únicos dos modificados son el importador y la prueba de compatibilidad indicada. Ningún archivo previo eliminado.
- Auditor v2 sin cambios: SHA-256 `151c1c0bc4a6e9644c0524573026269ff8a49a891a9d222360c1d8051d96502c`.
- Extractor sin cambios: `0528ed6c3f53d9f88cfcc44a267a690c2fae839757a141ba5d731390610bdd6f`.
- Esquema, lector PCAP, timeouts, todos los PCAP/logs originales y extracciones anteriores, Streamlit y procesamiento CSV sin cambios.
- Random Forest original sin cambios: `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. También permanecen intactos sus metadatos, el modelo piloto y los estudios previos.
- Las tres bases SQLite mantienen sus hashes y pasan `integrity_check` en modo de solo lectura. Todos los respaldos anteriores mantienen hashes y CRC válidos.

El importador cambia de SHA-256 `dbd3c141f1756e6e0819bb9f55c6f0c1ec04970e56558fa3ea88145e6a1e8de6` a `3ec6ae61497ea8417b12312d8488aac66d4b190eea2856945f331e7d3a16018e`. El cambio completo de los dos archivos anteriores se entrega como [diff revisable](validacion_normalizacion_hue/cambios.diff).

Las pruebas del panel, CSV y persistencia pasan; no se afirma una inspección gráfica manual de Streamlit. No se aumentaron límites de recursos ni se modificaron capturas, etiquetas fuente o criterios para obtener la nueva cobertura.

## 7. Archivos y reproducción

Modificados:

1. [Importador Zeek](../seguridad_pymes/zeek_labels.py): mapa exacto, campo normalizado y metadatos de versión/distribución.
2. [Prueba de adquisición](../tests/test_iot23_acquisition_compatibility.py): expectativa actual de Hue, conservando la evidencia anterior.

Añadidos: [diez pruebas nuevas](../tests/test_zeek_label_normalization.py), este informe, [ejecutores y evidencias](validacion_normalizacion_hue/) y el respaldo. [Inventario final](validacion_normalizacion_hue/inventario_final.json) registra cada adición, tamaño y hash, salvo el propio inventario para evitar autorreferencia. Los informes de Hue se guardan bajo una ruta nueva; los anteriores permanecen intactos.

Desde la raíz, comprobaciones repetibles sobre los datos locales, sin red:

```powershell
.venv\Scripts\python.exe -B -m unittest tests.test_zeek_label_normalization tests.test_label_audit tests.test_label_reconciliation tests.test_iot23_acquisition_compatibility -v
.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Los ejecutores de evidencia son [diagnóstico](validacion_normalizacion_hue/diagnosticar.py), [pruebas con logs](validacion_normalizacion_hue/pruebas.py), [censo y regresiones](validacion_normalizacion_hue/censar_y_revalidar.py) e [integridad](validacion_normalizacion_hue/verificar_integridad.py). Rechazan sobrescribir sus salidas; para generar otra ejecución documentada se debe elegir una carpeta de evidencia nueva. No son funcionalidades nuevas del producto.

Para reproducir únicamente la auditoría en otra carpeta nueva, sin tocar la extracción:

```powershell
.venv\Scripts\python.exe -B -m seguridad_pymes.label_audit data/processed/iot23_hue_4_1/extraction.json data/raw/iot23_hue_4_1/conn.log.labeled data/raw/iot23_hue_4_1/provenance.json --capture data/raw/iot23_hue_4_1/2018-10-25-14-06-32-192.168.1.132.pcap --output RUTA_NUEVA_DE_AUDITORIA
```

Reversión: extraer el respaldo a una carpeta nueva y verificar su manifiesto; recuperar únicamente los dos archivos modificados si se desea volver a la etapa anterior y apartar las pruebas/evidencias nuevas a una carpeta de conservación. No se requiere restaurar SQLite, modelos o fuentes, porque no cambiaron. Conservar los informes normalizados como evidencia histórica, identificados por versión, aunque se revierta el código. No se ejecutó borrado ni reversión destructiva.

## 8. Propuesta separada para las discrepancias: no implementada

La compatibilidad del vocabulario está resuelta dentro de la lista documentada. Recuperar cualquiera de las 93 referencias pendientes requeriría analizar reglas adicionales; **no forma parte de esta corrección**. Propongo para revisión:

1. Diseñar una regla de estado TCP versionada que trate FIN/ACK intercalados, retransmisiones demostrables y cierre simultáneo mediante números de secuencia, ACK, direcciones y contadores originales; no mediante una ventana temporal añadida.
2. Demostrar propiedad completa y exclusiva de cada paquete posterior al fin, distinguir reutilización de puertos mediante evidencia de handshake/secuencias y rechazar casos con UID alternativo, contradicción o explicación múltiple. Un ACK adicional aislado o contadores coincidentes no bastan.
3. Separar el caso de un ACK de los dos cierres con múltiples ACK; exigir pruebas positivas y contraejemplos de reutilización, solapamiento, retransmisión y cierres incompletos antes de proponer un nuevo auditor. Mantener v2 como referencia de comparación.
4. Mantener en cuarentena los siete flujos con checksum parcial incluso si una nueva regla justificara su contabilidad. No reparar el PCAP, descontar paquetes de las características ni repartir una etiqueta sobre paquetes dudosos.

No se estima cobertura recuperable bajo una regla futura aún no aprobada. Antes de entrenar será necesario revisar la separación por capturas/grupos y la concentración de segmentos y comportamientos; la mejora de cobertura y diversidad documentada aquí no equivale a un modelo validado ni a detección de ataques desde PCAP.
