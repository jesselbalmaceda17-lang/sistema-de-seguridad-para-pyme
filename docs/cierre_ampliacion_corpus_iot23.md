# Cierre verificado de la ampliación del corpus IoT-23

Fecha: 8 de noviembre de 2026. Tiempos y fechas de evidencia en UTC.

**Etapa cerrada con 187 pruebas aprobadas, cero fallos, cero errores y cero omitidas. Trojan 42-1 permanece en cuarentena y aporta cero flujos, referencias o paquetes con etiqueta admitida. Los tres escenarios anteriores conservan exactamente sus resultados. No recomiendo iniciar todavía el entrenamiento.**

## 1. Estado recuperado después de la interrupción

Se inspeccionaron los archivos reales y el proceso de pruebas pendiente. La ejecución anterior sí había terminado, con **83 pruebas aprobadas**, pero el selector del ejecutor no incluía el módulo de ampliación del corpus. Ese resultado no demostraba que se hubieran ejecutado sus cinco pruebas nuevas.

En [el estado al reanudar](validacion_ampliacion_corpus/estado_reanudacion.json) se registran **21 archivos añadidos por la etapa interrumpida**, incluyendo el respaldo, los cinco archivos de adquisición, las evidencias y ejecutores, y [el módulo de pruebas nuevo](../tests/test_corpus_expansion.py). Ninguno de los 165 archivos existentes antes de la ampliación había cambiado ni desaparecido. La [carpeta de procesamiento de 42-1](../data/processed/iot23_trojan_42_1/) estaba y continúa vacía: no se creó una extracción válida ni un informe de correspondencias.

Durante el cierre solo se corrigió [el ejecutor de pruebas de esta etapa](validacion_ampliacion_corpus/pruebas.py): se añadió explícitamente `tests.test_corpus_expansion` al selector y se utilizaron salidas nuevas con sufijo `_cierre`. Los logs y resultados anteriores se conservaron. Esta corrección afecta a la selección de pruebas, no al extractor, auditor o aplicación.

Se añadieron registros de cierre y este informe. [El inventario final](validacion_ampliacion_corpus/inventario_final.json) distingue las adiciones de toda la etapa y el cambio del ejecutor después de reanudar, con tamaños y hashes.

## 2. Respaldo y manifiesto comprobados otra vez

Se conservó y verificó [el respaldo anterior a la ampliación](../_backups/pre-corpus-expansion-20261108T192626Z-3cdf2ed2.zip):

- Tamaño: **48.589.785 bytes**.
- SHA-256: `05194834818c97ae65d07c43eac9980fd060607b33cb6444d975933b955a4a2c`.
- Manifiesto interno y CRC válidos.
- **165 archivos restaurados realmente en una carpeta temporal**, con sus hashes comprobados contra el manifiesto.
- Las tres bases restauradas pasaron `integrity_check`; el hash de sus volcados SQL completos coincide con el de sus fuentes. Las copias se habían obtenido mediante la API de respaldo consistente de SQLite. No se confunde identidad lógica con identidad física del archivo serializado.
- Los seis respaldos anteriores también conservan sus hashes y CRC. El entorno virtual, cachés y respaldos previos no se incluyeron dentro del nuevo ZIP; permanecen separados.

Evidencias: [respaldo inicial](validacion_ampliacion_corpus/respaldo.json) y [verificación de restauración durante el cierre](validacion_ampliacion_corpus/verificacion_respaldo_cierre.json). El proyecto sigue sin repositorio Git; no se creó uno ni se declaró un estado Git limpio.

## 3. Selección y datos efectivamente adquiridos

La etapa examinó solo metadatos oficiales de los 18 escenarios todavía no utilizados y no reservados. [La selección de fuentes](validacion_ampliacion_corpus/seleccion_fuentes.json) conserva índices, README, cabeceras HEAD y sus fechas/hashes. No se solicitaron los PCAP o logs de Mirai 34-1 ni Amazon Echo 5-1. Tampoco se descargaron subconjuntos como `test.pcap`, capturas filtradas por puerto o archivos `only5000`.

Antes de descargar se compararon estas alternativas:

| Escenario | PCAP anunciado | Etiquetas anunciadas | Motivo de selección o aplazamiento |
| --- | ---: | ---: | --- |
| Muhstik 3-1 | 57.919.772 bytes | 24.383.537 bytes | Publica 156.103 referencias; riesgo de superar 100.000 flujos y aumentar mucho el uso de memoria. No descargado |
| Torii 21-1 | 4.063.997 bytes | 428.943 bytes | Tamaño pequeño, pero repite familia y etiquetas C&C-Torii del piloto. No descargado |
| Trojan 42-1 | **2.908.160 bytes** | **585.829 bytes** | Piloto más pequeño con seis referencias publicadas de descarga de archivos. Fue el único par adquirido |

Las distribuciones publicadas son información del autor; no garantizan diversidad observada, flujos admitidos ni independencia. [IoT-23 oficial](https://www.stratosphereips.org/datasets-iot23) publica los escenarios y etiquetas; [la decisión previa](validacion_ampliacion_corpus/decision_previa.json) documenta los criterios antes de solicitar los cuerpos de datos.

Para 42-1 había **297.695.563.776 bytes libres en disco** y **10.117.582.848 bytes de memoria física disponible** al comprobar la adquisición. Se mantuvieron todos los límites: TCP idle 120 s, UDP idle 30 s, duración activa 300 s, TShark 120 s, un millón de paquetes, 50.000 flujos activos y 100.000 flujos. El lector del auditor conserva el límite de 128 MiB y un millón de frames.

El README de 42-1 contiene inconsistencias de metadatos: menciona el número genérico 41 y un año de inicio 2018, mientras el directorio oficial y el nombre del PCAP identifican 42-1 y enero de 2019. Se preservaron como advertencias, sin corregir el original ni inferir etiquetas a partir de su nombre. La correspondencia por paquetes debía resolver la admisibilidad, pero el truncamiento impidió completar ese paso.

Se conservaron únicamente los siguientes cuerpos de datos:

| Archivo | Tamaño | Obtención UTC | SHA-256 |
| --- | ---: | --- | --- |
| [PCAP original de 42-1](../data/raw/iot23_trojan_42_1/2019-01-10-14-34-38-192.168.1.197.pcap) | 2.908.160 bytes | 19:34:37 | `7573797f17aae96e3804a3cfb22d531b74c17bbae740de1e14048f89130fba37` |
| [Log Zeek original](../data/raw/iot23_trojan_42_1/conn.log.labeled) | 585.829 bytes | 19:34:39 | `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa` |

URLs oficiales exactas, fechas, ETag y cabeceras están en [procedencia](../data/raw/iot23_trojan_42_1/provenance.json). El par suma **3.493.989 bytes**. La comprobación posterior del extremo remoto solicitó otros **80 bytes del mismo PCAP**, no otro dataset. Durante el cierre no se realizaron nuevas peticiones de datasets ni se descargaron sustitutos.

La identidad byte a byte con el archivo completo de Zenodo no fue comprobada: se adquirió una instantánea de los directorios oficiales individuales, fijada por hashes. No se descargó el archivo completo del dataset.

## 4. Evidencia reproducible del truncamiento

TShark 4.6.9 leyó los registros completos iniciales y terminó con **código 14**: el archivo aparece cortado en medio de un paquete. La inspección independiente de la estructura PCAP encontró:

| Dato físico | Resultado |
| --- | ---: |
| Registros completos antes del fallo | **24.484** |
| Frame incompleto | **24.485** |
| Offset de la cabecera de ese registro | **2.908.099** |
| Offset del comienzo de sus datos | **2.908.115** |
| Tamaño capturado declarado | **91 bytes** |
| Tamaño original declarado | **91 bytes** |
| Bytes de paquete disponibles al llegar a EOF | **45 bytes** |
| Déficit para completar ese registro | **46 bytes** |

Esta es una inspección física de un prefijo, **no una extracción válida de 24.484 paquetes para el corpus**. Tampoco demuestra que falten únicamente 46 bytes de toda la captura: podría haber registros posteriores ausentes y no existe evidencia para reconstruirlos.

La respuesta del GET original tuvo exactamente la longitud anunciada por HEAD. Además, una petición HTTP Range devolvió `206 Partial Content`, rango `2908080-2908159/2908160`, y los últimos 80 bytes del servidor coincidieron exactamente con los locales. ETag y fecha de modificación también coincidieron. Por tanto, el servidor publica el mismo final incompleto; no hay evidencia de una descarga local acortada que se solucione repitiéndola.

Evidencias: [diagnóstico de offsets y rechazo](validacion_ampliacion_corpus/diagnostico_truncamiento.json), [confirmación del servidor](validacion_ampliacion_corpus/confirmacion_servidor.json) y [ejecución original detenida](validacion_ampliacion_corpus/ejecucion_trojan_42_1.json).

Se llamó también al extractor existente con el archivo completo: devolvió `CaptureError` por el código 14 de TShark. El lector de evidencia del auditor devolvió `ValueError: Invalid, truncated or unordered PCAP record`. No se modificó ninguno para aceptar el prefijo.

**No se borró el último registro, no se añadieron ceros, no se reparó el archivo ni se relajó la validación.** La captura completa queda en [cuarentena documentada](validacion_ampliacion_corpus/cuarentena_42_1.json).

## 5. Censo admisible y cobertura de 42-1

El log se pudo importar separadamente: contiene **4.426 referencias**, de las que 4.420 dicen Benign y seis Malicious. No hay filas rechazadas ni contradicciones detectadas; tiene marcador de cierre. Su importación y sus etiquetas textuales no prueban correspondencia con un flujo del extractor. Se guardó como [referencias sin correspondencia](validacion_ampliacion_corpus/etiquetas_importadas_42_sin_correspondencia.json).

| Medida de 42-1 | Resultado válido |
| --- | --- |
| Extracción completa | **No completada; archivo rechazado** |
| Auditoría completa de correspondencias | **No ejecutable sin extracción válida** |
| Total de flujos válidamente extraídos | **No disponible** |
| Paquetes aceptados/rechazados por una extracción válida | **No disponible** |
| Nuevos flujos admitidos | **0** |
| Nuevas referencias con correspondencia admitida | **0** |
| Nuevos paquetes con etiqueta admitida | **0** |
| Nuevos grupos utilizables | **0** |
| Cobertura porcentual de flujos/paquetes | **No aplicable: no hay denominador de una extracción válida** |

Los valores desconocidos se registran como nulos con motivo, no como ceros de características inventadas. Se pone en cuarentena el archivo completo; no se afirma que haya una cantidad conocida de flujos individuales en cuarentena.

No hubo una ampliación utilizable de diversidad y no se admite ninguna etiqueta procedente de 42-1 para entrenamiento. Las seis referencias maliciosas publicadas no se convierten en seis muestras nuevas.

## 6. Tres auditorías anteriores verificadas otra vez

Se ejecutaron de nuevo el importador y la auditoría por paquetes sobre las fuentes originales de 20-1, Hakai y Hue. Se compararon **todos los campos devueltos por el núcleo del auditor**, incluido el ledger, con sus informes preservados. También se comparó el censo de grupos canónico. Todos coinciden. Evidencia: [auditorías de cierre](validacion_ampliacion_corpus/auditorias_previas_cierre.json).

| Escenario | Flujos admitidos | Benign | Malicious | Pendientes | Grupos Benign | Grupos Malicious |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 20-1 | 3.495 | 3.207 | 288 | 4 | 3.192 | 6 |
| Hakai 8-1 | 4.237 | 2.181 | 2.056 | 0 | 2.181 | 2.056 |
| Hue 4-1 | 2.107 | 2.107 | 0 | **93** | 359 | 0 |
| Total admitido | **9.839** | **7.495** | **2.344** | 97 pendientes en total | **5.732** | **2.062** |

Se mantuvieron las coberturas de flujos y de paquetes aceptados, respectivamente: 20-1 **99,8857 % / 99,3059 %**, Hakai **100 % / 100 %** y Hue **95,7727 % / 94,2143 %**. Estas son métricas de correspondencia de etiquetas, no de detección.

Las 93 referencias de Hue no se recuperaron ni se reinterpretaron. No se modificaron sus reglas FIN/ACK, checksum, segmentación o contadores.

### Diversidad observada y unidades de agrupación

[El censo inicial por grupos](validacion_ampliacion_corpus/censo_inicial_grupos.json), recalculado y contrastado durante el cierre, usa los endpoints canónicos de cada paquete. Así evita que el primer paquete de un segmento hermano invierta su orientación y oculte la bidireccionalidad del grupo. No cambia la orientación ni las características del extractor.

| Clase | Flujos TCP | Flujos UDP | Grupos TCP | Grupos UDP | Grupos TCP con paquetes en ambas direcciones | Grupos TCP con payload en ambas direcciones |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Benign | 305 | 7.190 | 52 | 5.680 | **49** | **7** |
| Malicious | 2.344 | 0 | 2.062 | 0 | **2** | **2** |

Bidireccionalidad significa al menos un paquete observado desde cada endpoint; no garantiza una transacción de aplicación exitosa. Los tres grupos TCP benignos restantes son observaciones unidireccionales del piloto y Hakai. Los 49 bidireccionales benignos proceden de Hue.

| Clase admitida | Paquetes TCP | Con SYN | Con ACK | Con FIN | Con RST |
| --- | ---: | ---: | ---: | ---: | ---: |
| Benign | 6.304 | 99 | 6.252 | 95 | 1 |
| Malicious | 47.259 | 12.354 | 34.905 | 2 | 0 |

Un paquete puede tener varias banderas; las columnas no son categorías excluyentes. Las banderas UDP siguen siendo no aplicables, no mediciones TCP en cero.

De los 2.062 grupos TCP maliciosos, **2.060 son de SYN puro sin ACK** y solo **dos contienen otros patrones**, ambos bidireccionales y con payload en ambas direcciones en el piloto. Hakai aporta muchos grupos, pero no aporta ese segundo comportamiento. Todos los grupos UDP admitidos siguen siendo benignos.

Por tanto, el sesgo entre protocolo/banderas y etiqueta **no disminuyó** en esta ampliación fallida. Tampoco deben confundirse grupos con ataques independientes: comparten captura, dispositivo, destinos y rutina. En Hue, dos referencias originan 1.608 de los 2.107 segmentos admitidos; una sola referencia origina 254 de sus 302 segmentos TCP benignos. El número de filas no demuestra diversidad de experimentos.

No se calcularon exactitud, recall, F1 ni una evaluación de reglas de detección. Los conteos anteriores son descriptivos.

## 7. Pruebas ejecutadas después de reanudar

Las cinco pruebas de [ampliación del corpus](../tests/test_corpus_expansion.py) comprueban:

1. Un grupo sigue siendo bidireccional aunque cada segmento tenga orientación inicial opuesta.
2. Las retransmisiones SYN no se convierten en conexiones independientes ni en tráfico bidireccional.
3. Los flujos sin correspondencia verificada no aportan clase ni grupo admitido.
4. UDP no adquiere banderas TCP inventadas.
5. El PCAP oficial retenido, fijado por hash y offsets, es rechazado por el extractor real y el lector del auditor; no produce informes válidos y sus bytes no cambian.

Resultados realmente obtenidos, en orden:

| Ejecución | Aprobadas | Fallos | Errores | Omitidas | Tiempo incluido descubrimiento |
| --- | ---: | ---: | ---: | ---: | ---: |
| Específica anterior a la reanudación, selector incompleto | 83 | 0 | 0 | 0 | 21,4746 s |
| **Específica de cierre, con el módulo nuevo** | **88** | **0** | **0** | **0** | **25,3533 s** |
| **Suite completa de cierre** | **187** | **0** | **0** | **0** | **48,9520 s** |

Las cinco nuevas están incluidas en las 88 y en las 187; los conteos no se suman. El cero de `skipped` en el primer resultado no significa que su selector incluyera el módulo omitido. La omisión del selector quedó corregida y registrada sin ocultar la primera ejecución.

Unittest mide 45,063 s para ejecutar los 187 casos; el intervalo de 48,9520 s añade descubrimiento e importaciones. Las pruebas heredadas de entrenamiento usan fixtures temporales; no se entrenó con las capturas ni se escribió un modelo operativo.

Evidencias originales: [resultado inicial](validacion_ampliacion_corpus/resultado_especificas.json) y [log inicial](validacion_ampliacion_corpus/pruebas_especificas.log). Evidencias de cierre: [resultado específico](validacion_ampliacion_corpus/resultado_especificas_cierre.json), [log específico](validacion_ampliacion_corpus/pruebas_especificas_cierre.log), [resultado completo](validacion_ampliacion_corpus/resultado_completas_cierre.json), [log completo](validacion_ampliacion_corpus/pruebas_completas_cierre.log).

La lectura de 42-1 falló operativamente porque la fuente es incompleta. La prueba negativa pasa **porque verifica ese rechazo correcto**, no porque la captura haya sido validada o reparada.

## 8. Integridad y recursos

[La verificación final](validacion_ampliacion_corpus/integridad_cierre.json) confirma **165 de 165 archivos previos sin modificaciones ni eliminaciones**, incluidas todas las fuentes, extracciones y auditorías anteriores. También verifica que el único archivo de etapa cambiado después de reanudar es el selector de pruebas.

| Componente protegido | SHA-256 sin cambios |
| --- | --- |
| [Extractor PCAP](../seguridad_pymes/pcap_extract.py) | `0528ed6c3f53d9f88cfcc44a267a690c2fae839757a141ba5d731390610bdd6f` |
| [Esquema y timeouts](../seguridad_pymes/pcap_schema.py) | `e9add5d1d6862bbb12a3c8cb60908e55e8ce95ccefe47f34e0cbb6c9c52e68fb` |
| [Auditor v2](../seguridad_pymes/label_audit.py) | `151c1c0bc4a6e9644c0524573026269ff8a49a891a9d222360c1d8051d96502c` |
| [Importador normalizado](../seguridad_pymes/zeek_labels.py) | `3ec6ae61497ea8417b12312d8488aac66d4b190eea2856945f331e7d3a16018e` |
| [Random Forest original](../models/unsw_nb15_random_forest.joblib) | `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9` |

[El certificado del contrato protegido](validacion_ampliacion_corpus/contrato_protegido_cierre.json) comprueba además en ejecución el extractor 1.0.1, el esquema `sipymes.offline.ipv4.v1`, las **38 definiciones** y la configuración, comparándolas con las tres extracciones originales. Incluye los hashes del lector, interfaz, módulos CSV y metadatos del modelo. No se cambió Streamlit ni se afirma una revisión gráfica manual.

Las tres bases SQLite conservaron sus hashes y pasaron `PRAGMA integrity_check` en modo de solo lectura después de las pruebas. Los siete respaldos, contando el de esta etapa, se conservaron. No se añadió entrenamiento, captura en vivo, clasificación PCAP ni funcionalidad de aplicación.

La adquisición del par tardó **9,2717 s**. El intento inicial de procesamiento se detuvo en **1,1076 s**, con **0,3594 s de CPU Python**, antes de la extracción. Windows midió un máximo de working set Python de **30.367.744 bytes**; el máximo muestreado de RSS Python+hijos fue **146.624.512 bytes**, con intervalo objetivo de 20 ms. Este último no es el pico exacto del árbol de procesos y puede omitir picos entre muestras. No son medidas de una extracción/auditoría completa exitosa.

Los archivos raw, incluidos los manifiestos, ocupan **3.497.691 bytes**. El respaldo ocupa 48.589.785 bytes; el inventario registra también el almacenamiento de los censos, diagnóstico e importación independiente de referencias. No se elevaron límites de recursos para alcanzar el resultado.

## 9. Reproducción, conservación y reversión

Sin red ni nuevas descargas, desde la raíz:

```powershell
.venv\Scripts\python.exe -B -m unittest tests.test_corpus_expansion tests.test_zeek_label_normalization tests.test_label_audit tests.test_label_reconciliation tests.test_iot23_acquisition_compatibility -v
.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Los ejecutores que escriben evidencia usan creación exclusiva: no deben repetirse sobre los mismos nombres esperando reemplazarlos. Para nuevas evidencias se necesita otra carpeta o sufijo. Los comandos anteriores de unittest permiten repetir las comprobaciones locales sin sobrescribir los registros preservados.

Conservar [raw 42-1](../data/raw/iot23_trojan_42_1/) y sus hashes junto con el [registro de cuarentena](validacion_ampliacion_corpus/cuarentena_42_1.json). No emplear la copia importada del log como si fuera un corpus etiquetado. La reparación o el recorte de la captura no forman parte de esta etapa.

No se necesita restaurar ningún componente de aplicación porque ninguno cambió. Para retirar la etapa se pueden apartar sus adiciones según el inventario a una carpeta de conservación, manteniendo los respaldos. Si hiciera falta recuperar un original, extraer el ZIP en una carpeta nueva, verificar manifiesto/CRC/hashes y seleccionar explícitamente qué restaurar. No se ejecutó borrado ni sustitución de bases o modelos.

## 10. Recomendación para el siguiente estudio

**Recomiendo estudiar Muhstik 3-1 antes de autorizar otra adquisición.** Su [directorio oficial](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/) publica el PCAP completo y el log asociado; su README describe una conexión IRC. La distribución publicada contiene 4.536 referencias Benign, ocho C&C, 5.962 Attack y 145.597 PartOfAHorizontalPortScan. Es un candidato para buscar intercambios y comportamientos maliciosos diferentes de los SYN puros dominantes, **sin garantizar que esas etiquetas tengan correspondencia admisible**.

La procedencia y tamaños ya examinados están en [selección de fuentes](validacion_ampliacion_corpus/seleccion_fuentes.json). El par suma **82.303.309 bytes**: aproximadamente 55,24 MiB de PCAP y 23,25 MiB de etiquetas. El PCAP anunciado cabe en el límite de entrada de 128 MiB del auditor, pero:

- Sus 156.103 referencias Zeek no equivalen al número de flujos del extractor; sí plantean un riesgo claro frente al límite actual de 100.000 flujos, además del límite de 50.000 activos.
- Los objetos de Python, el ledger y la serialización JSON pueden requerir mucha más memoria y almacenamiento que los bytes del PCAP. No se ha medido esa captura y no se garantiza que complete con los límites actuales.
- Antes de adquirirla se debe presentar un presupuesto de RAM/disco y ejecución, analizar los límites configurables y acordar una ejecución completa que aborte limpiamente si los supera. No deben utilizarse `test.pcap`, subconjuntos ni un recorte silencioso como sustitutos.

Torii 21-1 sería más pequeño, pero su diversidad incremental es menos prometedora al repetir familia y C&C del piloto. Las alternativas grandes, como Mirai 44-1, superan ampliamente el límite de entrada vigente. Mirai 34-1 y Amazon Echo 5-1 deben seguir reservados para la futura evaluación independiente. También sería razonable solicitar a los autores una copia íntegra y verificable de 42-1; eso sería una adquisición futura, nunca una reconstrucción inventada de los bytes ausentes.

**El corpus no está todavía listo para un entrenamiento con evaluación defendible para PYMES.** Esta etapa no añadió muestras utilizables y permanecen solo dos grupos maliciosos con patrones distintos de SYN puro, pocos experimentos independientes y una fuerte asociación entre clase, protocolo, dispositivo y captura. No se necesita forzar la recuperación de Hue ni reparar 42-1 para cerrar correctamente la etapa: se necesita conservar sus exclusiones y revisar el próximo estudio antes de entrenar.
