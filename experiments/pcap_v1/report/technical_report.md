# Experimento PCAP v1: informe técnico

El proceso experimental se completó y reprodujo. **El Random Forest no demuestra generalización suficiente para integrarse como detector.** Coincide con SYN sin ACK en las decisiones de Torii/Hakai y falla extensamente sobre TCP benigno de Hue. Son resultados exploratorios de tres capturas IoT de laboratorio, no una validación para PYMES.

## Protección y alcance

Antes de modificar archivos se verificaron 165 archivos anteriores y 32 adiciones inventariadas. El respaldo nuevo restauró 197 archivos, verificó CRC/SHA-256 y las tres SQLite restauradas resultaron íntegramente legibles y lógicamente idénticas. El proyecto no es un repositorio Git. Todos los archivos preexistentes permanecen intactos; no se descargaron datos ni se capturaron interfaces.

Respaldo: [archivo recuperable](../../../_backups/pre-pcap-experiment-20261108T201328Z-8a60a27d.zip). SHA-256: `2b2d21114e5002c3adb89630946ea4fd8dc9e4134af53c2cc26e7cf0063e5348`. [Evidencia y manifiesto](../evidence/backup.json). La restauración se conserva en la ruta allí indicada.

## Corpus efectivamente admitido

| Captura | Flujos Benign | Flujos Malicious | Grupos Benign | Grupos Malicious |
|---|---:|---:|---:|---:|
| torii | 3207 | 288 | 3192 | 6 |
| hakai | 2181 | 2056 | 2181 | 2056 |
| hue | 2107 | 0 | 359 | 0 |

Total: **9.839 flujos, 7.794 grupos de conexión, 7.495 filas Benign y 2.344 Malicious**. Se recalcularon las tres auditorías por paquete y coincidieron con todos los campos de sus informes conservados. Quedan fuera cuatro flujos de Torii, 93 de Hue y toda Trojan 42-1. Los grupos no equivalen a ataques independientes.

Los 38 predictores mantienen nombres, fórmulas y orden del contrato. Protocolo: TCP=1, UDP=0, versión `sipymes.protocol.tcp1-udp0.v1`. No hay IP, puertos, UID, identificadores, tiempos absolutos ni etiquetas como predictores. Esos campos y la calidad se conservan por separado. [Dataset/manifiesto](../run_003/dataset/manifest.json).

Desconocidos: `fewer_than_two_packets_in_direction`: 58532; `no_packets_in_direction`: 18620; `not_applicable_to_udp`: 115040. Se conservan vacíos en CSV y NaN en el modelo; no se imputan, no se añaden indicadores, no se sustituyen por cero. El bosque utiliza su tratamiento nativo de ausentes. Esta ausencia estructural también puede actuar como proxy del protocolo.

## Diseño fijado antes de evaluar

Se entrenó con Hakai+Hue para evaluar Torii; Torii+Hue para evaluar Hakai; y Torii+Hakai para evaluar Hue. Las capturas, grupos y flujos son disjuntos en cada pliegue. No hubo separación aleatoria de filas, SMOTE, búsqueda de parámetros, calibración ni selección posterior. [Contrato previo](../run_003/prespecified.json).

Dummy aprende únicamente el prior ponderado de entrenamiento. TCP predice Malicious para TCP. SYN sin ACK predice Malicious para TCP con SYN total > 0 y ACK total = 0. Random Forest: 100 árboles, profundidad máxima 8, hoja mínima 5, sqrt, bootstrap, sin class_weight, n_jobs=1, semilla 20261108. Umbral fijo >=0,5.

Dummy y bosque usan peso inverso al número de segmentos admitidos del grupo, normalizado a media 1. Cada conexión tiene igual peso total; las clases no se balancean. El bootstrap interno del bosque sigue siendo por filas ponderadas y puede omitir conexiones pequeñas: no se transforma en bootstrap por conexión.

Por flujo se cuenta cada segmento una vez. Por grupo se promedian sus probabilidades y se aplica el mismo umbral; cada grupo cuenta una vez. Las vistas por grupo se calculan después de agregar todos sus segmentos. SYN puro exige exclusivamente SYN y cero payload en los paquetes auditados.

## Resultados completos por captura y método

Matriz `[[TN,FP],[FN,TP]]`; filas reales y columnas predichas Benign/Malicious. P/R/F1 se refieren a Malicious. Todas las tasas están en [0,1]. AP es average precision, la integral escalonada PR, no integración trapezoidal. N/A conserva su motivo explícito en JSON/CSV. Hue no tiene verdaderos Malicious; recall, F1, BA y AP no son aplicables.

### Por flujo

| Captura | Modelo | Matriz | P | R | F1 | FPR | BA | AP |
|---|---|---|---:|---:|---:|---:|---:|---:|
| torii | dummy | [[3207, 0], [288, 0]] | N/A | 0.000000 | 0.000000 | 0.000000 | 0.500000 | 0.082403 |
| torii | tcp_rule | [[3206, 1], [0, 288]] | 0.996540 | 1.000000 | 0.998267 | 0.000312 | 0.999844 | 0.996540 |
| torii | syn_no_ack_rule | [[3207, 0], [284, 4]] | 1.000000 | 0.013889 | 0.027397 | 0.000000 | 0.506944 | 0.095148 |
| torii | random_forest | [[3207, 0], [284, 4]] | 1.000000 | 0.013889 | 0.027397 | 0.000000 | 0.506944 | 0.987714 |
| hakai | dummy | [[2181, 0], [2056, 0]] | N/A | 0.000000 | 0.000000 | 0.000000 | 0.500000 | 0.485249 |
| hakai | tcp_rule | [[2179, 2], [0, 2056]] | 0.999028 | 1.000000 | 0.999514 | 0.000917 | 0.999541 | 0.999028 |
| hakai | syn_no_ack_rule | [[2181, 0], [0, 2056]] | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 1.000000 | 1.000000 |
| hakai | random_forest | [[2181, 0], [0, 2056]] | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 1.000000 | 1.000000 |
| hue | dummy | [[2107, 0], [0, 0]] | N/A | N/A | N/A | 0.000000 | N/A | N/A |
| hue | tcp_rule | [[1805, 302], [0, 0]] | 0.000000 | N/A | N/A | 0.143332 | N/A | N/A |
| hue | syn_no_ack_rule | [[2107, 0], [0, 0]] | N/A | N/A | N/A | 0.000000 | N/A | N/A |
| hue | random_forest | [[1810, 297], [0, 0]] | 0.000000 | N/A | N/A | 0.140959 | N/A | N/A |

### Por grupo

| Captura | Modelo | Matriz | P | R | F1 | FPR | BA | AP |
|---|---|---|---:|---:|---:|---:|---:|---:|
| torii | dummy | [[3192, 0], [6, 0]] | N/A | 0.000000 | 0.000000 | 0.000000 | 0.500000 | 0.001876 |
| torii | tcp_rule | [[3191, 1], [0, 6]] | 0.857143 | 1.000000 | 0.923077 | 0.000313 | 0.999843 | 0.857143 |
| torii | syn_no_ack_rule | [[3192, 0], [2, 4]] | 1.000000 | 0.666667 | 0.800000 | 0.000000 | 0.833333 | 0.667292 |
| torii | random_forest | [[3192, 0], [2, 4]] | 1.000000 | 0.666667 | 0.800000 | 0.000000 | 0.833333 | 0.948413 |
| hakai | dummy | [[2181, 0], [2056, 0]] | N/A | 0.000000 | 0.000000 | 0.000000 | 0.500000 | 0.485249 |
| hakai | tcp_rule | [[2179, 2], [0, 2056]] | 0.999028 | 1.000000 | 0.999514 | 0.000917 | 0.999541 | 0.999028 |
| hakai | syn_no_ack_rule | [[2181, 0], [0, 2056]] | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 1.000000 | 1.000000 |
| hakai | random_forest | [[2181, 0], [0, 2056]] | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 1.000000 | 1.000000 |
| hue | dummy | [[359, 0], [0, 0]] | N/A | N/A | N/A | 0.000000 | N/A | N/A |
| hue | tcp_rule | [[310, 49], [0, 0]] | 0.000000 | N/A | N/A | 0.136490 | N/A | N/A |
| hue | syn_no_ack_rule | [[359, 0], [0, 0]] | N/A | N/A | N/A | 0.000000 | N/A | N/A |
| hue | random_forest | [[315, 44], [0, 0]] | 0.000000 | N/A | N/A | 0.122563 | N/A | N/A |

### Protocolo y comportamiento del bosque

Los resultados de **todos** los métodos por TCP, UDP, SYN puro y otros comportamientos, por flujo y grupo, están en [metrics.csv](./metrics.csv), 120 combinaciones, incluidas las vistas vacías. Las probabilidades descriptivas por clase/patrón están en [pattern_scores.csv](./pattern_scores.csv).

| Captura | Unidad | Vista | B/M reales | Matriz | Recall M | FPR |
|---|---|---|---|---|---:|---:|
| torii | flow | tcp | 1/288 | [[1, 0], [284, 4]] | 0.013889 | 0.000000 |
| torii | flow | udp | 3206/0 | [[3206, 0], [0, 0]] | N/A | 0.000000 |
| torii | flow | tcp_pure_syn | 0/4 | [[0, 0], [0, 4]] | 1.000000 | N/A |
| torii | flow | tcp_other | 1/284 | [[1, 0], [284, 0]] | 0.000000 | 0.000000 |
| torii | group | tcp | 1/6 | [[1, 0], [2, 4]] | 0.666667 | 0.000000 |
| torii | group | udp | 3191/0 | [[3191, 0], [0, 0]] | N/A | 0.000000 |
| torii | group | tcp_pure_syn | 0/4 | [[0, 0], [0, 4]] | 1.000000 | N/A |
| torii | group | tcp_other | 1/2 | [[1, 0], [2, 0]] | 0.000000 | 0.000000 |
| hakai | flow | tcp | 2/2056 | [[2, 0], [0, 2056]] | 1.000000 | 0.000000 |
| hakai | flow | udp | 2179/0 | [[2179, 0], [0, 0]] | N/A | 0.000000 |
| hakai | flow | tcp_pure_syn | 0/2056 | [[0, 0], [0, 2056]] | 1.000000 | N/A |
| hakai | flow | tcp_other | 2/0 | [[2, 0], [0, 0]] | N/A | 0.000000 |
| hakai | group | tcp | 2/2056 | [[2, 0], [0, 2056]] | 1.000000 | 0.000000 |
| hakai | group | udp | 2179/0 | [[2179, 0], [0, 0]] | N/A | 0.000000 |
| hakai | group | tcp_pure_syn | 0/2056 | [[0, 0], [0, 2056]] | 1.000000 | N/A |
| hakai | group | tcp_other | 2/0 | [[2, 0], [0, 0]] | N/A | 0.000000 |
| hue | flow | tcp | 302/0 | [[5, 297], [0, 0]] | N/A | 0.983444 |
| hue | flow | udp | 1805/0 | [[1805, 0], [0, 0]] | N/A | 0.000000 |
| hue | flow | tcp_pure_syn | 0/0 | [[0, 0], [0, 0]] | N/A | N/A |
| hue | flow | tcp_other | 302/0 | [[5, 297], [0, 0]] | N/A | 0.983444 |
| hue | group | tcp | 49/0 | [[5, 44], [0, 0]] | N/A | 0.897959 |
| hue | group | udp | 310/0 | [[310, 0], [0, 0]] | N/A | 0.000000 |
| hue | group | tcp_pure_syn | 0/0 | [[0, 0], [0, 0]] | N/A | N/A |
| hue | group | tcp_other | 49/0 | [[5, 44], [0, 0]] | N/A | 0.897959 |

## Interpretación y sesgos

En Torii, RF y SYN sin ACK toman exactamente las mismas decisiones: cuatro segmentos SYN maliciosos detectados y 284 segmentos de dos conexiones maliciosas distintas de SYN puro omitidos. El recall por flujo es 1,39 %, mientras por grupo es 66,67 % (4/6): la diferencia nace de la segmentación, no de 284 ataques adicionales.

En Hakai, RF y SYN sin ACK vuelven a coincidir completamente, con F1=1. Todos los 2.056 grupos maliciosos son SYN puro. Este resultado perfecto no demuestra diversidad ni capacidad general de detección.

En Hue, el bosque produce 297 falsos positivos de 2.107 flujos y 44 de 359 grupos. Entre TCP, falla en 297/302 flujos (98,34 %) y 44/49 grupos (89,80 %). UDP diluye la FPR global a 14,10 % y 12,26 %. Dummy y SYN sin ACK no producen falsos positivos en Hue. La regla TCP produce 302 y 49, respectivamente.

La regla TCP supera al bosque en recall sobre Torii, pero falla sobre Hue. No se elige esa regla como sustituto: estos son resultados exploratorios de modelos fijados previamente. El bosque supera a SYN sin ACK en AP sobre Torii (ranking), pero no en decisiones al umbral fijado. Una AP alta no elimina el mal recall operativo. No se ajustó el umbral con esta captura ni se reclama que el bosque implemente únicamente SYN.

Las importancias por impureza asignan aproximadamente 45,15 %, 48,32 % y 43,98 % a banderas TCP en los pliegues Torii, Hakai y Hue. La columna protocolo tiene poca importancia directa, pero sus proxies incluyen tamaños, intervalos y ausencias estructurales. Estas importancias correlacionadas no prueban causalidad ni constituyen una ablación independiente.

El corpus tiene 52 grupos TCP benignos; solo 49 son bidireccionales y todos vienen de Hue, con payload en ambos sentidos en siete. De 2.062 grupos maliciosos, 2.060 son SYN puro y solo dos tienen otro patrón. Una conexión TCP de Hue genera 254 segmentos. Persisten sesgos de dispositivo, familia, periodo, protocolo, etiquetado y exclusión conservadora de casos difíciles. No hay Malicious UDP admitido. Tres capturas no permiten una separación robusta adicional de entrenamiento/validación/prueba. Los pliegues tampoco representan una evaluación prospectiva cronológica.

## Recursos medidos

La construcción del corpus y nueva auditoría consumieron 37.881 s; pico RSS muestreado 631.92 MiB. La ejecución canónica ocupa 48,004,036 bytes; sus 12 modelos comprimidos suman 39,592 bytes. La memoria se muestrea cada 10 ms: no es un pico exacto, incluye datos residentes y no equivale al tamaño del modelo. [Recursos de los 12 modelos](./resources.csv).

| Captura evaluada | RF entrenamiento s | Inferencia lote s | Pico RSS entrenamiento MiB | Archivo bytes |
|---|---:|---:|---:|---:|
| torii | 0.491086 | 0.011932 | 293.12 | 11921 |
| hakai | 0.492221 | 0.041672 | 293.41 | 12163 |
| hue | 0.740887 | 0.019083 | 295.39 | 11922 |

Python 3.14.6; dependencias: {"joblib": "1.6.0", "numpy": "2.5.4", "psutil": "7.2.2", "scikit-learn": "1.9.1"}. No se instalaron dependencias. El entorno, código y configuraciones tienen hashes registrados.

## Pruebas, corrección y reproducibilidad

Resultado final: **42 pruebas específicas y 229 completas aprobadas**, 0 fallos, 0 errores y 0 omisiones en la suite final. [Específicas](../evidence/specific_final.json), [suite completa](../evidence/full_final.json).

Se detectó una corrección real de precisión numérica: np.mean podía asignar distintos últimos bits a grupos de diferente longitud con idéntico prior Dummy. Eso rompía empates y alteraba AP por grupo. Torii Dummy pasó de AP=0.001407732775 a 0.001876172608, exactamente su prevalencia 6/3198. Se añadió una regresión que primero falló (41 aprobadas, un fallo), y luego pasó al conservar probabilidades idénticas exactamente y usar suma precisa para las demás. No cambió ningún modelo, predictor, partición, umbral ni predicción por flujo. Las ejecuciones iniciales run_001/run_002 permanecen conservadas y están sustituidas para informar métricas por run_003/run_004. [Corrección y comparación](../evidence/numerical_correction.json).

Dos ejecuciones corregidas verificaron 53 comprobaciones de identidad: corpus/manifiesto, contrato, modelos serializados, predicciones por flujo/grupo y métricas. Tiempos y RSS se excluyen de la identidad porque se vuelven a medir. [Repetición](../evidence/replay_final.json). Los 12 pipelines locales recargados produjeron exactamente sus predicciones anteriores; cada uno consume 38 columnas. [Recarga verificada](../evidence/model_roundtrip.json).

Los 197 archivos preexistentes comprobados permanecen idénticos y las tres SQLite devuelven ok. El extractor 1.0.1, auditor, características, timeouts, interfaz, CSV y modelos UNSW no cambiaron. [Integridad final](../evidence/integrity_final.json). También se verificaron los siete respaldos anteriores.

## Entregables, reproducción y reversión

Código nuevo: [pcap_experiment](../../../pcap_experiment/), con contrato, corpus, modelos, evaluación, ejecución y validación; [pruebas nuevas](../../../tests/test_pcap_experiment.py). [Instrucciones reproducibles](../../../pcap_experiment/README.md). Cada ejecución contiene dataset/manifiesto, contrato previo, entorno, tres particiones, cuatro modelos por partición, predicciones y resultados. No existe un modelo final entrenado con todo el corpus y no se ha integrado ninguno.

Para revertir basta con apartar los archivos nuevos indicados por el inventario; ningún componente original necesita sustitución. Se conserva el respaldo y la restauración verificada para recuperar archivos concretos en una carpeta separada. No restaurar sobre una SQLite abierta.

## Recomendación

Dar por completado el experimento como prueba funcional del proceso de aprendizaje. **No integrar este RF como detector ni reemplazar el modelo original.** Si se desea avanzar en clasificación, hace falta una ampliación dirigida que aporte TCP benigno de otras capturas/dispositivos y conexiones maliciosas no limitadas a SYN puro en capturas independientes. No hace falta recopilar indefinidamente para cerrar el software experimental: el resultado negativo ya está medido y es reproducible. Cualquier calibración posterior necesita datos independientes; estas capturas ya no constituyen una prueba final intacta. Mirai 34-1 y Amazon Echo 5-1 siguen reservados y no se han utilizado.
