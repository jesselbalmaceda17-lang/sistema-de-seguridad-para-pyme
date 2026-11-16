# Piloto de correspondencia PCAP–etiquetas: IoT-23, escenario 20-1

Fecha de ejecución: **2026-11-08**. Alcance: fase 2, etapa B; importación y
auditoría offline independientes. **El piloto no permite preparar todavía un
conjunto binario de entrenamiento**: se conservan 3.207 correspondencias con
etiqueta Benign, pero ninguna de las 16 conexiones Malicious de referencia
supera todas las comprobaciones conservadoras. No se ha entrenado un modelo
operativo, cambiado el extractor ni integrado PCAP en el panel.

## Resultado ejecutado

La extracción real utilizó el extractor **1.0.1**, esquema
`sipymes.offline.ipv4.v1`, y **TShark 4.6.9**, ejecutado por su ruta absoluta de
Windows. La salida identifica el ejecutable, versión, configuración y hash de
la captura. Los 3.499 flujos contienen las 38 características originales.

| Medida | Resultado |
| --- | ---: |
| Paquetes leídos | 50.156 |
| Paquetes aceptados por el extractor | 41.207 |
| Paquetes excluidos: `unsupported_ethernet_payload` | 8.949 |
| Cobertura de extracción: aceptados / leídos | 82,157668 % |
| Flujos extraídos | 3.499 |
| Conexiones de referencia importadas | 3.209 |
| Filas de referencia rechazadas | 0 |
| Correspondencias inequívocas admitidas | 3.207 |
| Ambiguas: más de una referencia cubre completamente el flujo | 0 |
| Sin referencia de la misma tupla y con soporte temporal | 0 |
| Diferencias de segmentación | 6 |
| Referencia incompleta que impide la correspondencia | 0 |
| Referencias contradictorias que impiden la correspondencia | 0 |
| Flujos rechazados por incompatibilidad de contadores | 286 |
| Cobertura por flujos: 3.207 / 3.499 | 91,654759 % |
| Referencias con al menos un flujo admitido: 3.192 / 3.209 | 99,470240 % |
| Paquetes en flujos etiquetados | 5.996 |
| Cobertura de etiquetas sobre paquetes aceptados: 5.996 / 41.207 | 14,550926 % |
| Cobertura de etiquetas sobre todos los paquetes: 5.996 / 50.156 | 11,954701 % |

Los estados de flujo son mutuamente excluyentes; suman 3.499. Cero en
`ambiguous` no significa que todos los casos estén resueltos: hay cinco flujos
con varias referencias solapadas que se contabilizan como diferencias de
segmentación, además de otro cubierto solo parcialmente. Los 286 conflictos de
contadores también quedan sin etiqueta.

| Etiqueta original | Referencias | Referencias con flujo admitido | Flujos admitidos |
| --- | ---: | ---: | ---: |
| Benign | 3.193 | 3.192 | 3.207 |
| Malicious | 16 | 0 | 0 |

La cobertura Malicious es **0 %**. La alta cobertura global por número de flujos
oculta que las conexiones largas concentran muchos paquetes y permanecen sin
etiqueta. Estas cifras miden correspondencia bajo una política explícita; no
son precisión, recall ni resultados de detección de ataques.

Evidencias completas:

- [Informe de auditoría por flujo y referencia](../data/processed/iot23_pilot_20_1/audit_exact/label_audit.json).
- [Referencias importadas, valores originales y motivos de ausencia](../data/processed/iot23_pilot_20_1/audit_exact/imported_labels.json).
- [Extracción real con características, calidad y configuración](../data/processed/iot23_pilot_20_1/extraction.json).
- [Diagnósticos, seis casos de segmentación y tres grupos de contadores](./validacion_iot23_piloto_20_1/evidencia_correspondencias.json).

## Fuentes y versión

Se consultó el [índice oficial de IoT-23](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/),
el [directorio oficial del escenario](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/),
su [subdirectorio de conexiones](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/bro/)
y el [README oficial](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/README.md)
**antes de solicitar los dos archivos de datos**. Ambos están publicados bajo
el mismo escenario de la distribución v1. El README corrobora la familia de
escenario, fecha y host. La [descripción de Stratosphere IPS](https://www.stratosphereips.org/datasets-iot23)
publica para este escenario 3.193 conexiones Benign y 16 Malicious, distribución
que coincide con el archivo obtenido. El [registro de publicación 1.0.0](https://zenodo.org/records/4743746)
sirve como referencia de versión.

La pertenencia a v1 se verifica documentalmente mediante estas fuentes. **No
se verificó identidad byte a byte frente al archivo completo de Zenodo**: no
se descargó ese archivo ni el dataset completo. Los hashes siguientes fijan
exactamente el par oficial individual utilizado y permiten distinguir futuras
revisiones del servidor.

| Archivo y URL oficial | Bytes | Obtención UTC |
| --- | ---: | --- |
| [PCAP del escenario](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap) | 4.057.401 | 2026-11-08T15:52:19.097606+00:00 |
| [Conexiones etiquetadas](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled) | 419.604 | 2026-11-08T15:52:22.736652+00:00 |

SHA-256 del PCAP:

```text
4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9
```

SHA-256 de las conexiones:

```text
ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711
```

El [manifiesto de procedencia](../data/raw/iot23_pilot_20_1/provenance.json)
incluye URLs, tamaños, fechas, hashes, Last-Modified, ETag cuando existe y
hashes de los metadatos consultados. Son 4.477.005 bytes de datos, además de
cuatro documentos pequeños de procedencia; no se descargaron otros escenarios
ni muestras ejecutables de malware.

La adquisición usa `curl.exe` preexistente de Windows con validación HTTPS
mediante Schannel, sin `--insecure`, instalaciones ni cambios de certificados.
La lectura inicial con urllib no pudo validar la cadena de certificados local;
el transporte nativo completó la descarga con verificación TLS habilitada.
Hay límites de cinco millones de bytes para el PCAP y un millón para las
etiquetas, tiempos máximos y rechazo de redirecciones o sobrescrituras.

## Contrato del importador y del auditor

El [importador](../seguridad_pymes/zeek_labels.py) versionado
`sipymes.zeek-labels.v1` interpreta las cabeceras ASCII de Zeek: separador,
campos, tipos, valores vacíos y no establecidos. Contempla la particularidad de
IoT-23: las tres columnas finales se separan mediante varios espacios aunque
las columnas anteriores usan tabuladores. Conserva UID, línea de origen,
campos originales, SHA-256 y un identificador derivado del hash y la línea.

Los valores ausentes, vacíos, inválidos o no reconocidos se representan como
`null` con motivo explícito. Las filas con número incorrecto de columnas se
ponen en cuarentena con línea y hash; no se rellenan. Los tipos declarados y
las cabeceras obligatorias se validan. Se detectan UID duplicados, registros
contradictorios y etiquetas incompatibles para la misma tupla e intervalo.

En este archivo hay 885 duraciones no establecidas. Los contadores de cada
una demuestran que se observó exactamente un paquete: el auditor puede usar
el instante inicial como soporte puntual **sin cambiar la duración original
`null`**. Hay 3.201 registros con algún `field_problems`; muchos corresponden
al detalle `-` válido de Benign o a estas duraciones desconocidas. Esa cifra
no significa 3.201 filas corruptas: no se rechazó ninguna fila del piloto.

El [auditor](../seguridad_pymes/label_audit.py), contrato
`sipymes.label-audit.v1`, aplica estas reglas:

1. Comprueba que los hashes de PCAP y etiquetas coincidan con el manifiesto;
   exige extractor 1.0.1 y esquema original. Rechaza identificadores de flujo
   duplicados y verifica conservación del total de paquetes aceptados.
2. Usa protocolo y el par no ordenado de extremos IPv4/puerto; una conexión
   invertida conserva la misma clave, pero intercambia los contadores por
   dirección al compararlos. No interpreta forward como cliente.
3. Convierte tiempos decimales a nanosegundos enteros sin redondear. Exige que
   una única referencia cubra **todo** el intervalo observado del flujo,
   usando intervalos cerrados y **tolerancia de cero nanosegundos**. No usa
   vecinos más cercanos, tolerancias implícitas ni coincidencias por nombre.
4. Examina también las referencias que solo se solapan parcialmente. Dos
   referencias cubrientes generan ambigüedad; un flujo que atraviesa varias
   referencias o rebasa su soporte queda como diferencia de segmentación.
   Una referencia con final desconocido que no puede excluirse impide asignar
   etiqueta. La reutilización de puertos se resuelve por intervalos separados.
5. Admite varios segmentos del extractor dentro de una referencia únicamente
   cuando no hay competidores y sus contadores conocidos son compatibles.
   Compara paquetes y **bytes IP**, incluidos encabezados, con `orig_pkts`,
   `resp_pkts`, `orig_ip_bytes` y `resp_ip_bytes`; no compara bytes IP con bytes
   de aplicación. Cada segmento y la suma de segmentos admitidos deben ser
   menores o iguales que su referencia. Un exceso conjunto revoca todas las
   etiquetas de ese grupo. Un contador desconocido sigue desconocido y no
   demuestra igualdad ni se reemplaza por cero.
6. Conserva la etiqueta original. Solo Benign y Malicious tienen equivalencia
   binaria explícita 0 y 1; cualquier otro valor permanece desconocido. Un
   host infectado, el nombre de un archivo o varias etiquetas iguales no
   justifican forzar una correspondencia.

Estos criterios aportan trazabilidad conservadora, pero no demuestran que
Zeek y el extractor hayan considerado exactamente los mismos paquetes. Los
contadores son condiciones de compatibilidad, no identificadores de paquetes.
La política y sus límites quedan en cada informe; no se afirma una verdad de
terreno más precisa que las referencias publicadas.

## Discrepancias verificables

El extractor conserva los timeouts originales: TCP inactivo 120 s, UDP
inactivo 30 s y límite activo 300 s; orientación por primer paquete observado.
Quince referencias se distribuyen entre varios segmentos admitidos. Esta
diferencia de unidad de análisis debe conservarse en cualquier entrenamiento
futuro para evitar separar segmentos de una misma conexión entre particiones.

Se encontraron tres grupos con exceso de contadores:

| UID Zeek | Etiqueta | Flujos excluidos | Diferencia observada |
| --- | --- | ---: | --- |
| `CyLMgu8PRDfN5yuLj` | Malicious | 137 | Suma `orig_ip_bytes` 348.990 frente a 348.808: exceso de 182 bytes |
| `CGLDvm3X8xOnv1Rfwf` | Malicious | 148 | Suma orig 8.873 paquetes frente a 8.872; resp 9.308 frente a 9.307; bytes orig 374.513 frente a 372.893 y resp 391.935 frente a 388.975 |
| `Cs2uux2Y3UfNwPD9Yd` | Benign | 1 | Respuesta 3 paquetes y 219 bytes IP frente a 2 paquetes y 146 bytes |

Las dos referencias Malicious anteriores publican `missed_bytes` de 1.579 y
4.500. Es un dato de procedencia, **no una explicación demostrada** de todas
las diferencias. No se atribuye la causa a pérdida de captura, paquetes
duplicados, checksum o un defecto del extractor sin una inspección posterior
por paquete y de las convenciones/versiones de Zeek.

Las diferencias de segmentación incluyen secuencias TCP SYN para las que el
extractor genera un flujo mientras Zeek publica varias conexiones. Por
ejemplo, el puerto origen 38086 tiene un flujo de cinco paquetes y tres
referencias candidatas. Aunque sus etiquetas coincidan, el auditor no las
fusiona ni las adjudica como una conexión inequívoca. Los seis casos, sus
intervalos, contadores y líneas originales están en la
[evidencia de correspondencias](./validacion_iot23_piloto_20_1/evidencia_correspondencias.json).

El total de paquetes conocido de las referencias utilizables es 41.203,
frente a 41.207 aceptados por el extractor. No basta con corregir esta
diferencia global de cuatro paquetes: las discrepancias de bytes y de
segmentación requieren una reconciliación independiente.

## Pruebas y preservación del proyecto

Suite completa ejecutada mediante `unittest` en el entorno virtual existente:
**134 aprobadas, 0 fallos, 0 errores, 0 omitidas**, sin fallos esperados ni
éxitos inesperados. Ejecución UTC 16:07:48–16:08:08 del 2026-11-08.

- [Salida completa de los 134 métodos](./validacion_iot23_piloto_20_1/pruebas_completas.log).
- [Resultado estructurado](./validacion_iot23_piloto_20_1/resultado_pruebas.json).
- [35 pruebas nuevas](../tests/test_label_audit.py): 12 de importación, 18 de
  correspondencia, cuatro de adquisición controlada y una de regresión con
  el par oficial local. Incluyen ausencia de coincidencia, dirección invertida,
  reutilización de puertos, registros incompletos, un nanosegundo fuera del
  intervalo, contradicciones, ambigüedad, segmentación, presupuestos conjuntos
  de paquetes/bytes, hashes y repetibilidad sin mutar entradas.

Las pruebas unitarias no descargan datos. La regresión local vuelve a importar
y auditar la extracción guardada y verifica los hashes del par; no repite la
extracción real del escenario. En un equipo sin ese par la regresión se omite
explícitamente. En esta ejecución estuvo presente y **no hubo omisiones**.
También se ejecutaron las 99 pruebas preexistentes, incluidas las que usan
TShark con PCAP/PCAPNG controlados. Las pruebas antiguas de entrenamiento usan
fixtures temporales; no entrenan ni sobrescriben los modelos operativos.

No existe un repositorio Git en esta carpeta ni en sus antecesores:
`git status` informa `not a git repository`. No se inicializó uno ni se
presenta un diff o commit inexistente.

Antes de los cambios se creó el
[respaldo recuperable de 69 archivos](../_backups/pre-iot23-pilot-20261108T154817Z-558de56f.zip),
con manifiesto y snapshots consistentes de las tres bases SQLite. Después de
la suite se verificaron los SHA-256 de los **69 archivos originales sin
cambios**, la CRC del ZIP y la restauración de sus 69 entradas a una carpeta
temporal. `PRAGMA integrity_check` dio `ok` en las tres bases originales y en
las tres copias restauradas. Los dos respaldos previos se conservan y también
pasaron la verificación CRC.

SHA-256 del nuevo respaldo:

```text
c0b4eddf3cfe19a9b25c91853cb34ce2846c797a29b99b31e72344bf21a0883d
```

La [evidencia de integridad](./validacion_iot23_piloto_20_1/integridad.json)
enumera los 69 archivos, hashes y comprobaciones de SQLite y respaldos. La
primera comprobación de restauración encontró un bloqueo al limpiar una copia
SQLite temporal: el contexto de una conexión SQLite no la cierra. Se corrigió
el script de verificación usando cierre explícito y se completó la
restauración de nuevo. No fue un fallo de la suite ni requirió cambiar código
del producto o bases del proyecto.

La preservación byte a byte y las pruebas existentes cubren la ruta CSV,
Streamlit, SQLite, modelos y sus metadatos, y las definiciones de las 38
características. No se hizo una sesión manual interactiva del panel ni una
evaluación nueva de detección; no se afirma haberlas realizado.

## Archivos añadidos y alcance pendiente

**Archivos preexistentes modificados o eliminados: ninguno.** Se añadieron:

- [Adquisición limitada y manifiesto](../seguridad_pymes/iot23_sources.py).
- [Importador independiente de Zeek](../seguridad_pymes/zeek_labels.py).
- [Auditor independiente y CLI](../seguridad_pymes/label_audit.py).
- [Pruebas](../tests/test_label_audit.py).
- [Par oficial pequeño y manifiesto](../data/raw/iot23_pilot_20_1/).
- [Extracción y auditoría JSON](../data/processed/iot23_pilot_20_1/).
- Este informe y las [evidencias de validación](./validacion_iot23_piloto_20_1/).
- El respaldo previo a esta etapa, conservando los anteriores.

El JSON de extracción ocupa 22.680.150 bytes porque contiene las 38 medidas y
su calidad por flujo. El alcance sigue siendo el escenario pequeño, no un
procesador masivo de todo IoT-23. No se instalaron dependencias, se cambiaron
fórmulas/timeouts ni se consultaron interfaces reales.

Quedan pendientes la reconciliación por paquete de los contadores, el estudio
de la segmentación de Zeek frente al extractor y un criterio de aceptación
para etiquetas maliciosas que tenga evidencia suficiente. No están
implementados entrenamiento, selección de variables, evaluación de un nuevo
modelo, clasificación PCAP, alertas desde capturas ni monitoreo en tiempo real.
El siguiente paso defendible es investigar las discrepancias manteniendo
versionadas las reglas; no entrenar con las correspondencias actuales ni
relajar tolerancias para aumentar artificialmente la cobertura.

## Reproducción y reversión

Desde la raíz del proyecto, usando destinos **nuevos** para evitar
sobrescrituras:

```powershell
# Solo si se desea otra adquisición explícita del mismo par pequeño:
.\.venv\Scripts\python.exe -B -m seguridad_pymes.iot23_sources data/raw/iot23_20_1_nueva_adquisicion

# Para repetir con los archivos ya obtenidos, elegir una salida nueva:
.\.venv\Scripts\python.exe -B -m seguridad_pymes.pcap_extract data/raw/iot23_pilot_20_1/2018-10-02-13-12-30-192.168.100.103.pcap --output data/processed/iot23_pilot_20_1/extraction_repetida.json --tshark "C:\Program Files\Wireshark\tshark.exe"
.\.venv\Scripts\python.exe -B -m seguridad_pymes.label_audit data/processed/iot23_pilot_20_1/extraction_repetida.json data/raw/iot23_pilot_20_1/conn.log.labeled data/raw/iot23_pilot_20_1/provenance.json --output data/processed/iot23_pilot_20_1/audit_repetida
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Estos comandos documentan cómo repetir la ejecución; la extracción guardada
del escenario se ejecutó una vez durante este piloto. La suite y la auditoría
sí verifican repetibilidad mediante sus casos controlados y regresión local.

Para revertir, basta con dejar de usar los módulos añadidos: no hay cambios en
los puntos de entrada del producto. Si se necesita recuperar un proyecto
anterior a esta etapa, extraer el respaldo **a una carpeta nueva**, validar su
manifiesto y las bases SQLite, y usar el entorno virtual/dependencias ya
existentes. El respaldo no incluye el entorno virtual ni cachés. No extraerlo
sobre las bases de trabajo abiertas. Los datos y evidencias del piloto pueden
conservarse aparte; no es necesario borrar ningún modelo, base, captura ni
respaldo para volver al funcionamiento previo.
