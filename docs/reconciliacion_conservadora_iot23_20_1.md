# Reconciliación conservadora de etiquetas: IoT-23 20-1

Fecha: **2026-11-08**. Contrato nuevo: `sipymes.label-audit.v2`.
Se implementó únicamente la auditoría por paquete, sus pruebas y esta
documentación. El extractor **1.0.1**, las 38 características, sus fórmulas y
sus timeouts permanecen intactos. No se entrenó ningún modelo operativo ni
se incorporó clasificación PCAP al panel.

## Resultado real y comparación

La captura se volvió a procesar con TShark **4.6.9** desde su ruta absoluta.
La extracción completa resultó **idéntica byte a byte** a la de la etapa B:
50.156 paquetes leídos, 41.207 aceptados, 8.949 excluidos y 3.499 flujos.
Las 3.209 referencias originales de Zeek se importaron sin modificarlas.

| Medida | Auditoría anterior v1 | Auditoría por paquete v2 |
| --- | ---: | ---: |
| Flujos con correspondencia admitida | 3.207 | **3.495** |
| Flujos sin etiqueta admitida | 292 | **4** |
| Cobertura por flujos | 91,654759 % | **99,885682 %** |
| Paquetes contenidos en flujos admitidos | 5.996 | **40.921** |
| Cobertura sobre los 41.207 paquetes aceptados | 14,550926 % | **99,305943 %** |
| Cobertura sobre los 50.156 paquetes leídos | 11,954701 % | **81,587447 %** |
| Referencias con al menos un flujo admitido | 3.192 | **3.206** |
| Cobertura de referencias, sobre 3.209 | 99,470240 % | **99,906513 %** |
| Referencias Malicious con flujo admitido | 0 / 16 | **14 / 16** |
| Flujos admitidos con etiqueta original Malicious | 0 | **288** |
| Flujos admitidos con etiqueta original Benign | 3.207 | **3.207** |

El aumento de cobertura se obtuvo mediante reglas documentadas y evidencias
por frame. No es una medida de precisión, recall, detección de ataques o
eficacia del Random Forest. La etiqueta transferida mantiene el significado
y las limitaciones de la referencia del laboratorio.

| Estado v2 | Flujos |
| --- | ---: |
| `admitted_unique` | 3.177 |
| `admitted_sibling_segment` | 313 |
| `admitted_partition` | 4 |
| `admitted_tcp_closure` | 1 |
| `quarantined_partial_checksum` | 3 |
| `counter_mismatch` | 1 |
| **Total** | **3.499** |

Las 313 correspondencias entre segmentos hermanos incluyen 30 flujos Benign
ya cubiertos por v1 y 283 segmentos Malicious recuperados. El cierre TCP y las
cuatro particiones completan los 288 flujos adicionales admitidos.

Hay **3.495 admitidos, 4 pendientes en cuarentena y 0 rechazos terminales**.
Para este resumen, los estados terminales son `not_found`, `ambiguous` y
`contradictory`; el resto de estados no admitidos permanece pendiente. Por
tanto, «cero rechazos terminales» no significa cobertura del 100 % ni que los
cuatro flujos pendientes tengan etiqueta válida. Todos conservan
`binary_label: null`.

## Evidencias entregadas

- [Resumen de ejecución y extracción real](./validacion_reconciliacion_iot23_20_1/ejecucion_piloto.json).
- [Evidencia compacta: cobertura, referencias recuperadas, cuarentenas, checksum y cierre](./validacion_reconciliacion_iot23_20_1/evidencia_compacta.json).
- [Auditoría completa, con el registro de los 50.156 frames](./validacion_reconciliacion_iot23_20_1/audit_v2/label_audit.json).
- [Referencias importadas y campos originales](./validacion_reconciliacion_iot23_20_1/audit_v2/imported_labels.json).
- [Extracción repetida](./validacion_reconciliacion_iot23_20_1/extraccion_repetida.json).
- [Comprobación independiente de checksum con TShark](./validacion_reconciliacion_iot23_20_1/checksum_tshark.tsv)
  y [comando, código de salida y fecha](./validacion_reconciliacion_iot23_20_1/checksum_tshark_comando.json).
- [Integridad de archivos protegidos, SQLite y respaldos](./validacion_reconciliacion_iot23_20_1/integridad.json).

SHA-256 de ambas extracciones, anterior y repetida:

```text
12113adbf60e0c5f3adcd493b2ab15c8e1b65cd7cf4108459f9ab04a6dbcf77b
```

SHA-256 de la auditoría v2 completa:

```text
614b80b18b349962e5aaad4cb3f8752f8ec380bf4aa9f7ef769234e972abd361
```

La auditoría se volvió a calcular después de las pruebas finales, leyendo
otra vez el PCAP y las etiquetas, y coincidió estructuralmente con el informe
guardado. Esa comprobación está registrada en la evidencia compacta. No se
generó una segunda copia del informe completo de 71.245.827 bytes.

## Reglas implementadas

### Vinculación con los archivos originales

El [auditor](../seguridad_pymes/label_audit.py) conserva el contrato v1 para
comparación histórica y añade la API `audit_packet_correspondences`. La CLI
activa v2 cuando recibe `--capture`; sin ese argumento conserva v1. Un informe
v1 no debe presentarse como una reconciliación por paquete.

Antes de admitir correspondencias, v2 verifica hash de la captura, número
total de frames, pertenencia exclusiva de cada paquete a un flujo, tupla,
protocolo, paquetes y bytes por dirección y marcas inicial/final del flujo.
Una discrepancia entre el PCAP y la extracción hace fallar la operación antes
de escribir un informe. La API v2 no funciona sin evidencia de paquetes.

Cada entrada de `packet_ledger` conserva número de frame, timestamp entero en
nanosegundos, hash de los bytes del paquete, tamaños, extremos observados,
checksum, secuencias/banderas TCP cuando corresponden, flujo, referencias
candidatas, referencia de contabilización, UID, línea original y regla de
soporte. También distingue si el flujo completo recibió una etiqueta.
Los frames ajenos a la extracción permanecen visibles como
`outside_extraction`, con el motivo correspondiente; no se asignan a una
referencia ni se rellenan campos de transporte desconocidos.

### Checksum y conservación de referencias

El lector independiente calcula el checksum IP y el de transporte a partir
de los bytes, incluido el pseudoencabezado. Distingue:

- `valid`: satisface el checksum completo.
- `partial_pseudoheader`: no satisface el checksum completo, pero el valor
  almacenado coincide exactamente con la suma plegada del pseudoencabezado.
- `incorrect`: no satisface ninguno de los dos casos anteriores.
- `not_present_ipv4_udp`: ausencia permitida del checksum UDP en IPv4,
  registrada explícitamente; no equivale a haberlo validado.

«Parcial» identifica un patrón matemático compatible con offload, no una
prueba absoluta de su causa física. «Incorrecto» describe los bytes guardados,
no demuestra por sí solo corrupción en el cable. TShark 4.6.9 reconoció el
patrón parcial en los mismos cuatro frames. La distinción concuerda con la
[documentación de Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html).

**Todo flujo que contiene un checksum parcial o incorrecto permanece sin
etiqueta.** No se elimina el paquete, se corrigen bytes ni se recalculan
características quitándolo. Un checksum IP incorrecto invalida también la
evidencia de la referencia afectada.

Para recuperar hermanos de un flujo con checksum parcial se exige, además:

1. Asignación exclusiva por protocolo, extremos y tiempos exactos.
2. Los cuatro contadores Zeek conocidos y conservados por igualdad, después
   de separar únicamente los paquetes con patrón parcial demostrado.
3. Evidencia original `C` o `c` en la dirección correspondiente del historial.
4. `missed_bytes` conocido e igual a la suma de los payloads parciales
   identificados para esa referencia.
5. Testigos de los límites publicados: primer paquete contabilizado en el
   inicio y algún paquete contabilizado en el final declarado.

La falta de cualquiera de estas condiciones impide recuperar los hermanos.
Un checksum realmente incorrecto según los bytes no se utiliza como una
excepción de offload. Los valores desconocidos no se sustituyen por cero.
La igualdad de contadores es más exigente que la compatibilidad por límites
superiores que empleaba v1.

En este piloto se identificaron frames 266, 24789, 24825 y 24828 con patrón
parcial: suman 7.821 bytes IP y explican la diferencia global de cuatro
paquetes entre PCAP y referencias. No apareció ningún checksum de transporte
de categoría `incorrect`; su tratamiento se verificó con fixtures negativos.

### ACK final

No se introdujo una tolerancia temporal. La excepción exige un ACK puro sin
payload y los dos paquetes inmediatamente anteriores de la misma tupla:
FIN+ACK en direcciones opuestas, checksums completos válidos, secuencias y
reconocimientos exactos módulo 2^32. El segundo FIN debe estar exactamente en
el final declarado por Zeek; la referencia debe publicar `SF` y ambos FIN en
su historial. Finalmente deben conservarse todos sus contadores.

El caso real pertenece a `CyLMgu8PRDfN5yuLj`:

| Frame | Timestamp epoch, segundos | Flags | Secuencia | ACK |
| ---: | --- | --- | ---: | ---: |
| 24772 | 1538520727.193416 | FIN+ACK | 4227138534 | 1048708645 |
| 24773 | 1538520727.194155 | FIN+ACK | 1048708645 | 4227138535 |
| 24775 | 1538520727.344572 | ACK | 4227138535 | 1048708646 |

El flujo `3ea46b1fdc49e9ff66ba53a670df2665c052febf95e3b8faf4fd1bc11822ffb0`,
de 72 paquetes, queda admitido por esa cadena. El ACK llega 150,417 ms después
del final publicado, pero el tiempo transcurrido no es el criterio de
aceptación. Una secuencia distinta, payload adicional, otro SYN interpuesto,
evidencia de cierre ausente o contadores incompatibles impiden la excepción.
Zeek documenta que su duración puede excluir el ACK final aunque forme parte
de la conexión. [Definición oficial](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

### Partición entre varias referencias

No se elige el UID más cercano ni basta con que varias etiquetas coincidan.
Todos los paquetes del flujo deben tener una única referencia; cada
referencia debe estar contabilizada completamente dentro de ese flujo,
conservar sus tiempos y contadores, y tener la misma etiqueta original y el
mismo detalle. Un solapamiento ambiguo, contradicción, dato desconocido
necesario o paquete sin soporte deja el flujo sin etiqueta.

Se admitieron cuatro flujos SYN, puertos origen 38086, 38088, 38090 y 38096.
Cada uno contiene cinco paquetes y corresponde a tres referencias de
3 + 1 + 1 paquetes. Por ejemplo:

| Frames del flujo `e10721eb68b9…` | UID original | Paquetes / bytes IP |
| --- | --- | --- |
| 151, 153, 154 | `CNgUZj2l83jIcPrLi2` | 3 / 180 |
| 162 | `CMvZfV3A0fj2GCfJs2` | 1 / 60 |
| 164 | `CkYqtu3UaUFRMgWRtl` | 1 / 60 |

Las duraciones desconocidas de los registros de un solo paquete permanecen
`null`: sus contadores demuestran soporte puntual. No se inventa duración
cero. Los informes conservan todos los UID y el estado diferenciado
`admitted_partition`; no presentan estas asociaciones como uno a uno.

## Referencias recuperadas y cuarentenas

Estas son las 14 referencias originales Malicious con al menos un flujo
admitido. Las filas que comparten una partición no representan flujos
adicionales independientes.

| UID original | Línea de origen | Flujos admitidos asociados |
| --- | ---: | ---: |
| `CNgUZj2l83jIcPrLi2` | 62 | 1 |
| `CMvZfV3A0fj2GCfJs2` | 64 | 1 |
| `CkYqtu3UaUFRMgWRtl` | 68 | 1 |
| `CF49552MEZIPhghQJ3` | 96 | 1 |
| `Cf0ngw4SmqbOgwbRDk` | 97 | 1 |
| `CCVhqme8G3qXTDhac` | 102 | 1 |
| `CtHxXv46wV7Bx8Fsx1` | 109 | 1 |
| `ChumG2IokpJupNVD` | 111 | 1 |
| `CTGh3U2czm2PpX2n19` | 112 | 1 |
| `CyLMgu8PRDfN5yuLj` | 1834 | 137 |
| `CJ4kZO1ywwJo2JI9hj` | 1844 | 1 |
| `CZIOiq4kCqrzOyTnr9` | 1846 | 1 |
| `CsnYKr3Uz7O6PbCqe8` | 1847 | 1 |
| `CGLDvm3X8xOnv1Rfwf` | 3216 | 147 |

Permanecen pendientes estos cuatro flujos; sus identificadores completos,
frames y motivos están en la evidencia compacta y la auditoría completa:

| Prefijo único del ID | Paquetes | Motivo |
| --- | ---: | --- |
| `cc4106bf438e…` | 136 | Contiene el frame parcial 266; ningún paquete del flujo genera etiqueta admitida |
| `b63b68abdd38…` | 135 | Contiene los frames parciales 24825 y 24828 |
| `87214fa5383a…` | 12 | Contiene el frame parcial 24789 y las referencias `CAeI0M2CvsuJgdMglf` / `CfzKAA1RjOB1codUAk` |
| `492c232e633d…` | 3 | Referencia UDP `Cs2uux2Y3UfNwPD9Yd`: el PCAP muestra 0/3 paquetes por dirección Zeek, pero publica 1/2 |

Los dos UID del flujo de 12 paquetes son las referencias Malicious no
recuperadas. Sus contadores pueden reconciliarse separando el parcial, pero
el flujo completo sigue en cuarentena. En total hay 3.208 referencias con
contadores verificados; solo 3.206 tienen algún flujo íntegramente admitido.
Verificar una referencia no etiqueta automáticamente todos sus segmentos.

`excluded_frames` enumera paquetes que fallaron una comprobación individual;
no es una lista de paquetes borrados ni el total de la cuarentena. Por
ejemplo, el UDP tiene `excluded_frames: []` porque sus tres paquetes están
observados y mapeados por tiempo, pero falla la conservación direccional de
la referencia y **todo el flujo permanece sin etiqueta**. En el registro de
paquetes, `flow_label_admitted` es falso para los 286 paquetes de los cuatro
flujos pendientes.

## Pruebas ejecutadas

Se añadieron [29 pruebas nuevas](../tests/test_label_reconciliation.py):
28 casos controlados y una regresión real con el par oficial local. Los
fixtures construyen PCAP pequeños con checksums, tiempos y secuencias
conocidos; no requieren red ni TShark para sus casos unitarios. La regresión
local no descarga archivos y verifica los hashes oficiales fijados durante
la adquisición.

La secuencia final fue:

| Ejecución | Aprobadas | Fallos | Errores | Omitidas |
| --- | ---: | ---: | ---: | ---: |
| Específicas: importador/auditor anterior y reconciliación | **64** | **0** | **0** | **0** |
| Suite completa del proyecto | **163** | **0** | **0** | **0** |

- [Salida específica final](./validacion_reconciliacion_iot23_20_1/pruebas_especificas_finales.log)
  y [resultado estructurado](./validacion_reconciliacion_iot23_20_1/resultado_especificas_finales.json).
- [Salida completa final](./validacion_reconciliacion_iot23_20_1/pruebas_completas_finales.log)
  y [resultado estructurado](./validacion_reconciliacion_iot23_20_1/resultado_completas_finales.json).

La suite específica final comenzó a las 17:14:53 UTC y terminó a las
17:15:02 UTC; después se ejecutó la suite completa, hasta las 17:15:25 UTC.
La repetición independiente del auditor y la comprobación con TShark se
realizaron después. Antes se habían ejecutado 59 y 63 pruebas específicas y
una suite completa de 162; todos esos pases también aprobaron y sus registros
se conservaron. Tras añadir la regresión real se ejecutó la secuencia final
64/163, sin reutilizar resultados de pruebas anteriores.

Se cubrieron checksum válido/parcial/incorrecto, corrupción del encabezado
IP, evidencia de omisión ausente o contradictoria, contadores por exceso y
por defecto, orientación invertida, límites y corrupción de PCAP, timestamps
de nanosegundos, archivos big/little endian, repetibilidad e inmutabilidad,
reutilización de puertos, UID duplicados, etiquetas y detalles contradictorios,
particiones incompletas, frames ausentes/repetidos, FIN/ACK incorrectos,
payload adicional, nuevo SYN interpuesto y secuencias que desbordan 32 bits.

La regresión real comprueba 3.495 admitidos, 40.921 paquetes etiquetados,
14 referencias Malicious recuperadas, los cuatro frames parciales siempre
en cuarentena y exactamente una excepción de cierre. Las 134 pruebas
preexistentes también se ejecutaron, incluidas las de CSV, persistencia y
lectura real PCAP/PCAPNG. Las pruebas históricas de entrenamiento trabajan con
fixtures temporales; no entrenan ni sobrescriben modelos operativos con
IoT-23 o UNSW-NB15 en esta fase. Las advertencias de Streamlit por ejecutar
sin sesión interactiva no fueron fallos de prueba.

## Integridad, cambios y reversión

No existe repositorio Git en la carpeta o sus antecesores; `git status`
informa `not a git repository`. No se creó ni alteró un estado de Git.

Antes de editar se creó y verificó el
[respaldo de 85 archivos](../_backups/pre-reconciliation-20261108T165622Z-fb48e1bc.zip):
CRC, hashes, restauración a una carpeta temporal y `integrity_check` de las
tres bases restauradas. Los snapshots SQLite del respaldo se obtuvieron
mediante la API de backup con conexión de origen de solo lectura. Se
excluyeron entorno virtual, cachés y respaldos anteriores.

SHA-256 del respaldo nuevo:

```text
b010da149e8cce78847b27467bb4b797638367128bb2b3abe7e7c174de9608d6
```

Después de las pruebas se verificaron **84 archivos protegidos sin cambios**
por SHA-256 y se confirmó que el único archivo preexistente modificado es
[el auditor](../seguridad_pymes/label_audit.py). Los tres respaldos anteriores
y el nuevo mantienen hashes y CRC correctos. Las tres bases SQLite actuales
también dieron `integrity_check: ok`, conservando sus hashes.

Se añadió [el archivo de pruebas](../tests/test_label_reconciliation.py),
este informe y las [evidencias de esta validación](./validacion_reconciliacion_iot23_20_1/).
No se modificaron los informes ni resultados históricos. No hubo archivos
preexistentes eliminados, cambios de dependencias ni nuevas descargas.

Las comprobaciones incluyen los módulos del extractor y su esquema,
importador Zeek, ruta CSV, Streamlit, SQLite, modelos, metadatos, datos
originales y referencias. No se hizo una sesión manual interactiva del
panel; la preservación se acredita mediante hashes y las pruebas existentes.

Para revertir, extraer el respaldo a **una carpeta nueva**, comprobar el
manifiesto y las bases y utilizar esa copia del proyecto con sus dependencias
existentes. Así se recuperan el auditor anterior y sus 134 pruebas, sin borrar
ni sobrescribir el proyecto actual, sus datos o evidencias. El entorno virtual
no está incluido. No hay migraciones de base de datos ni modelos que revertir.

## Uso y límites pendientes

Desde la raíz, elegir siempre una carpeta de salida nueva:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.label_audit data/processed/iot23_pilot_20_1/extraction.json data/raw/iot23_pilot_20_1/conn.log.labeled data/raw/iot23_pilot_20_1/provenance.json --capture data/raw/iot23_pilot_20_1/2018-10-02-13-12-30-192.168.100.103.pcap --output docs/validacion_reconciliacion_iot23_20_1/otra_ejecucion
.\.venv\Scripts\python.exe -B -m unittest tests.test_label_audit tests.test_label_reconciliation -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

El lector de evidencia v2 está acotado a **PCAP clásico Ethernet/IPv4,
TCP/UDP**, hasta 128 MiB y un millón de frames por defecto. Rechaza PCAPNG
explícitamente: el extractor original conserva su soporte PCAPNG, pero aún
no se implementó su evidencia raw consciente de interfaces en el auditor.
No se convierte ni reescribe una captura para eludir esa limitación.

No se implementaron reconstrucción general de conexiones TCP, reensamblado,
variantes de cierre distintas del caso probado, tratamiento permisivo de
referencias incompletas ni corrección automática de contadores Zeek. Esos
casos deben seguir pendientes cuando falte prueba suficiente. El registro
de conexiones publicado resume paquetes: la reconciliación demuestra
compatibilidad verificable con esos resúmenes, no acceso a un UID original
por paquete emitido por la versión histórica de Zeek.

Los informes añaden `connection_group_id`, compartido entre hermanos y entre
referencias unidas por una partición, y `capture_group_id`. **Ninguno de esos
grupos debe repartirse entre entrenamiento y evaluación.** Los 288 segmentos
con etiqueta Malicious corresponden a solo **seis grupos de conexión** y una
captura, no a 288 escenarios independientes. El dataset de entrenamiento y
su evaluación siguen pendientes; esta cobertura no autoriza conclusiones
de generalización a redes PYMES.

La interfaz, SQLite, modelos y ruta CSV permanecen como antes. No hay
entrenamiento operativo, clasificación PCAP, alertas desde capturas, nuevas
capturas de interfaces ni monitoreo en tiempo real.
