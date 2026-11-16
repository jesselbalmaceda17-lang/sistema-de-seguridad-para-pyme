# Validación real de la fase 1 del extractor PCAP

Fecha: 2026-11-08. Resultado final: **99 pruebas aprobadas, 0 omitidas,
0 fallos y 0 errores**. Se ejecutaron pruebas reales con TShark y archivos
sintéticos, sin interfaces de captura, sin cambiar modelos operativos y sin
conectar PCAP a inferencia, Streamlit o SQLite.

## Entorno comprobado

- Windows 11 de 64 bits; TShark informa versión 25H2, build 26200.
- TShark **4.6.9**, ejecutado desde `C:\Program Files\Wireshark\tshark.exe`.
- Npcap **1.88**, informado por `tshark --version`. No se usó para captura.
- Entorno virtual preexistente del proyecto; ninguna instalación o actualización.
- Esquema **`sipymes.offline.ipv4.v1`**, conservado; extractor **`1.0.1`**.

La salida real de versión está en
[tshark_version.txt](./validacion_pcap_20261108/tshark_version.txt).
La detección explícita por ruta absoluta y la búsqueda en Program Files
funcionaban y no requirieron cambios de implementación. Se probaron ambas con
PATH vacío y se completaron extracciones reales en esas condiciones.

## Error reproducido y corrección

Antes de cambiar el código se ejecutaron las cinco pruebas anteriormente
omitidas. Resultado: **3 aprobadas, 1 fallo de aserción, 1 error y 0 omitidas**.

La lectura de campos reales mostró `ip.flags.mf = "False"`. El lector original
aplicaba conversión a entero a ese campo y esperaba `0`. Así, rechazaba paquetes
IPv4 válidos como `missing_or_invalid_header` y no producía flujos:

- La prueba UDP encontró cero paquetes aceptados en lugar de tres.
- La prueba TCP intentó acceder al primer flujo inexistente y produjo
  `IndexError`. Era otra consecuencia del mismo error de lectura.

Se añadió interpretación booleana estricta: `True`/`False` sin distinguir
mayúsculas, además de `1`/`0`. Un campo vacío, desconocido o con valor `2`
continúa rechazándose; no se interpreta como cero. Una indicación verdadera
de fragmentación sigue generando `ipv4_fragment_not_supported`.

El extractor subió de 1.0.0 a **1.0.1** para identificar la corrección en sus
informes. El esquema y sus 38 definiciones permanecen iguales; tampoco cambió
el módulo de agrupación ni sus fórmulas. Los identificadores de flujo incluyen
la versión del extractor y por ello distinguen las dos implementaciones.

Tras la corrección, las cinco pruebas originales se ejecutaron otra vez:
**5 aprobadas, 0 omitidas, 0 fallos y 0 errores**.

## Validación real ampliada

Se ampliaron las pruebas reales a nueve métodos de prueba. Todos aprobaron,
sin omisiones. Los subcasos recorren PCAP y PCAPNG cuando corresponde:

1. TCP: las **38 características** contra un oráculo manual en ambos formatos.
2. UDP: las **38 características**, repetibilidad, direcciones y calidad en
   ambos formatos.
3. TCP y UDP de un solo paquete en ambos formatos: las 38 salidas con valores,
   estados y motivos, incluidas dirección ausente e intervalos desconocidos.
4. Ruta absoluta y descubrimiento automático con PATH vacío, con lectura real.
5. TCP parcial con inicio desconocido y cierre por RST.
6. Paquete truncado con contenedor válido y rechazo explícito de calidad.
7. Carga Ethernet no admitida con motivo, conteo y cero flujos.
8. Contenedor corrupto rechazado sin producir informe. Esta firma inválida se
   detecta antes de invocar TShark; se conserva la prueba original.
9. Cola de contenedor truncada después de un paquete válido: error de TShark,
   sin aceptar como completo el resultado parcial.

También se añadieron dos pruebas de regresión sin dependencia real: formatos
booleanos estrictos y descubrimiento por ruta/Program Files sin PATH.
Los oráculos numéricos no llaman a las funciones de agregación para construir
sus resultados esperados. Los conteos, categorías, estados y motivos se comparan
exactamente; los valores flotantes se contrastan a doce posiciones decimales.

Valores de referencia de los casos conservados como evidencia:

| Caso | Paquetes ida/vuelta | Bytes IPv4 ida/vuelta | Duración observada |
| --- | ---: | ---: | ---: |
| UDP controlado | 2 / 1 | 64 / 29 | 0,5 s |
| TCP controlado | 3 / 3 | 180 / 160 | 1,6 s |

El TCP controlado ejercita las ocho banderas del esquema, incluidas URG, ECE
y CWR. Sus tamaños son 40/60/80 bytes en ida y 40/50/70 en vuelta; los intervalos
son 0,4/0,6 s y 0,5/1,0 s, respectivamente. Se validan mínimos, máximos,
medias y desviaciones poblacionales. Estos paquetes son fixtures de medida,
no tráfico de un ataque ni demostración de eficacia de un detector.

## Suite completa y evidencia persistida

Se ejecutó la suite completa con descubrimiento `unittest discover -s tests -v`
mediante `TextTestRunner`, guardando el registro y los conteos del objeto
resultado. El [registro completo](./validacion_pcap_20261108/unittest_completo.log)
termina con:

```text
Ran 99 tests in 26.167s

OK
```

El [resultado estructurado](./validacion_pcap_20261108/resultado_pruebas.json)
registra exactamente:

| Ámbito | Aprobadas | Omitidas | Fallos | Errores |
| --- | ---: | ---: | ---: | ---: |
| Suite completa final | **99** | **0** | **0** | **0** |
| De ellas, extractor | 44 | 0 | 0 | 0 |
| De ellas, pruebas preexistentes | 55 | 0 | 0 | 0 |
| Integración real, incluida dentro del extractor | 9 | 0 | 0 | 0 |

El tiempo total del proceso de validación, incluyendo descubrimiento e
importaciones, fue 55,825 s. No es un benchmark de capacidad del extractor.
Hubo advertencias de Streamlit sobre `ScriptRunContext` en sus pruebas,
sin excepciones ni fallos. Las pruebas preexistentes entrenan exclusivamente
modelos efímeros de fixture; ningún modelo operativo se reentrenó.

Para repetir la validación:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_pcap_extraction.RealTSharkIntegrationTests -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Después de la suite se comprobó además la CLI real en dos archivos sintéticos
conservados. Ambos comandos terminaron con código 0 y generaron 38
características; se comprobaron hashes, conteos, bytes y duración:

- [UDP PCAP](./validacion_pcap_20261108/udp_control.pcap) y su
  [JSON extraído](./validacion_pcap_20261108/udp_control.pcap.flujos.json).
- [TCP PCAPNG](./validacion_pcap_20261108/tcp_control.pcapng) y su
  [JSON extraído](./validacion_pcap_20261108/tcp_control.pcapng.flujos.json).
- [Comandos, salidas y hashes de la CLI](./validacion_pcap_20261108/cli_evidencia.json).

Para repetir un caso sin sobrescribir la evidencia guardada:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.pcap_extract .\docs\validacion_pcap_20261108\udp_control.pcap --output .\udp_revalidado.json --tshark 'C:\Program Files\Wireshark\tshark.exe'
```

## Conservación y respaldos

Git continúa sin inicializar: `git status --short` informó que no es un
repositorio. Se conserva el
[respaldo original](../_backups/pre-pcap-20261108T145704Z-c78b980b.zip).
Antes de las correcciones se creó y verificó otro respaldo recuperable de los
59 archivos existentes, con snapshots consistentes de las bases:
[pre-real-pcap-validation-20261108T151858Z-da1e2f71.zip](../_backups/pre-real-pcap-validation-20261108T151858Z-da1e2f71.zip).

La [comparación de integridad](./validacion_pcap_20261108/integridad.json)
registra hashes por archivo y estas comprobaciones:

- **52 archivos originales anteriores a la fase PCAP siguen idénticos** al
  primer respaldo, incluidos CSV, modelos, metadatos, aplicación y bases.
- De los 59 archivos del respaldo previo a esta validación, 55 están idénticos
  y cuatro tienen los cambios autorizados que se enumeran abajo.
- No falta ningún archivo de esos respaldos; el ZIP original conserva CRC y
  hashes internos válidos. Ambos ZIP tienen SHA-256 registrado.
- Las tres bases SQLite, abiertas en modo de solo lectura, devolvieron `ok`
  en `PRAGMA integrity_check`.
- Las definiciones de características coinciden con las previas al comparar
  su AST; el módulo completo de agrupación también coincide byte por byte.
- Las pruebas existentes de CSV, panel y persistencia temporal aprobaron.

El [informe inicial](./informe_fase1_pcap.md) se conserva sin cambios como
registro histórico de la etapa en que faltaba TShark. Este informe documenta
la validación posterior con la dependencia disponible.

## Cambios realizados y reversión

Archivos modificados en esta validación:

| Archivo | Cambio |
| --- | --- |
| [pcap_reader.py](../seguridad_pymes/pcap_reader.py) | Interpretación estricta del booleano de fragmentación. |
| [pcap_schema.py](../seguridad_pymes/pcap_schema.py) | Únicamente versión de implementación 1.0.0 → 1.0.1. |
| [test_pcap_extraction.py](../tests/test_pcap_extraction.py) | Regresiones y ampliación de oráculos reales para las 38 características. |
| [extractor_pcap.md](./extractor_pcap.md) | Versión validada, resultado actual, corrección y nueve pruebas opcionales. |

Se añadieron este informe, los nueve archivos de evidencia enlazados y el
respaldo previo a la validación. No se modificaron dependencias, aplicación,
módulo de agregación, generadores de fixtures, datos preexistentes ni modelos.

Para revertir solo esta corrección, extraer el segundo respaldo en una carpeta
nueva y recuperar desde ella esos cuatro archivos de código/documentación.
La versión 1.0.0 volvería a presentar el fallo de lectura corregido. Mantener
ambos respaldos y los datos/modelos/bases actuales; no es necesario sustituir
SQLite ni borrar archivos para revertir. Las evidencias pueden conservarse
como registro de la validación.

## Límites que permanecen

La validación demuestra los casos de laboratorio cubiertos y el contrato de
38 características en TShark 4.6.9. No demuestra ausencia de pérdida en un
sensor, reconstrucción completa de sesiones ni eficacia para detectar ataques.
Se mantienen las restricciones de Ethernet sin VLAN, IPv4 no fragmentado y
TCP/UDP. No hay reensamblado, captura de interfaces, monitoreo continuo,
integración PCAP con el modelo anterior, alertas o un modelo nuevo.
