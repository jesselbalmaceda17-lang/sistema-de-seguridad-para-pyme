# Informe de implementación — extractor PCAP offline, fase 1

Fecha: 2026-11-08. Plataforma de trabajo: Windows, PowerShell y el entorno
virtual preexistente del proyecto. Esquema `sipymes.offline.ipv4.v1`, extractor
`1.0.0`. [Guía de uso y contrato completo](./extractor_pcap.md).

## Resultado y alcance

Se añadió un componente independiente de lectura offline mediante TShark
opcional y extracción determinista de 38 características TCP/UDP observadas
sobre Ethernet/IPv4. Incluye duración, protocolo, paquetes y bytes IPv4 por
dirección, estadísticos de tamaños/intervalos y ocho banderas TCP por dirección.
Las medidas desconocidas conservan `null` y motivo; los ceros representan
conteos o medidas observadas válidas. No hay adaptación a UNSW-NB15.

Se incorporaron orientación por primer paquete, clave bidireccional con
separación por interfaz, timeouts configurables, segmentación por nuevo SYN,
cierre por RST y marcas explícitas de inicio/final no observados. Los FIN de
ambas direcciones se registran como evidencia, sin afirmar cierre TCP verificado.

Los informes JSON registran fuente, SHA-256, esquema, versiones, configuración,
calidad y referencias a las tramas de cada flujo. El ejecutable solo recibe
archivos mediante `-r`; no recibe interfaces de captura. El componente no
importa inferencia, entrenamiento, SQLite, Streamlit ni bibliotecas de ML.

## Archivos añadidos

| Archivo | Responsabilidad |
| --- | --- |
| [pcap_schema.py](../seguridad_pymes/pcap_schema.py) | Esquema, definiciones, versión, valores con estado y configuración validada. |
| [pcap_reader.py](../seguridad_pymes/pcap_reader.py) | Descubrimiento opcional de TShark, subproceso offline aislado, validación de campos y motivos de rechazo. |
| [pcap_extract.py](../seguridad_pymes/pcap_extract.py) | Agrupación bidireccional, características, procedencia e interfaz de línea de comandos. |
| [pcap_fixtures.py](../tests/pcap_fixtures.py) | Generadores controlados PCAP/PCAPNG con biblioteca estándar; sin captura real. |
| [test_pcap_extraction.py](../tests/test_pcap_extraction.py) | Oráculos manuales, errores del backend, límites, repetibilidad e integración opcional. |
| [extractor_pcap.md](./extractor_pcap.md) | Uso en Windows, contrato, políticas, limitaciones y reversión. |
| [informe_fase1_pcap.md](./informe_fase1_pcap.md) | Este informe con evidencia de validación. |

No se modificó ningún archivo preexistente. Se conservan intactos interfaz,
base activa, respaldos SQLite anteriores, datasets, modelos, metadatos,
dependencias y ruta CSV. El ZIP de respaldo es un artefacto adicional fuera
de esta lista de código/documentación.

## Respaldo recuperable y Git

Antes de editar se ejecutó `git status --short`; el resultado fue
`fatal: not a git repository (or any of the parent directories): .git`.
No se inicializó un repositorio ni se crearon commits.

Se creó [pre-pcap-20261108T145704Z-c78b980b.zip](../_backups/pre-pcap-20261108T145704Z-c78b980b.zip),
de **28 435 071 bytes**, con 52 archivos originales, incluidos datos y modelos.
Se excluyeron entorno virtual, cachés y carpeta de respaldos; las dependencias
fijadas están incluidas. Las tres bases SQLite se copiaron mediante la API de
backup con fuentes de solo lectura y comprobación de integridad.

Se verificaron CRC del ZIP y SHA-256 de cada entrada contra su manifiesto.
Después de las pruebas se realizó una restauración real en un directorio
temporal separado: los 52 archivos restaurados coincidieron con sus hashes y
las tres bases restauradas devolvieron `ok` en `PRAGMA integrity_check`.
La comparación posterior de los 52 archivos originales con `source_sha256`
detectó **cero archivos cambiados y cero ausentes**.

## Evidencia de pruebas

Comando ejecutado sobre el estado final del código:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Resultado observado, código de salida 0:

```text
Ran 93 tests in 10.737s
OK (skipped=5)
```

Esto significa **88 pruebas aprobadas, 5 omitidas y 0 fallos**.
El módulo nuevo aporta 38 pruebas: 33 aprobadas y 5 omitidas. Las 55 pruebas
preexistentes también aprobaron, incluidas CSV, entrenamiento de fixtures,
inferencia/persistencia temporal y panel Streamlit. Se observaron advertencias
de Streamlit sobre `ScriptRunContext` en su entorno de pruebas, sin fallos.
Las pruebas existentes entrenan modelos efímeros; ningún modelo real se
reentrenó o sustituyó.

Las comprobaciones nuevas aprobadas cubren:

- Conteos y sumas IPv4 contrastados con valores calculados manualmente;
  medias, desviaciones poblacionales e intervalos por dirección.
- Nanosegundos, intervalos cero observados y ausencia de muestras con motivo.
- Orientación, separación por interfaz/protocolo, inactividad TCP/UDP,
  timeout activo, RST, FIN, ACK final, SYN retransmitido y tupla reutilizada.
- Inicio TCP no observado, fin de archivo y rechazo de extremos indistinguibles.
- Rechazos de cabeceras, truncamiento de paquete, protocolos fuera de alcance,
  fragmentos y contabilidad de calidad.
- Cabecera de contenedor realmente inválida, rechazada antes de invocar TShark.
- Límites de recursos y desorden temporal con error explícito.
- Hash, detección de cambio de fuente y repetibilidad de resultados.
- Comandos del backend offline, ausencia de shell, limpieza del perfil temporal,
  errores/salida inválida/timeouts mediante sustituto controlado del subproceso.
- Importación en proceso nuevo sin cargar componentes de aplicación o ML.
- Salida CLI sin sobrescritura y sin informe ante un fallo de extracción.

## Dependencia pendiente y límites de validación

**TShark no está instalado o localizable en este equipo. No se instaló.**
Las cinco pruebas de integración opcionales quedaron omitidas explícitamente:
PCAP/PCAPNG bidireccional y repetición, TCP parcial/RST, Ethernet no admitido,
archivo corrupto y cola de contenedor truncada tras un paquete válido.

Los campos decodificados y el transporte simulado comprueban lógica y errores,
pero no demuestran que una versión real de TShark entregue esos campos en este
equipo. Por ello, la lectura binaria completa de capturas y la compatibilidad
con una versión concreta de TShark siguen pendientes de validación. Tras la
instalación manual descrita en la guía, ejecutar de nuevo las pruebas: las
cinco omitidas deben ejecutarse y aprobar antes de usar resultados del lector.

No se ejecutó captura de interfaces ni se instalaron dependencias globales.
No se inspeccionaron capturas empresariales o tráfico ajeno al laboratorio.

## No implementado en esta fase

- Clasificación o alertas desde PCAP, conversión a las 42 entradas UNSW-NB15,
  cambios de umbral o modelos nuevos.
- Integración PCAP en Streamlit o persistencia de flujos en SQLite.
- Captura de interfaces, procesamiento continuo o bloqueo de tráfico.
- VLAN, IPv6, enlaces distintos de Ethernet, reensamblado IPv4/TCP,
  reconstrucción HTTP/FTP/TLS, cálculo de RTT o estimación de pérdidas reales.
- Reconstrucción exhaustiva del estado TCP: aperturas simultáneas, ACK de cierre
  y reutilizaciones ambiguas no se resuelven completamente.
- Garantía de integridad/completitud del sensor o eficacia de detección.
- Benchmark de capacidad o memoria para tráfico empresarial. Los límites son
  protecciones configurables, no cifras de capacidad demostrada.

Los flujos y referencias a paquetes se conservan en memoria bajo límites; no
se afirma procesamiento de tamaño ilimitado. Las capturas fuera de orden se
rechazan en conjunto. Los paquetes fuera de alcance se excluyen con motivos
y las métricas describen únicamente el conjunto aceptado.

## Reversión

1. Apartar los siete archivos nuevos listados arriba a otra carpeta, sin tocar
   archivos de datos, modelos, bases ni módulos preexistentes. No es necesario
   desinstalar paquetes ni revertir configuraciones globales.
2. Conservar el ZIP. Para recuperación completa, extraerlo en una carpeta nueva
   y verificar `archive_sha256` del manifiesto e integridad SQLite antes de
   elegir esa copia como proyecto. No sobrescribir el espacio de trabajo activo.
3. Si se requiere un entorno nuevo, reconstruirlo desde
   [requirements-lock.txt](../requirements-lock.txt); el entorno anterior se
   dejó intacto y no se incluyó en el ZIP.

El informe de extracción no constituye una predicción ni evidencia de un ataque.
