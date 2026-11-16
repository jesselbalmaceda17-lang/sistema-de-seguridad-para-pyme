# Extractor offline de laboratorio — fase 1

Este componente lee archivos PCAP/PCAPNG existentes y genera JSON de flujos
observados. No captura interfaces, no clasifica ataques y no llama al modelo,
al panel Streamlit ni a SQLite. No declara equivalencia con UNSW-NB15.

## Windows 11 y dependencia opcional

El código usa exclusivamente la biblioteca estándar de Python. No cambia
[requirements.txt](../requirements.txt) ni instala dependencias.

Para leer paquetes se necesita TShark. Si falta, el comando termina con error
explícito y pasos de instalación; nunca lo descarga ni instala automáticamente.

1. Descargar manualmente Wireshark desde <https://www.wireshark.org/download.html>.
2. En el instalador de Windows, seleccionar el componente TShark.
3. Verificarlo en PowerShell:

   ```powershell
   & 'C:\Program Files\Wireshark\tshark.exe' --version
   ```

La lectura offline no necesita captura de interfaces ni Npcap. El descubrimiento
busca en PATH y después en Program Files; también se admite `--tshark`.
Validado con **TShark 4.6.9** en Windows 11 de 64 bits, con Npcap 1.88
informado por el ejecutable. Se comprobaron ruta absoluta y descubrimiento en
Program Files con PATH vacío. Las nueve pruebas de integración real y la suite
completa aprobaron: 99 aprobadas, ninguna omitida y ningún fallo/error.
Véase el [informe de validación real](./validacion_real_fase1_pcap.md).
Al cambiar la versión de TShark, repetir las pruebas y conservar su versión.

Referencias: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) e
[instalación para Windows](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).

## Uso

Desde la raíz del proyecto, con un archivo autorizado de laboratorio:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.pcap_extract .\laboratorio.pcapng --output .\laboratorio.flujos.json --tshark 'C:\Program Files\Wireshark\tshark.exe'
```

El archivo de salida debe ser nuevo y su carpeta debe existir. No se sobrescriben
archivos. `--help` muestra timeouts y límites configurables. Códigos de salida:
0, extracción completada; 2, error. No se genera un informe exitoso si TShark
falla, excede su tiempo, hay desorden temporal, se alcanza un límite o el archivo
fuente cambia durante la extracción. Un fallo del dispositivo al escribir JSON
puede dejar un archivo parcial: no debe usarse como informe válido.

El lector verifica la firma y tamaño mínimo del contenedor; TShark valida el
contenido restante. Se usa `-r` con ruta absoluta, sin shell, sin resolución de
nombres, con configuración personal vacía y reensamblado IP/TCP desactivado.
Se registran versión, ruta del ejecutable y primeros 4000 bytes de diagnósticos.
No se conservan cargas útiles ni credenciales en el JSON.

## Contrato de características

Esquema: **`sipymes.offline.ipv4.v1`**. Extractor: **`1.0.1`**.
Las definiciones se exportan con cada informe desde
[pcap_schema.py](../seguridad_pymes/pcap_schema.py). Son 38 características:

| Nombre o patrón | Definición |
| --- | --- |
| `observed_duration_seconds` | Último timestamp menos primero; un paquete tiene duración observada cero. |
| `transport_protocol` | `tcp` o `udp` según protocolo IPv4. |
| `{forward,reverse}_packet_count` | Paquetes aceptados de cada dirección; incluye retransmisiones. |
| `{forward,reverse}_ipv4_byte_count` | Suma de longitudes totales IPv4; incluye cabeceras IP/transporte y excluye Ethernet, padding y FCS. |
| `{forward,reverse}_ipv4_size_{min,max,mean,population_std}_bytes` | Estadísticos de esas longitudes IPv4. |
| `{forward,reverse}_iat_{min,max,mean,population_std}_seconds` | Diferencias entre timestamps de paquetes consecutivos de la misma dirección, aunque haya paquetes inversos intercalados. |
| `{forward,reverse}_tcp_{fin,syn,rst,psh,ack,urg,ece,cwr}_count` | Número de paquetes TCP con cada bandera activada; un paquete puede contribuir a varias. |

La desviación es poblacional: `sqrt(sum(x²)/n - mean²)`. La implementación usa
acumuladores enteros para evitar cancelación antes de convertir a flotante.
Con una muestra es cero. Los timestamps se procesan como nanosegundos enteros;
los tiempos de salida de características se expresan en segundos. No se afirma
que la precisión original de la captura sea de nanosegundos. Los timestamps
absolutos se exportan como cadenas de enteros para evitar pérdida en JavaScript.

Cada característica tiene `{value, status, reason}`. Una medida disponible tiene
`status: "ok"` y `reason: null`. Una desconocida tiene `value: null`,
`status: "unavailable"` y un motivo:

- `no_packets_in_direction`: no hay tamaños que resumir.
- `fewer_than_two_packets_in_direction`: no hay intervalos suficientes.
- `not_applicable_to_udp`: las banderas TCP no corresponden al protocolo.

Cero paquetes y cero bytes en una dirección son conteos observados válidos.
Una media sin muestras permanece desconocida. No hay imputación, estimaciones
de ataques ni conversiones al esquema de 42 entradas del modelo existente.

## Agrupación, orientación y límites de interpretación

La clave incluye interfaz, protocolo y par no orientado de extremos IPv4/puerto.
El origen del primer paquete aceptado define `forward`; su destino define
`reverse`. No se infiere cliente/servidor ni se cambia la orientación a posteriori.
Extremos idénticos en dirección y puerto se rechazan: no permiten distinguir
ambas direcciones con esta clave. Interfaces distintas nunca se fusionan.

Los paquetes deben llegar en orden no decreciente de timestamp y con número de
trama estrictamente creciente. No se reordenan silenciosamente. Los timeouts
se evalúan antes del paquete entrante; igualdad con el límite abre otro flujo:

| Configuración | Valor predeterminado |
| --- | ---: |
| Inactividad TCP | 120 s |
| Inactividad UDP | 30 s |
| Duración activa máxima | 300 s |
| Tiempo máximo de decodificación TShark | 120 s |
| Paquetes examinados, incluidos rechazados | 1 000 000 |
| Flujos activos | 50 000 |
| Flujos totales | 100 000 |

Si coinciden ambos timeouts, se registra `active_timeout`. RST cierra tras
contabilizar su paquete. Un nuevo SYN sin ACK divide la tupla si cambia el
número de secuencia inicial, cambia su dirección o se observaron FIN en ambos
sentidos. Un SYN repetido con la misma secuencia y dirección permanece en el
flujo. Los FIN se registran, pero no cierran inmediatamente: así se conserva el
ACK final. El cierre posterior ocurre por timeout, nuevo SYN o fin del archivo.
No se verifica que los números de ACK confirmen el cierre ni se reensambla TCP.
Las aperturas TCP simultáneas y reutilizaciones ambiguas son una limitación de
esta política de segmentación; no se afirma reconstrucción completa de sesiones.

`start_observation` distingue SYN inicial observado de comienzo desconocido.
`end_observation` distingue RST, FIN en ambos sentidos y final no observado.
UDP no permite determinar comienzo/final de sesión con estas observaciones.
Timeout y EOF describen el corte del extractor, no una desconexión demostrada.
Incluso con SYN y FIN no se declara captura completa: pérdidas o duplicados del
sensor no pueden descartarse a partir del archivo.

## Calidad y procedencia

Cada informe contiene SHA-256 y tamaño del archivo, formato, configuración y su
hash, versiones, definiciones, conteos de aceptación/rechazo y ejemplos acotados
de rechazo. Cada flujo registra extremos, interfaz, timestamps, números de trama,
motivo de cierre, calidad e identificador determinista derivado de origen,
configuración, esquema, versión, ordinal y primera trama.

El alcance inicial es Ethernet sin VLAN, IPv4 no fragmentado y TCP/UDP con
cabeceras observables. Se rechazan explícitamente paquetes truncados, marcados
como malformados por TShark, otros enlaces, VLAN, IPv6, ARP, ICMP, fragmentación
IPv4 y cabeceras inválidas. La marca de malformado puede proceder también del
disector de aplicación; esta primera versión aplica una política conservadora.
Se conservan sus motivos y conteos; no se inventan sus características. Si hubo
rechazos, todos los flujos llevan `capture_has_rejected_packets: true` como
advertencia global, sin atribuir arbitrariamente un paquete rechazado a un flujo.

Cada trama aceptada contribuye exactamente una vez. No se deduplican paquetes
ni se corrigen efectos de offloading: las métricas describen el archivo observado.
No se mezclan archivos para completar contexto ni se reconstruyen HTTP/FTP,
TLS, RTT, pérdidas reales o características UNSW-NB15. Los datos se procesan
por streaming desde TShark; los flujos terminados y referencias de trama se
conservan en memoria hasta escribir JSON, bajo los límites configurados.

Repetibilidad significa mismas características, agrupación e identificadores
para el mismo archivo, parámetros y versión de herramientas. La procedencia
contiene rutas locales; no se promete JSON idéntico entre instalaciones distintas.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_pcap_extraction -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

[test_pcap_extraction.py](../tests/test_pcap_extraction.py) distingue cálculos
con oráculos manuales, transporte TShark simulado para comprobar errores/comandos,
y pruebas reales opcionales. [pcap_fixtures.py](../tests/pcap_fixtures.py) genera
PCAP y PCAPNG sintéticos pequeños sin bibliotecas ni interfaces de red.
Si falta TShark, las nueve pruebas de integración real se omiten explícitamente;
las pruebas simuladas no se presentan como validación real de decodificación.
Los fixtures TCP no constituyen sesiones completas de aplicación y no son
evidencia de eficacia de detección.

La validación real encontró y corrigió una incompatibilidad de representación:
TShark 4.6.9 exporta `ip.flags.mf` como `True`/`False`. El lector ahora acepta
esas formas y `1`/`0`; valores vacíos o desconocidos siguen rechazándose. No
cambiaron las definiciones ni fórmulas del esquema. La versión del extractor
subió a 1.0.1 para distinguir la implementación corregida en la procedencia.

## Respaldo y reversión

Antes de crear estos módulos se comprobó Git: esta carpeta no era repositorio.
No se inicializó Git. Se creó y verificó
[pre-pcap-20261108T145704Z-c78b980b.zip](../_backups/pre-pcap-20261108T145704Z-c78b980b.zip),
con 52 archivos originales, datos y modelos incluidos. Las tres bases SQLite
se guardaron con la API de backup, comprobando integridad, sin escribir en las
bases fuente. El manifiesto interno conserva hashes del origen y del respaldo.
Se excluyeron `.venv`, cachés y la carpeta de respaldos. El entorno existente
permanece intacto; puede reconstruirse desde el archivo de dependencias fijadas.

Para revertir esta fase, basta con apartar los archivos nuevos enumerados en el
informe de implementación. Ningún archivo de aplicación preexistente necesita
restaurarse. No borrar ni sobrescribir datos, modelos o bases para revertir.

Para comprobar recuperabilidad completa, extraer el ZIP **en una carpeta nueva**,
verificar los hashes `archive_sha256` de `BACKUP_MANIFEST.json` y comprobar las
bases SQLite. No restaurar directamente sobre el proyecto activo. Las copias
SQLite son snapshots consistentes; no se exige identidad binaria con el archivo
fuente, cuya identidad también está registrada como `source_sha256`.
