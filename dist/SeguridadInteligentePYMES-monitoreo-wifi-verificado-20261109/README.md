# Seguridad Inteligente PYMES — monitoreo autorizado y CSV

Esta versión permite iniciar y detener captura pasiva desde Streamlit y revisar alertas por **reglas transparentes**, sin preparar CSV. Mantiene una sección independiente de análisis CSV con el Random Forest UNSW-NB15 original. Las alertas no confirman ataques. No se distribuye el Random Forest PCAP experimental.

## Instalación en Windows 11

Requisitos comprobados: Windows 11 x64, Python 3.14.6, las versiones de [requirements-lock.txt](requirements-lock.txt), TShark 4.6.9 y Npcap disponible para el usuario. TShark se instala seleccionándolo en [Wireshark oficial](https://www.wireshark.org/download.html); la captura en Windows necesita [Npcap oficial](https://npcap.com/). No se instala software ni se eleva la aplicación automáticamente. Instalar el controlador puede requerir autorización administrativa; si Npcap ya permite capturar a su usuario, la aplicación no necesita pedir elevación.

Copiar la carpeta completa a un directorio escribible. Abrir PowerShell allí:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip --isolated install --no-cache-dir -r requirements-lock.txt -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -B herramientas/verificar_paquete.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

Abrir <http://127.0.0.1:8501>. Mantener la escucha local: no se añadió autenticación ni administración multiusuario. El launcher usa su propia carpeta y fija el modelo CSV original. Admite un entorno externo explícito con `-PythonPath` y otro puerto local con `-Port`. No contiene rutas de un usuario de desarrollo. La instalación de Python requiere disponibilidad previa de `venv` y `pip`; las dependencias se obtienen por HTTPS de PyPI, sin instalador offline incluido.

### Configurar y comprobar TShark/Npcap

Se verificaron TShark 4.6.9 y Npcap 1.88. Seleccionar el componente TShark al instalar Wireshark y habilitar en Npcap la captura para la cuenta autorizada. Una instalación de Npcap restringida a administradores requiere gestionar ese permiso con el administrador del equipo; la aplicación no lo cambia. Npcap actual proporciona la interfaz de loopback sin crear un adaptador de red adicional.

Con la instalación habitual, comprobar en PowerShell:

```powershell
& "$env:ProgramFiles\Wireshark\tshark.exe" --version
& "$env:ProgramFiles\Wireshark\tshark.exe" -D
Get-Service npcap
```

La lista debe incluir `\Device\NPF_Loopback` para esta demostración. La aplicación busca TShark en `PATH` y en la carpeta estándar de Wireshark de Program Files. Si se instaló en otra carpeta, añadir esa carpeta al `PATH` de la misma PowerShell antes de iniciar; por ejemplo, `$env:PATH = 'D:\Wireshark;' + $env:PATH`, sustituyendo la ruta por la instalación real. Si no hay interfaz o acceso, revisar Npcap y reiniciar el equipo si su instalador lo solicita antes de probar otra vez.

Si una política corporativa impide el script, desde la carpeta del paquete se puede ejecutar directamente:

```powershell
$env:SIPYMES_MODEL_PATH = 'models/unsw_nb15_random_forest.joblib'
.\.venv\Scripts\python.exe -B -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

El modelo original conserva SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. **Joblib puede ejecutar código al cargar; usar solo modelos de procedencia confiable.** El [manifiesto](manifest.sha256.json) verifica archivos, pero no autentica por sí solo a quien los publica.

## Iniciar y detener monitoreo

1. En «Monitoreo de red», seleccionar una interfaz disponible y confirmar autorización. Loopback observa comunicaciones locales de este equipo; Wi-Fi/Ethernet solo muestran lo accesible desde esa interfaz. Ver toda una LAN puede requerir puerto espejo, TAP u otra infraestructura autorizada.
2. Revisar, si es necesario, «Configuración y límites». Pulsar «Iniciar monitoreo». El estado y los contadores se actualizan aproximadamente cada segundo. El procesamiento y la persistencia ocurren en segundo plano; un rerender no inicia otra captura.
3. Consultar paquetes, conexiones observadas por tuplas, segmentos persistidos y alertas por reglas. Una conexión puede producir varios segmentos por inactividad o ventana de paquetes. Abrir la evidencia de una alerta para ver valor observado, umbral, ventana, origen, fecha y severidad.
4. Guardar revisión manual pendiente, confirmada o falso positivo. La revisión no cambia el hecho observado ni confirma técnicamente un ataque.
5. Pulsar «Detener monitoreo». Esperar al estado detenido; se cierran los flujos pendientes y TShark/dumpcap. Una pestaña desconectada deja de renovar el permiso temporal: se detiene en aproximadamente 20 s más el tiempo de cierre. En Windows, un Job Object elimina los hijos si el proceso de la aplicación termina abruptamente.

No se activa modo promiscuo, modo monitor Wi-Fi, bloqueo, exploración activa ni interceptación de terceros. El filtro admite IPv4 TCP/UDP y excluye el puerto de control de Streamlit para no medir su propia actualización. IPv6, VLAN y fragmentación no están soportados por este cálculo. Los paquetes excluidos se contabilizan con motivos. Ni ausencia de tráfico ni ausencia de alertas prueban que la red sea segura.

## Qué significan las reglas

| Regla | Evidencia observable | Configuración inicial | Severidad |
|---|---|---|---|
| `syn_observed` | Paquetes TCP SYN sin ACK desde el mismo origen; incluye retransmisiones y no equivale a intentos independientes fallidos. | 100 paquetes en 30 s | Media: requiere revisión del patrón. |
| `destination_ports` | Número de puertos destino distintos presentes en esos SYN del mismo origen. | 30 puertos en 30 s | Media: revisar amplitud de contactos; no se denomina ataque confirmado. |
| `ipv4_volume` | Suma de longitudes IPv4 observadas desde el origen, incluyendo cabeceras. Puede representar tráfico legítimo. | 10 MiB en 30 s | Baja: aviso de volumen, sin inferencia de intención. |

Los umbrales son puntos operativos de partida, no valores científicamente validados para todas las PYMES. Como máximo se emite una alerta de cada regla/origen por intervalo de ventana; la ventana de cálculo es móvil y las retransmisiones se identifican en la descripción. No hay regla de «conexiones fallidas» porque la captura parcial/asimétrica no permite atribuir ausencia de respuesta con suficiente certeza. No se adaptan características PCAP al modelo CSV.

## Demostración local segura

Solo sobre loopback autorizado, abrir la configuración y elegir SYN=5, puertos=4 y volumen=1 KiB. Iniciar monitoreo y, en otra PowerShell desde esta carpeta, ejecutar:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.monitor_demo
```

La demostración crea sus propios servicios TCP/UDP en `127.0.0.1`, intercambia datos con ellos y los cierra. No tiene opción de destino remoto y no escanea puertos de terceros. Deben aparecer paquetes, conexiones y las tres reglas al superar esos umbrales. Son comunicaciones benignas diseñadas para probar reglas; las alertas no son etiquetas de ataques. Detener monitoreo y restaurar los umbrales adecuados para su siguiente uso.

Se incluye además un [PCAP sintético Ethernet](demo/laboratorio_sintetico.pcap) de dos paquetes UDP bidireccionales, sin etiquetas de entrenamiento. Su lectura offline, separada del monitoreo real, puede comprobarse con:

```powershell
.\.venv\Scripts\python.exe -B -m seguridad_pymes.pcap_extract demo/laboratorio_sintetico.pcap --output demo/extraccion_nueva.json
```

La salida debe ser nueva: dos paquetes y un flujo con 38 características. El lector offline conserva sus reglas originales y solo admite Ethernet; el adaptador vivo admite además NULL/loopback IPv4. La captura real no se demuestra reproduciendo este PCAP: se comprueba con el monitor activo y los servicios locales del comando anterior.

## Historial, límites y recuperación

El historial de reglas está en `data/monitoring/history.sqlite3`; cada sesión tiene PCAPNG y configuración en `data/monitoring/sessions/`. El CSV conserva su base independiente en `data/processed/security_analysis.sqlite3`. Ninguna base histórica se entrega precargada. Los overrides de administrador `SIPYMES_MONITOR_DIR` y `SIPYMES_DATABASE_PATH` deben apuntar a ubicaciones separadas, escribibles y elegidas conscientemente.

Por defecto: 300 s, 256 MiB para el árbol de captura, 128 MiB para historial/capturas acumulados, 100.000 paquetes, 2.000 flujos activos y 10.000 segmentos. Se limita la cola a 1.024 paquetes, la ventana a 50.000 eventos y cada segmento a 256 paquetes; la inactividad es 5 s y la ventana activa 30 s. El RSS se supervisa cada 250 ms; Windows limita además memoria comprometida del Job Object. No es un límite por hilo para toda la memoria de Streamlit. Los archivos de captura se autolimitan a la mitad del presupuesto; buffers, bloques PCAPNG y diagnóstico final pueden añadir un pequeño margen antes del cierre. No se borran sesiones automáticamente.

Si un límite impide conservar todas las observaciones, la sesión queda parcial/con error y registra qué no se persistió. No se descartan flujos silenciosamente para fingir cobertura. La captura física puede perder paquetes sin evidencia suficiente para cuantificarlo; el sistema no garantiza completitud. Los PCAPNG pueden contener información sensible y requieren almacenamiento autorizado. Ver [recuperación](RECUPERACION.md) y [resultados/limitaciones](VERIFICACION.md).

El análisis CSV sigue siendo por archivo, con 42 características, regla `predict`, límite de entrada 100 MiB y las ventanas de historial anteriores. Su [CSV sintético de demostración](demo/demostracion_sintetica.csv) conserva ocho resultados y cuatro alertas esperadas, independientes de las reglas de red. Ninguna de estas pruebas mide precisión de detección en redes reales ni sustituye una prueba en otro equipo físico.


## Comprobación física adicional

Wi-Fi verificada desde Streamlit en esta computadora: 18,28 s, 315 paquetes IPv4, 23 conexiones, 24 segmentos y ninguna alerta. Ver [alcance y resultados](VERIFICACION_WIFI.md) y [resumen verificable](validacion_wifi.json). Código y modelo idénticos a la entrega anterior. Ethernet y otras redes requieren su propia comprobación autorizada.
