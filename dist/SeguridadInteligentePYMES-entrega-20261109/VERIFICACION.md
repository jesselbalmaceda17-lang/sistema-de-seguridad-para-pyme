# Estado de verificación de esta entrega

Entorno nuevo creado con el Python base de Windows; 41 versiones fijadas comprobadas y pip check sin conflictos. 7 pruebas de aceptación del paquete: APROBADAS. Código operativo y modelo conservados sin cambios.

El entorno no hereda site-packages globales ni del entorno de desarrollo; los paquetes se descargaron sin caché desde los requisitos incluidos. La prueba utiliza Python aislado y confirma que módulos y dependencias se importan de las ubicaciones esperadas. Se conserva el mismo intérprete base instalado en este Windows: no equivale a una prueba en otro equipo físico.

| Filas sintéticas | CSV bytes | Clasificación y scores (s) | Modelo (s) | Escritura final SQLite (s) | Reporte (s) | Pico RSS árbol (MiB) | Estado |
|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 1541 | 0.094 | 0.092 | 0.013 | 0.013 | 259.4 | PASSED |
| 100 | 14961 | 0.090 | 0.085 | 0.014 | 0.016 | 261.6 | PASSED |
| 1000 | 149258 | 0.158 | 0.134 | 0.021 | 0.049 | 256.6 | PASSED |
| 10000 | 1499259 | 0.564 | 0.105 | 0.095 | 0.494 | 267.0 | PASSED |
| 50000 | 7539259 | 1.787 | 0.111 | 0.424 | 1.673 | 380.3 | PASSED |

Cada proceso tuvo un límite de 120 s y 1,5 GiB RSS. Se exigieron al menos 4 GiB disponibles antes de cada lote. El RSS externo suma el lanzador de Windows y sus descendientes cada 50 ms: es una suma conservadora, no memoria física única. 10.000 filas es un lote de referencia offline; 50.000 es exploratorio. Los datos son sintéticos y las pruebas no miden precisión, concurrencia ni garantizan rendimiento a 100 MiB. La medición de reporte abarca construcción y serialización con funciones y formato existentes, sin tiempo de renderizado/transmisión del navegador.

Arranque real mediante el script del paquete: HTTP de salud en 2.812 s; interfaz, análisis, revisión, historial y exportaciones verificados en navegador con SQLite nueva. Persistencia tras reinicio: True. Se comprobó otra ubicación con espacios y sin rutas de desarrollo en los archivos operativos.

Las versiones y resultados anteriores se refieren a este equipo Windows 11. Pendiente: otro equipo físico, instalación offline (no se incluyen wheels), carga real representativa del despliegue y concurrencia. No hay autenticación ni captura en vivo; el modelo PCAP permanece fuera de la entrega. El comentario histórico del lock sobre instalación no verificada describe su creación previa; este registro informa el resultado posterior sin alterar ese archivo.

Los resultados de detección no se validaron con tráfico real ni etiquetas nuevas. El fixture solo comprueba consistencia. No se garantiza ausencia de defectos ni de vulnerabilidades. Consulte [README.md](README.md) y [RECUPERACION.md](RECUPERACION.md).
