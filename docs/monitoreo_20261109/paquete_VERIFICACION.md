# Verificación operativa — 9 de noviembre de 2026

Versión de monitoreo aprobada para el alcance local comprobado: Windows 11 x64, Python 3.14.6, TShark 4.6.9 y Npcap 1.88. Se continuó el trabajo existente, sin modificar módulos durante este cierre. No hay defectos reproducibles pendientes en las pruebas realizadas. El código distribuido coincide por SHA-256 con el que superó las pruebas; los últimos cambios anteriores al cierre quedaron incluidos.

## Qué se comprobó en vivo

- Aplicación Streamlit ejecutada mediante su launcher desde una copia independiente, fuera de desarrollo, en una ruta con espacios. Inicio desde el navegador sobre `\Device\NPF_Loopback`, con autorización explícita y umbrales de demostración SYN=5, puertos=4 y volumen=1 KiB.
- El generador propio completó 12 conexiones TCP y 8 intercambios UDP locales. La sesión observó **8.103 paquetes, 14 conexiones, 45 segmentos y 4 alertas**: las tres reglas, con un segundo aviso de volumen tras otra ventana. También había tráfico local de fondo; estos totales no se atribuyen exclusivamente al generador. Se identificaron sus 13 flujos.
- Revisión manual guardada como falso positivo desde Streamlit y comprobada en SQLite. Detención con el botón: estado `stopped` tanto en sesión como en contadores persistidos, sin sesión parcial ni cierre forzado. Integridad SQLite `ok`.
- Lectura del PCAPNG conservado: solo `127.0.0.1`, sin paquetes del puerto 8531 de Streamlit. TShark/dumpcap ausentes después del cierre. El servidor de pruebas propio se detuvo comprobando la identidad de sus procesos.

## Qué se comprobó con simulaciones o archivos

| Comprobación | Resultado y alcance |
|---|---|
| Monitoreo tras los últimos cambios | **38/38** pruebas: observaciones sintéticas, reglas, límites, persistencia, errores, autorización y controles Streamlit con transporte simulado. |
| Suite completa actual | **273/273**. Incluye las 38 anteriores; no deben sumarse como pruebas distintas. Las pruebas de entrenamiento usan fixtures y artefactos temporales; no se reentrenó ningún modelo existente del proyecto. |
| Aceptación CSV en copia independiente | **7/7**: modelo original real, CSV sintético conocido, 8 registros y 4 alertas; predicciones y scores coinciden con el oráculo anterior. SQLite, revisión, exportaciones, entradas inválidas, recuperación y detección de alteración. AppTest sustituye únicamente el transporte de carga/descarga; no demuestra ese transporte HTTP. |
| PCAP Ethernet sintético | Extracción CLI: 2 paquetes, 1 flujo, 38 características. Es lectura de archivo, no prueba de captura real. |
| Evidencia previa reutilizada | Integración conservada: captura real de 142 paquetes/13 conexiones/3 alertas, replay con las mismas 38 características, nueva sesión por duración y cierre abrupto con eliminación de hijos mediante Job Object. Se verificó otra vez el hash de su PCAP; no se presenta como una nueva ejecución. |
| Archivos protegidos | 2.521 archivos sin cambios y ninguno ausente respecto al respaldo anterior al monitoreo. La única diferencia de los 2.522 registrados es la integración ya existente en el panel. Incluye los 5 archivos de modelos y los 228 de experimentos, sin alteraciones. Tres bases originales con hash binario y lógico conservados e `integrity_check=ok`. |
| Respaldo existente | SHA-256 y CRC del ZIP previo comprobados; su restauración de 778 archivos ya estaba verificada. No se repitió el respaldo ni la restauración masiva. |

El Random Forest original conserva SHA-256 `58505ee89df22c4c223b66d5e7172388d5d1fad6b7d135fce800a2765b2029e9`. No se modificaron modelos, datasets ni experimentos PCAP previos. Las alertas de monitoreo proceden de reglas transparentes y no son inteligencia artificial.

## Qué permanece sin verificar

Otro equipo físico, instalación nueva de drivers en él, visibilidad de Wi-Fi/Ethernet, red de una PYME, carga sostenida, precisión o falsos positivos en producción. No se capturó una red ajena. IPv6, VLAN y fragmentación permanecen fuera del alcance implementado. Los límites de memoria y errores se probaron principalmente con simulaciones; la evidencia de cierre abrupto es la previa reutilizada.

Se reutilizó el entorno virtual limpio ya instalado y se volvieron a comprobar sus 41 versiones y `pip check`; no se repitieron las descargas de dependencias. Los historiales de prueba, PCAPNG reales y bases originales no se incluyen en el ZIP limpio. La distribución contiene requisitos, [instalación y demostración](README.md), [recuperación](RECUPERACION.md) y manifiesto SHA-256. El informe de cierre del proyecto registra la ruta independiente, los logs y la comprobación final del ZIP. Esta es una verificación técnica de entrega, no documentación académica.
