# Experimento PCAP v1

Este paquete es independiente de la aplicación, del pipeline UNSW-NB15 y de SQLite.
No captura interfaces, no adquiere datos y no es un detector validado para PYMES.

## Reproducción

Desde la raíz del proyecto y con las dependencias existentes del entorno virtual:

```powershell
.\.venv\Scripts\python.exe -B -m pcap_experiment.run --output experiments/pcap_v1/nueva_ejecucion
.\.venv\Scripts\python.exe -B -m pcap_experiment.validation specific --output experiments/pcap_v1/evidence/nuevas_especificas
.\.venv\Scripts\python.exe -B -m pcap_experiment.validation full --output experiments/pcap_v1/evidence/nuevas_completas
```

Cada salida debe ser nueva. El programa rechaza sobrescrituras. Las capturas y los
informes de extracción existentes deben estar en sus rutas originales. Antes de
construir el corpus, se vuelven a importar las etiquetas y a ejecutar las auditorías
por paquete; se exige igualdad con los informes conservados. No se modifica el auditor.

## Contrato de datos

- [contract.py](./contract.py) fija las 38 columnas, orden, protocolo TCP=1/UDP=0,
  semilla, modelos, reglas, particiones y umbral antes de evaluar.
- [dataset.py](./dataset.py) escribe tres archivos unidos **solo por posición de fila**:
  `features.csv` (38 predictores), `targets.csv` (etiqueta binaria) y
  `metadata.jsonl` (etiquetas originales/normalizadas, UID, procedencia, grupos,
  direcciones, frames, calidad y motivos de desconocidos).
- Las celdas vacías representan valores desconocidos; se cargan como NaN.
  Random Forest usa su soporte nativo de valores ausentes; no hay imputación,
  columnas indicadoras añadidas ni sustituciones por cero. Dummy ignora X.
  La regla SYN exige banderas conocidas para TCP y no interpreta NaN de UDP como cero.
- Ningún identificador, dirección, puerto, timestamp absoluto, etiqueta o calidad
  entra al modelo. La selección de columnas es una lista explícita, no una exclusión heurística.
- No entran los cuatro flujos pendientes de Torii, los 93 de Hue ni Trojan 42-1.

## Diseño fijado

Tres pliegues dejan fuera Torii, Hakai y Hue, respectivamente. Se comprueba que no
existen grupos de conexión, hashes de captura ni flujos compartidos entre entrenamiento
y evaluación. No se reservó una validación adicional; no se seleccionan parámetros,
modelos ni umbrales con los resultados. No se entrena un modelo final con todo el corpus.

Dummy usa el prior ponderado de entrenamiento. La regla TCP devuelve 1 para TCP.
La regla SYN devuelve 1 para TCP con suma SYN > 0 y suma ACK = 0 en ambas direcciones.
Random Forest utiliza 100 árboles, profundidad máxima 8, hoja mínima 5,
`max_features="sqrt"`, `bootstrap=True`, sin ponderación de clases, semilla 20261108
y un solo proceso. No se utiliza SMOTE ni búsqueda de hiperparámetros.

Cada conexión recibe el mismo peso total de entrenamiento: el peso de un segmento
es inverso al número de segmentos admitidos de su grupo, normalizado a media 1.
Esto no convierte las conexiones en ataques independientes. Tampoco hace que el
bootstrap interno del bosque se realice por grupos: utiliza filas ponderadas,
y esa limitación debe conservarse en la interpretación.

La predicción por grupo es la media aritmética de probabilidades de todos sus
segmentos admitidos, con umbral fijo >= 0,5; no es una votación por paquetes ni un
máximo. Se prohíben agregaciones parciales de grupos. Primero se agregan grupos
completos y después se separan por protocolo o comportamiento. Las métricas por
flujo no tienen ponderación; cada fila cuenta una vez. Las métricas por grupo cuentan
cada grupo una vez. No se mezclan en un único resultado.

## Métricas, modelos y recursos

La matriz tiene filas reales y columnas predichas, en orden Benign/Malicious.
PR-AUC se define explícitamente como **average precision**, no integración trapezoidal.
Precisión sin predicciones positivas es null. Recall y F1 Malicious sin casos reales
Malicious son null; exactitud balanceada y AP requieren ambas clases.
FPR necesita verdaderos benignos. Cada null conserva su motivo.

Los resultados contienen las vistas completa, TCP, UDP, TCP SYN puro y TCP otros,
por flujo y por grupo. SYN puro exige en los paquetes auditados exclusivamente
bandera SYN y cero payload. Este diagnóstico está en metadatos y no añade predictores.

Se conservan predicciones individuales, particiones, métricas, comparaciones
pareadas, importancias por impureza (no causales) y los cuatro pipelines de cada pliegue.
Las decisiones del experimento se reproducen con `positive_scores(model, X) >= 0.5`;
no se sustituye este contrato por las convenciones de desempate de `predict` de otro estimador.
Los archivos joblib son generados localmente; no se carga ningún modelo externo.
No deben cargarse archivos joblib de procedencia desconocida.

Se miden tiempos de pared/CPU y RSS del proceso cada 10 ms. El RSS incluye datos
residentes y ajustes anteriores; no representa la memoria exclusiva del modelo y
puede perder picos entre muestras. El tamaño comprimido del archivo se mide aparte.

## Límites y reversión

Solo hay tres capturas, dos con clase maliciosa; Hue no permite medir recall
malicioso. Protocolo, banderas, ausencias y comportamiento del dispositivo están
fuertemente asociados a las etiquetas. Las métricas son exploratorias y no tienen
intervalos de confianza que supongan independencia entre ataques.

El respaldo y su restauración verificada están documentados en
[backup.json](../experiments/pcap_v1/evidence/backup.json). Para desactivar este trabajo
basta con no ejecutar el paquete: la aplicación nunca lo importa. Para retirarlo,
tras verificar el inventario, pueden apartarse este paquete, el test nuevo y el
directorio de resultados. Los componentes originales no necesitan restauración.
El respaldo puede restaurarse primero en una carpeta nueva para comparar y recuperar
archivos concretos; no se recomienda extraerlo sobre una base SQLite en uso.
