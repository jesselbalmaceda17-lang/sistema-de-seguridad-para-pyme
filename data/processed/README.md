# Datos procesados y reportes

Este directorio contiene localmente:

- `demo_20_registros.csv`, muestra de 20 registros derivada del conjunto de
  entrenamiento, para una demostración diagnóstica y no para estimar
  generalización.
- `evaluation/metrics.json`, matriz CSV y gráficos SVG del benchmark oficial
  sobre el holdout de UNSW-NB15 con el modelo definitivo.
- `threshold_study/threshold_study_report.json`, `threshold_metrics.csv`,
  metadatos y el modelo experimental asociado.
- La base SQLite de trabajo y archivos de respaldo, que contienen historial
  local de análisis y estados de revisión.

Los reportes y artefactos requeridos para identificar esta entrega tienen
tamaño y SHA-256 en `delivery-manifest.json`. La carpeta está excluida por
`.gitignore`; un checkout limpio no los incluye automáticamente. Antes de
redistribuir datos UNSW-NB15, revise su licencia y procedencia.

La SQLite activa y sus respaldos no forman parte del manifiesto de paquete:
contienen historial de uso local y deben distribuirse solo mediante un proceso
de respaldo autorizado, separado y con controles de privacidad. El respaldo
verificado existente debe conservarse sin modificaciones.

Los resultados guardados son un benchmark del conjunto usado y no acreditan
rendimiento en redes reales de PYMES. Las métricas del estudio de umbral fueron
seleccionadas y medidas en la misma partición de validación; corresponden al
modelo experimental, no al modelo definitivo, y no son una estimación
independiente.
