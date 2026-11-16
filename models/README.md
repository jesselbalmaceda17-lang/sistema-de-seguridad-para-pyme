# Artefactos de modelos

Esta carpeta contiene localmente el modelo definitivo seleccionable por defecto,
`unsw_nb15_random_forest.joblib`, y sus metadatos. El Pipeline serializado
incluye preprocesamiento y clasificador. La aplicación usa exactamente
`model.predict()` para su regla predeterminada.

El segundo modelo seleccionable es
`data/processed/threshold_study/threshold_study_random_forest.joblib`; es un
Pipeline experimental ajustado por separado y clasifica con el score de clase 1
de `predict_proba` >= 0.65. Sus métricas pertenecen a una partición de
validación usada también para seleccionar el umbral; no son métricas del modelo
definitivo ni una evaluación independiente.

Ambos modelos y sus archivos `.metadata.json` figuran en
`delivery-manifest.json`. El artefacto `unsw_nb15_random_forest_pilot.joblib` y
sus metadatos también existen localmente, pero son desarrollo/selección y no
son requeridos por el selector ni por una entrega operativa.

La carpeta `models/` está excluida por `.gitignore`; por tanto, un checkout
limpio no incluye estos archivos. Para reproducir la aplicación, obtenga los
artefactos del paquete de entrega o cópielos desde una fuente verificada y
compruebe sus hashes. No asuma que los artefactos estarán presentes al instalar
solo el código.

Los artefactos joblib solo deben cargarse desde ubicaciones de confianza:
deserializarlos puede ejecutar código.
