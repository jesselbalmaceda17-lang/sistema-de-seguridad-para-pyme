# Pruebas

Las pruebas se ejecutan con `unittest` de la biblioteca estándar:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

La suite usa CSV, bases SQLite y modelos temporales. Algunos casos entrenan
modelos pequeños sobre fixtures y llaman a predicción para comprobar interfaces,
persistencia y errores; no leen ni evalúan los datasets oficiales y no son
evidencia de eficacia de los modelos.

La prueba de medición de recursos usa un Pipeline y filas efímeras para verificar
la instrumentación `psutil` a varios tamaños; sus tiempos y memoria no son un
benchmark de UNSW-NB15 ni deben citarse como resultados del proyecto.

El número de pruebas aprobadas se informa en el registro de validación de cada
cierre, no como una propiedad fija de la suite.
