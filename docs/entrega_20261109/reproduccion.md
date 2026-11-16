# Comandos de la verificación técnica

Ejecutados en PowerShell desde la raíz del proyecto, salvo el launcher, que también se ejecutó desde fuera del paquete. Usar las instrucciones del [paquete](../../dist/SeguridadInteligentePYMES-entrega-20261109/README.md) para instalar una entrega normal. Este registro describe las pruebas y no requiere mover ni alterar fuentes originales.

## Entorno independiente utilizado en los resultados finales

```powershell
py -3.14 -m venv _delivery_validation/venv_entrega
.\_delivery_validation\venv_entrega\Scripts\python.exe -m pip --isolated install --no-cache-dir --disable-pip-version-check --retries 1 --timeout 20 --report docs/entrega_20261109/instalacion_paquete_pip.json --log docs/entrega_20261109/instalacion_paquete_pip.log -r dist/SeguridadInteligentePYMES-entrega-20261109/requirements-lock.txt -r dist/SeguridadInteligentePYMES-entrega-20261109/requirements.txt
.\_delivery_validation\venv_entrega\Scripts\python.exe -I -m pip check
.\_delivery_validation\venv_entrega\Scripts\python.exe -I -B dist/SeguridadInteligentePYMES-entrega-20261109/herramientas/verificar_paquete.py
```

Para una repetición verdaderamente limpia elegir otro nombre de entorno que no exista y ajustar los comandos; no copiar paquetes del entorno anterior. La creación final utiliza el lanzador base, no el Python del entorno original. El [registro de aislamiento](pruebas_paquete_001/instalacion_limpia.json) contiene la configuración efectiva, rutas de importación, versiones y resultado de `pip check`.

## Aceptación y carga con resultados nuevos

Los directorios de salida deben ser nuevos. Estos comandos usan nombres de ejemplo para una repetición posterior y rechazan sobrescrituras:

```powershell
.\_delivery_validation\venv_entrega\Scripts\python.exe -I -B docs/entrega_20261109/test_paquete.py dist/SeguridadInteligentePYMES-entrega-20261109 docs/entrega_20261109/pruebas_paquete_repeticion
.\_delivery_validation\venv_entrega\Scripts\python.exe -I -B docs/entrega_20261109/rendimiento.py dist/SeguridadInteligentePYMES-entrega-20261109 _delivery_validation/venv_entrega/Scripts/python.exe docs/entrega_20261109/rendimiento_repeticion
.\_delivery_validation\venv_entrega\Scripts\python.exe -B -m unittest discover -s tests -v
```

El [harness de carga](rendimiento.py) fija 120 s y 1,5 GiB RSS por caso; exige 4 GiB de memoria disponible antes de cada lote. Produce CSV sintéticos, SQLite nuevas, logs y resultados por etapa. No entrena, no captura interfaces ni procesa datasets de investigación. La medición final registrada es [rendimiento_003](rendimiento_003/resultados.json); los pilotos se conservaron y están identificados en el [informe](informe_entrega_tecnica.md).

## Inicio desde cualquier ubicación

Desde la carpeta extraída y con el entorno normal instalado en su interior:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\iniciar.ps1
```

El parámetro opcional `-PythonPath` permite proporcionar un entorno nuevo situado fuera del paquete. Así se probó el launcher:

```powershell
$pythonPrueba = (Resolve-Path .\_delivery_validation\venv_entrega\Scripts\python.exe).Path
$launcher = (Resolve-Path '.\_delivery_validation\Copia independiente con espacios\iniciar.ps1').Path
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $launcher -PythonPath $pythonPrueba -Port 8527
```

El [supervisor de arranque](servidor_paquete.py) documenta el proceso real, su cwd externo al paquete, limpieza de overrides, health HTTP y reinicio. La [verificación externa](arranque_externo.json) registra el launcher ejecutado desde la extracción del ZIP fuera del proyecto, puerto 8528, y su detención. Las rutas absolutas de esos registros son evidencias del equipo de prueba; el paquete usa rutas relativas o derivadas de su propia ubicación.

En navegador se cargó el CSV del propio paquete y se contrastaron ocho predicciones/cuatro alertas con [el oráculo](../../dist/SeguridadInteligentePYMES-entrega-20261109/demo/resultados_esperados.json). La revisión y las exportaciones se ejercitaron en la copia con espacios; los [archivos de estado](navegador_final.json) y [la comprobación externa final](navegador_externo_final.json) guardan los resultados. Las acciones del navegador no se reproducen automáticamente con los comandos anteriores.

## Protección y recuperación

La [protección inicial](respaldo_inicial.json) identifica el respaldo restaurado. El [verificador final](integridad_cierre.py) comprueba contra esa foto los archivos originales, las tres SQLite, restauración, modelos y distribución. Puede repetirse antes de usar o modificar normalmente las bases originales:

```powershell
.\_delivery_validation\venv_entrega\Scripts\python.exe -I -B docs/entrega_20261109/integridad_cierre.py
```

El verificador espera que no hayan cambiado los archivos protegidos desde el cierre. El procedimiento operativo de backup/restauración para el usuario está en [RECUPERACION.md](../../dist/SeguridadInteligentePYMES-entrega-20261109/RECUPERACION.md) y fue probado con bases sintéticas, revisión persistida, origen corrupto y destino existente. No usar las bases de prueba para reemplazar las originales.

Las utilidades de preparación, finalización y empaquetado se conservan como trazabilidad de esta ejecución. No volver a ejecutarlas sobre la distribución congelada: un cambio produciría una entrega distinta y exigiría un nuevo manifiesto y pruebas. El [registro del ZIP](paquete_final.json) permite comprobar la identidad del entregable actual.
