"""Render retained results without fitting or selecting any model."""

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from pcap_experiment.common import read_json, require, write_json

BASE = Path(__file__).resolve().parent
METHODS = ("dummy", "tcp_rule", "syn_no_ack_rule", "random_forest")
CAPTURES = ("torii", "hakai", "hue")
METRICS = ("precision_malicious", "recall_malicious", "f1_malicious", "false_positive_rate",
           "balanced_accuracy", "pr_auc_average_precision")


def fmt(value):
    return "N/A" if value is None else f"{value:.6f}"


def report(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    result = read_json(BASE / "run_003/results.json")
    manifest = read_json(BASE / "run_003/dataset/manifest.json")
    tests = read_json(BASE / "evidence/full_final.json")
    specific = read_json(BASE / "evidence/specific_final.json")
    integrity = read_json(BASE / "evidence/integrity_final.json")
    replay = read_json(BASE / "evidence/replay_final.json")
    roundtrip = read_json(BASE / "evidence/model_roundtrip.json")
    correction = read_json(BASE / "evidence/numerical_correction.json")
    environment = read_json(BASE / "run_003/environment.json")
    backup = read_json(BASE / "evidence/backup.json")
    require(tests["successful"] and specific["successful"] and integrity["all_unchanged"]
            and replay["all_identical"] and roundtrip["all_predictions_exact"], "Final evidence incomplete")
    with (BASE / "run_003/dataset/metadata.jsonl").open(encoding="utf-8") as f:
        metadata = [json.loads(line) for line in f]
    fields = ["capture", "method", "unit", "view", "n", "benign", "malicious", "tn", "fp", "fn", "tp", *METRICS, "undefined_reasons"]
    with (output / "metrics.csv").open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n"); writer.writeheader()
        for capture in CAPTURES:
            for method in METHODS:
                for unit, views in result["folds"][capture]["models"][method]["metrics"].items():
                    for view, m in views.items():
                        cm = m["confusion_matrix_true_rows_predicted_columns_B_M"]
                        writer.writerow({"capture": capture, "method": method, "unit": unit, "view": view,
                            **{k:m[k] for k in ("n", "benign", "malicious", *METRICS)},
                            "tn":cm[0][0], "fp":cm[0][1], "fn":cm[1][0], "tp":cm[1][1],
                            "undefined_reasons":json.dumps(m["undefined_reasons"], sort_keys=True)})
    with (output / "resources.csv").open("x", encoding="utf-8", newline="") as f:
        fields = ["capture", "method", "train_seconds", "infer_seconds", "train_cpu_seconds", "infer_cpu_seconds",
                  "train_sampled_rss_peak_bytes", "infer_sampled_rss_peak_bytes", "compressed_model_bytes"]
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n"); writer.writeheader()
        for capture in CAPTURES:
            for method in METHODS:
                r = result["folds"][capture]["models"][method]
                writer.writerow(dict(capture=capture, method=method, train_seconds=r["training"]["wall_seconds"],
                    infer_seconds=r["inference"]["wall_seconds"], train_cpu_seconds=r["training"]["cpu_seconds"],
                    infer_cpu_seconds=r["inference"]["cpu_seconds"], train_sampled_rss_peak_bytes=r["training"]["sampled_rss_peak_bytes"],
                    infer_sampled_rss_peak_bytes=r["inference"]["sampled_rss_peak_bytes"], compressed_model_bytes=r["model"]["size_bytes"]))
    # Descriptive score ranges only. They never feed back into the fixed threshold.
    pattern_scores = []
    by_id = {m["flow_id"]: m for m in metadata}
    for capture in CAPTURES:
        for method in METHODS:
            folder = BASE / ("run_003/held_out_"+capture)
            with (folder / (method+"_predictions.csv")).open(encoding="utf-8") as f:
                flows = [{"class":row["binary_label"], "protocol":by_id[row["flow_id"]]["protocol"],
                          "behavior":by_id[row["flow_id"]]["behavior_flow"], "score":float(row["probability_malicious"])}
                         for row in csv.DictReader(f)]
            groups = [{"class":str(r["binary_label"]), "protocol":r["protocol"], "behavior":r["behavior"], "score":r["probability_malicious"]}
                      for r in read_json(folder/(method+"_group_predictions.json"))]
            for unit, records in (("flow",flows),("group",groups)):
                partitions = defaultdict(list)
                for r in records: partitions[(r["class"],r["protocol"],r["behavior"])].append(r["score"])
                for (label, protocol, behavior), values in sorted(partitions.items()):
                    values.sort(); n=len(values); median=(values[(n-1)//2]+values[n//2])/2
                    pattern_scores.append(dict(capture=capture, method=method, unit=unit, binary_label=int(label),
                        protocol=protocol, behavior=behavior, n=n, minimum=values[0], median=median, maximum=values[-1]))
    with (output/"pattern_scores.csv").open("x",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=list(pattern_scores[0]),lineterminator="\n");writer.writeheader();writer.writerows(pattern_scores)
    lines = ["# Experimento PCAP v1: informe técnico", "",
        "El proceso experimental se completó y reprodujo. **El Random Forest no demuestra generalización suficiente para integrarse como detector.** "
        "Coincide con SYN sin ACK en las decisiones de Torii/Hakai y falla extensamente sobre TCP benigno de Hue. "
        "Son resultados exploratorios de tres capturas IoT de laboratorio, no una validación para PYMES.", "",
        "## Protección y alcance", "",
        f"Antes de modificar archivos se verificaron 165 archivos anteriores y 32 adiciones inventariadas. El respaldo nuevo "
        f"restauró {backup['restored_files_verified']} archivos, verificó CRC/SHA-256 y las tres SQLite restauradas resultaron íntegramente "
        "legibles y lógicamente idénticas. El proyecto no es un repositorio Git. "
        "Todos los archivos preexistentes permanecen intactos; no se descargaron datos ni se capturaron interfaces.", "",
        f"Respaldo: [archivo recuperable](../../../{backup['archive']}). SHA-256: `{backup['archive_sha256']}`. "
        "[Evidencia y manifiesto](../evidence/backup.json). La restauración se conserva en la ruta allí indicada.", "",
        "## Corpus efectivamente admitido", "",
        "| Captura | Flujos Benign | Flujos Malicious | Grupos Benign | Grupos Malicious |",
        "|---|---:|---:|---:|---:|"]
    for capture in CAPTURES:
        rows=[m for m in metadata if m["capture"]==capture]
        b=sum(m["binary_label"]==0 for m in rows);mal=len(rows)-b
        bg=len({m["connection_group_id"] for m in rows if m["binary_label"]==0})
        mg=len({m["connection_group_id"] for m in rows if m["binary_label"]==1})
        lines.append(f"| {capture} | {b} | {mal} | {bg} | {mg} |")
    lines += ["", "Total: **9.839 flujos, 7.794 grupos de conexión, 7.495 filas Benign y 2.344 Malicious**. "
        "Se recalcularon las tres auditorías por paquete y coincidieron con todos los campos de sus informes conservados. "
        "Quedan fuera cuatro flujos de Torii, 93 de Hue y toda Trojan 42-1. Los grupos no equivalen a ataques independientes.", "",
        "Los 38 predictores mantienen nombres, fórmulas y orden del contrato. Protocolo: TCP=1, UDP=0, "
        "versión `sipymes.protocol.tcp1-udp0.v1`. No hay IP, puertos, UID, identificadores, tiempos absolutos ni etiquetas como predictores. "
        "Esos campos y la calidad se conservan por separado. [Dataset/manifiesto](../run_003/dataset/manifest.json).", "",
        "Desconocidos: "+"; ".join(f"`{k}`: {v}" for k,v in manifest["unknown_reason_counts"].items())+". "
        "Se conservan vacíos en CSV y NaN en el modelo; no se imputan, no se añaden indicadores, no se sustituyen por cero. "
        "El bosque utiliza su tratamiento nativo de ausentes. Esta ausencia estructural también puede actuar como proxy del protocolo.", "",
        "## Diseño fijado antes de evaluar", "",
        "Se entrenó con Hakai+Hue para evaluar Torii; Torii+Hue para evaluar Hakai; y Torii+Hakai para evaluar Hue. "
        "Las capturas, grupos y flujos son disjuntos en cada pliegue. No hubo separación aleatoria de filas, SMOTE, "
        "búsqueda de parámetros, calibración ni selección posterior. [Contrato previo](../run_003/prespecified.json).", "",
        "Dummy aprende únicamente el prior ponderado de entrenamiento. TCP predice Malicious para TCP. SYN sin ACK "
        "predice Malicious para TCP con SYN total > 0 y ACK total = 0. Random Forest: 100 árboles, profundidad máxima 8, "
        "hoja mínima 5, sqrt, bootstrap, sin class_weight, n_jobs=1, semilla 20261108. Umbral fijo >=0,5.", "",
        "Dummy y bosque usan peso inverso al número de segmentos admitidos del grupo, normalizado a media 1. "
        "Cada conexión tiene igual peso total; las clases no se balancean. El bootstrap interno del bosque sigue siendo "
        "por filas ponderadas y puede omitir conexiones pequeñas: no se transforma en bootstrap por conexión.", "",
        "Por flujo se cuenta cada segmento una vez. Por grupo se promedian sus probabilidades y se aplica el mismo umbral; "
        "cada grupo cuenta una vez. Las vistas por grupo se calculan después de agregar todos sus segmentos. "
        "SYN puro exige exclusivamente SYN y cero payload en los paquetes auditados.", "",
        "## Resultados completos por captura y método", "",
        "Matriz `[[TN,FP],[FN,TP]]`; filas reales y columnas predichas Benign/Malicious. P/R/F1 se refieren a Malicious. "
        "Todas las tasas están en [0,1]. AP es average precision, la integral escalonada PR, no integración trapezoidal. "
        "N/A conserva su motivo explícito en JSON/CSV. Hue no tiene verdaderos Malicious; recall, F1, BA y AP no son aplicables.", ""]
    for unit,title in (("flow","Por flujo"),("group","Por grupo")):
        lines += ["### "+title,"", "| Captura | Modelo | Matriz | P | R | F1 | FPR | BA | AP |", "|---|---|---|---:|---:|---:|---:|---:|---:|"]
        for capture in CAPTURES:
            for method in METHODS:
                m=result["folds"][capture]["models"][method]["metrics"][unit]["all"]
                lines.append(f"| {capture} | {method} | {m['confusion_matrix_true_rows_predicted_columns_B_M']} | "+" | ".join(fmt(m[k]) for k in METRICS)+" |")
        lines.append("")
    lines += ["### Protocolo y comportamiento del bosque", "",
        "Los resultados de **todos** los métodos por TCP, UDP, SYN puro y otros comportamientos, por flujo y grupo, "
        "están en [metrics.csv](./metrics.csv), 120 combinaciones, incluidas las vistas vacías. "
        "Las probabilidades descriptivas por clase/patrón están en [pattern_scores.csv](./pattern_scores.csv).", "",
        "| Captura | Unidad | Vista | B/M reales | Matriz | Recall M | FPR |", "|---|---|---|---|---|---:|---:|"]
    for capture in CAPTURES:
        for unit in ("flow","group"):
            for view in ("tcp","udp","tcp_pure_syn","tcp_other"):
                m=result["folds"][capture]["models"]["random_forest"]["metrics"][unit][view]
                lines.append(f"| {capture} | {unit} | {view} | {m['benign']}/{m['malicious']} | {m['confusion_matrix_true_rows_predicted_columns_B_M']} | {fmt(m['recall_malicious'])} | {fmt(m['false_positive_rate'])} |")
    lines += ["", "## Interpretación y sesgos", "",
        "En Torii, RF y SYN sin ACK toman exactamente las mismas decisiones: cuatro segmentos SYN maliciosos detectados "
        "y 284 segmentos de dos conexiones maliciosas distintas de SYN puro omitidos. El recall por flujo es 1,39 %, "
        "mientras por grupo es 66,67 % (4/6): la diferencia nace de la segmentación, no de 284 ataques adicionales.", "",
        "En Hakai, RF y SYN sin ACK vuelven a coincidir completamente, con F1=1. Todos los 2.056 grupos maliciosos son "
        "SYN puro. Este resultado perfecto no demuestra diversidad ni capacidad general de detección.", "",
        "En Hue, el bosque produce 297 falsos positivos de 2.107 flujos y 44 de 359 grupos. Entre TCP, falla en "
        "297/302 flujos (98,34 %) y 44/49 grupos (89,80 %). UDP diluye la FPR global a 14,10 % y 12,26 %. "
        "Dummy y SYN sin ACK no producen falsos positivos en Hue. La regla TCP produce 302 y 49, respectivamente.", "",
        "La regla TCP supera al bosque en recall sobre Torii, pero falla sobre Hue. No se elige esa regla como sustituto: "
        "estos son resultados exploratorios de modelos fijados previamente. El bosque supera a SYN sin ACK en AP sobre "
        "Torii (ranking), pero no en decisiones al umbral fijado. Una AP alta no elimina el mal recall operativo. "
        "No se ajustó el umbral con esta captura ni se reclama que el bosque implemente únicamente SYN.", "",
        "Las importancias por impureza asignan aproximadamente 45,15 %, 48,32 % y 43,98 % a banderas TCP en los pliegues "
        "Torii, Hakai y Hue. La columna protocolo tiene poca importancia directa, pero sus proxies incluyen tamaños, "
        "intervalos y ausencias estructurales. Estas importancias correlacionadas no prueban causalidad ni constituyen "
        "una ablación independiente.", "",
        "El corpus tiene 52 grupos TCP benignos; solo 49 son bidireccionales y todos vienen de Hue, con payload en ambos "
        "sentidos en siete. De 2.062 grupos maliciosos, 2.060 son SYN puro y solo dos tienen otro patrón. "
        "Una conexión TCP de Hue genera 254 segmentos. Persisten sesgos de dispositivo, familia, periodo, protocolo, "
        "etiquetado y exclusión conservadora de casos difíciles. No hay Malicious UDP admitido. "
        "Tres capturas no permiten una separación robusta adicional de entrenamiento/validación/prueba. "
        "Los pliegues tampoco representan una evaluación prospectiva cronológica.", "",
        "## Recursos medidos", "",
        f"La construcción del corpus y nueva auditoría consumieron {result['dataset_preparation_resources']['wall_seconds']:.3f} s; "
        f"pico RSS muestreado {result['dataset_preparation_resources']['sampled_rss_peak_bytes']/2**20:.2f} MiB. "
        f"La ejecución canónica ocupa {sum(p.stat().st_size for p in (BASE/'run_003').rglob('*') if p.is_file()):,} bytes; "
        f"sus 12 modelos comprimidos suman {sum(p.stat().st_size for p in (BASE/'run_003').rglob('*.joblib')):,} bytes. "
        "La memoria se muestrea cada 10 ms: no es un pico exacto, incluye datos residentes y no equivale al tamaño del modelo. "
        "[Recursos de los 12 modelos](./resources.csv).", "",
        "| Captura evaluada | RF entrenamiento s | Inferencia lote s | Pico RSS entrenamiento MiB | Archivo bytes |",
        "|---|---:|---:|---:|---:|"]
    for capture in CAPTURES:
        m=result["folds"][capture]["models"]["random_forest"]
        lines.append(f"| {capture} | {m['training']['wall_seconds']:.6f} | {m['inference']['wall_seconds']:.6f} | {m['training']['sampled_rss_peak_bytes']/2**20:.2f} | {m['model']['size_bytes']} |")
    lines += ["", f"Python {environment['python']}; dependencias: "+json.dumps(environment['versions'],sort_keys=True)+". "
        "No se instalaron dependencias. El entorno, código y configuraciones tienen hashes registrados.", "",
        "## Pruebas, corrección y reproducibilidad", "",
        f"Resultado final: **{specific['passed']} pruebas específicas y {tests['passed']} completas aprobadas**, "
        f"{tests['failures']} fallos, {tests['errors']} errores y {tests['skipped']} omisiones en la suite final. "
        "[Específicas](../evidence/specific_final.json), [suite completa](../evidence/full_final.json).", "",
        "Se detectó una corrección real de precisión numérica: np.mean podía asignar distintos últimos bits a grupos "
        "de diferente longitud con idéntico prior Dummy. Eso rompía empates y alteraba AP por grupo. "
        f"Torii Dummy pasó de AP={correction['old_torii_dummy_group_ap']:.12f} a "
        f"{correction['corrected_torii_dummy_group_ap']:.12f}, exactamente su prevalencia 6/3198. "
        "Se añadió una regresión que primero falló (41 aprobadas, un fallo), y luego pasó al conservar probabilidades "
        "idénticas exactamente y usar suma precisa para las demás. No cambió ningún modelo, predictor, partición, "
        "umbral ni predicción por flujo. Las ejecuciones iniciales run_001/run_002 permanecen conservadas y están "
        "sustituidas para informar métricas por run_003/run_004. [Corrección y comparación](../evidence/numerical_correction.json).", "",
        f"Dos ejecuciones corregidas verificaron {len(replay['checks'])} comprobaciones de identidad: corpus/manifiesto, "
        "contrato, modelos serializados, predicciones por flujo/grupo y métricas. Tiempos y RSS se excluyen de la "
        "identidad porque se vuelven a medir. [Repetición](../evidence/replay_final.json). "
        "Los 12 pipelines locales recargados produjeron exactamente sus predicciones anteriores; cada uno consume 38 columnas. "
        "[Recarga verificada](../evidence/model_roundtrip.json).", "",
        f"Los {integrity['protected_files']} archivos preexistentes comprobados permanecen idénticos y las tres SQLite "
        "devuelven ok. El extractor 1.0.1, auditor, características, timeouts, interfaz, CSV y modelos UNSW no cambiaron. "
        "[Integridad final](../evidence/integrity_final.json). También se verificaron los siete respaldos anteriores.", "",
        "## Entregables, reproducción y reversión", "",
        "Código nuevo: [pcap_experiment](../../../pcap_experiment/), con contrato, corpus, modelos, evaluación, "
        "ejecución y validación; [pruebas nuevas](../../../tests/test_pcap_experiment.py). "
        "[Instrucciones reproducibles](../../../pcap_experiment/README.md). "
        "Cada ejecución contiene dataset/manifiesto, contrato previo, entorno, tres particiones, cuatro modelos por "
        "partición, predicciones y resultados. No existe un modelo final entrenado con todo el corpus y no se ha integrado ninguno.", "",
        "Para revertir basta con apartar los archivos nuevos indicados por el inventario; ningún componente original "
        "necesita sustitución. Se conserva el respaldo y la restauración verificada para recuperar archivos concretos "
        "en una carpeta separada. No restaurar sobre una SQLite abierta.", "",
        "## Recomendación", "",
        "Dar por completado el experimento como prueba funcional del proceso de aprendizaje. **No integrar este RF "
        "como detector ni reemplazar el modelo original.** Si se desea avanzar en clasificación, hace falta una ampliación "
        "dirigida que aporte TCP benigno de otras capturas/dispositivos y conexiones maliciosas no limitadas a SYN puro "
        "en capturas independientes. No hace falta recopilar indefinidamente para cerrar el software experimental: "
        "el resultado negativo ya está medido y es reproducible. Cualquier calibración posterior necesita datos "
        "independientes; estas capturas ya no constituyen una prueba final intacta. Mirai 34-1 y Amazon Echo 5-1 "
        "siguen reservados y no se han utilizado.", ""]
    with (output/"technical_report.md").open("x",encoding="utf-8",newline="\n") as f:f.write("\n".join(lines))
    print("Report created:",output)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    report(parser.parse_args().output)
