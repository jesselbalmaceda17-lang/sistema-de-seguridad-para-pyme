"""Frozen choices made before inspecting held-out predictions."""

from seguridad_pymes.pcap_schema import feature_definitions

FEATURE_NAMES = tuple(feature_definitions())
PROTOCOL_VERSION = "sipymes.protocol.tcp1-udp0.v1"
PROTOCOL_ENCODING = {"udp": 0, "tcp": 1}
SEED = 20261108
THRESHOLD = 0.5
RF_PARAMETERS = dict(n_estimators=100, max_depth=8, min_samples_leaf=5,
                     max_features="sqrt", bootstrap=True, class_weight=None,
                     random_state=SEED, n_jobs=1)
SPECIFICATION = {
    "version": "sipymes.pcap-experiment.v1",
    "feature_names": list(FEATURE_NAMES), "feature_count": 38,
    "protocol_encoding_version": PROTOCOL_VERSION,
    "protocol_encoding": PROTOCOL_ENCODING,
    "unknowns": "empty CSV cell -> NaN; native RandomForest missing-value routing; no imputation or added predictors",
    "threshold": THRESHOLD, "positive_if": "probability >= 0.5",
    "random_forest": RF_PARAMETERS,
    "dummy": "weighted training class prior; no dependence on evaluation labels",
    "protocol_rule": "Malicious iff transport_protocol == tcp",
    "syn_rule": "Malicious iff TCP, total SYN > 0 and total ACK == 0; no evaluation tuning",
    "training_weights": "1 / admitted training segments in connection group, normalized to mean 1; Dummy and RF",
    "group_prediction": "arithmetic mean of all admitted segment probabilities in group, threshold >= 0.5",
    "pr_auc": "average precision (stepwise PR integral), only when both true classes exist",
    "single_class_policy": "recall/F1 Malicious null if no true Malicious; precision null if no predicted Malicious; balanced accuracy/AP null unless both true classes exist",
    "splits": [
        {"train": ["hakai", "hue"], "test": "torii"},
        {"train": ["torii", "hue"], "test": "hakai"},
        {"train": ["torii", "hakai"], "test": "hue"}],
    "scope": "exploratory leave-one-capture-out; no hyperparameter selection, calibration, definitive test or deployment claim",
}
