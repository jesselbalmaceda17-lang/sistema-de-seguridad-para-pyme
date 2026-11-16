"""Small frozen baselines; no dependency on labels, captures or production models at prediction."""

from collections import Counter
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from pcap_experiment.common import require
from pcap_experiment.contract import FEATURE_NAMES, RF_PARAMETERS, SEED


class FixedRule(ClassifierMixin, BaseEstimator):
    def __init__(self, rule="tcp"):
        self.rule = rule

    def fit(self, X, y, sample_weight=None):
        require(self.rule in {"tcp", "syn_no_ack"}, "Unknown fixed rule")
        require(X.shape[1] == 38, "Fixed rules require the exact 38-column contract")
        self.classes_ = np.array([0, 1])
        self.n_features_in_ = 38
        return self

    def predict_proba(self, X):
        require(X.ndim == 2 and X.shape[1] == self.n_features_in_, "Wrong predictor shape")
        protocol = X[:, FEATURE_NAMES.index("transport_protocol")]
        require(np.isin(protocol, [0, 1]).all(), "Unknown protocol code")
        tcp = protocol == 1
        if self.rule == "tcp":
            positive = tcp
        else:
            columns = [FEATURE_NAMES.index(f"{d}_tcp_{flag}_count")
                       for flag in ("syn", "ack") for d in ("forward", "reverse")]
            flags = X[:, columns]
            require(np.isfinite(flags[tcp]).all(), "SYN rule cannot invent unknown TCP flags")
            positive = tcp & (flags[:, 0] + flags[:, 1] > 0) & (flags[:, 2] + flags[:, 3] == 0)
        p = positive.astype(float)
        return np.column_stack([1-p, p])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


def training_weights(metadata):
    counts = Counter(m["connection_group_id"] for m in metadata)
    values = np.array([1 / counts[m["connection_group_id"]] for m in metadata])
    return values / values.mean()


def make_models():
    return {"dummy": Pipeline([("classifier", DummyClassifier(strategy="prior", random_state=SEED))]),
            "tcp_rule": Pipeline([("classifier", FixedRule("tcp"))]),
            "syn_no_ack_rule": Pipeline([("classifier", FixedRule("syn_no_ack"))]),
            "random_forest": Pipeline([("classifier", RandomForestClassifier(**RF_PARAMETERS))])}


def positive_scores(model, X):
    probabilities = model.predict_proba(X)
    classes = list(model.classes_)
    return probabilities[:, classes.index(1)] if 1 in classes else np.zeros(len(X))
