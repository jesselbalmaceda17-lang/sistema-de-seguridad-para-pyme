"""Punto de entrada de la aplicación Streamlit."""

import os

from seguridad_pymes.database import DEFAULT_DATABASE_PATH
from seguridad_pymes.dashboard import render_dashboard
from seguridad_pymes.training import DEFAULT_MODEL_PATH


if __name__ == "__main__":
    model_path_override = os.environ.get("SIPYMES_MODEL_PATH")
    render_dashboard(
        model_path=(
            model_path_override
            if model_path_override is not None
            else str(DEFAULT_MODEL_PATH)
        ),
        database_path=os.environ.get(
            "SIPYMES_DATABASE_PATH",
            str(DEFAULT_DATABASE_PATH),
        ),
        model_path_override=model_path_override is not None,
    )
