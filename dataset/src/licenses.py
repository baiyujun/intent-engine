"""License gate driven by scripts/license_config.yaml."""
import pathlib, yaml

_CONFIG = None
_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "license_config.yaml"

def load_license_config() -> dict:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = yaml.safe_load(_PATH.read_text()) or {}
    return _CONFIG

def _entry(source_key: str) -> dict:
    return load_license_config().get(source_key, {})

def license_status(source_key: str) -> str:
    return _entry(source_key).get("license_status", "excluded")

def license_spdx(source_key: str):
    return _entry(source_key).get("license_spdx")

def can_enter_training(source_key: str) -> bool:
    return license_status(source_key) == "ok"
