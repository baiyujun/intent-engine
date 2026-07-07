import pathlib, shutil
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
LOCAL = pathlib.Path("/home/hjy/ClawSentry/src/clawsentry/gateway/attack_patterns.yaml")
URL = "https://github.com/AI45Lab/ClawSentry"
def main():
    try:
        if LOCAL.exists():
            pathlib.Path("raw/clawsentry_rules").mkdir(parents=True, exist_ok=True)
            shutil.copy(LOCAL, pathlib.Path("raw/clawsentry_rules/attack_patterns.yaml"))
            update_manifest("clawsentry_rules", {"source_ref": "local:/home/hjy/ClawSentry", "action": "copy"})
        else:
            r = clone_or_pull(URL, pathlib.Path("raw/clawsentry_rules/repo"))
            update_manifest("clawsentry_rules", {**r, "url": URL, "license_note": "MIT"})
    except Exception as e:
        append_fetch_error("clawsentry_rules", e); raise
if __name__ == "__main__": main()
