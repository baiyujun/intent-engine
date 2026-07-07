import pathlib
from src.fetch_utils import download_file, update_manifest, append_fetch_error
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
def main():
    try:
        r = download_file(URL, pathlib.Path("raw/mitre_attack/enterprise-attack.json"))
        update_manifest("mitre_attack", {**r, "url": URL, "license_note": "ATT&CK ToU; taxonomy ok, samples needs_confirmation"})
    except Exception as e:
        append_fetch_error("mitre_attack", e); raise
if __name__ == "__main__": main()
