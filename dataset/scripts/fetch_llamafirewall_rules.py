import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/meta-llama/PurpleLlama"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/llamafirewall_rules"))
        update_manifest("llamafirewall_rules", {**r, "url": URL, "license_note": "custom; needs_confirmation"})
    except Exception as e:
        append_fetch_error("llamafirewall_rules", e); raise
if __name__ == "__main__": main()
