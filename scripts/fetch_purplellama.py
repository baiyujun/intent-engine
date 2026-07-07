import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/meta-llama/PurpleLlama"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/purplellama"))
        update_manifest("purplellama", {**r, "url": URL, "license_note": "Llama Community License; needs_confirmation"})
    except Exception as e:
        append_fetch_error("purplellama", e); raise
if __name__ == "__main__": main()
