import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/microsoft/BIPIA"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/bipia"))
        update_manifest("bipia", {**r, "url": URL, "license_note": "custom Microsoft; needs_confirmation"})
    except Exception as e:
        append_fetch_error("bipia", e); raise
if __name__ == "__main__": main()
