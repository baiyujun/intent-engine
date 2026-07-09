import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/Lordog/R-Judge"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/rjudge"))
        update_manifest("rjudge", {**r, "url": URL, "license_note": "no LICENSE; needs_confirmation"})
    except Exception as e:
        append_fetch_error("rjudge", e); raise
if __name__ == "__main__": main()
