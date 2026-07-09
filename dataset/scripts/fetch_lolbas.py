import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/LOLBAS-Project/LOLBAS"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/lolbas"))
        update_manifest("lolbas", {**r, "url": URL, "license_note": "GPL-3.0; command patterns only"})
    except Exception as e:
        append_fetch_error("lolbas", e); raise
if __name__ == "__main__": main()
