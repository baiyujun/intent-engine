import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/uiuc-kang-lab/InjecAgent"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/injecagent"))
        update_manifest("injecagent", {**r, "url": URL, "license_note": "MIT, file named LICENCE"})
    except Exception as e:
        append_fetch_error("injecagent", e); raise
if __name__ == "__main__": main()
