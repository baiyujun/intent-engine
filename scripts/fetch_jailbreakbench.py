import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URLS = {"repo": "https://github.com/JailbreakBench/jailbreakbench",
        "artifacts": "https://github.com/JailbreakBench/artifacts"}
def main():
    for k, u in URLS.items():
        try:
            r = clone_or_pull(u, pathlib.Path(f"raw/jailbreakbench/{k}"))
            update_manifest(f"jailbreakbench_{k}", {**r, "url": u, "license_note": "MIT"})
        except Exception as e:
            append_fetch_error(f"jailbreakbench_{k}", e)
if __name__ == "__main__": main()
