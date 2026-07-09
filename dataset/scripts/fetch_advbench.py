import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error
URL = "https://github.com/llm-attacks/llm-attacks"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/advbench"))
        update_manifest("advbench", {**r, "url": URL, "license_note": "MIT (llm-attacks); avoid gated HF walledai/AdvBench"})
    except Exception as e:
        append_fetch_error("advbench", e); raise
if __name__ == "__main__": main()
