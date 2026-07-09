import pathlib
from src.fetch_utils import clone_or_pull, update_manifest, append_fetch_error

URL = "https://github.com/ethz-spylab/agentdojo"
def main():
    try:
        r = clone_or_pull(URL, pathlib.Path("raw/agentdojo"))
        update_manifest("agentdojo", {**r, "url": URL})
        return r
    except Exception as e:
        append_fetch_error("agentdojo", e); raise
if __name__ == "__main__": main()
