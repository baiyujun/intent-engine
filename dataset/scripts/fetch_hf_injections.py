"""Fetch 3 HF prompt-injection datasets into raw/hf_injections/."""
import pathlib
from src.fetch_utils import update_manifest, append_fetch_error

SOURCES = [
    ("hf_deepset", "deepset/prompt-injections", "Apache-2.0"),
    ("hf_jayavibhav", "jayavibhav/prompt-injection", "none"),
    ("hf_imoxto", "imoxto/prompt_injection_cleaned_dataset-v2", "none"),
]

def main():
    try:
        from datasets import load_dataset
        out = pathlib.Path("raw/hf_injections"); out.mkdir(parents=True, exist_ok=True)
        for key, repo, lic in SOURCES:
            try:
                ds = load_dataset(repo)
                ds.save_to_disk(str(out / key))
                update_manifest(key, {"source_ref": repo, "license": lic, "action": "hf_load"})
            except Exception as e:
                append_fetch_error(key, e)
    except Exception as e:
        append_fetch_error("hf_injections", e)
if __name__ == "__main__": main()
