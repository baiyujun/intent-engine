"""Fetch OWASP Agentic AI + LLM Top 10 reference pages into raw/owasp/."""
import pathlib
from src.fetch_utils import download_file, update_manifest, append_fetch_error

URLS = {
    "agentic": "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
    "llm2025": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
}

def main():
    dest_dir = pathlib.Path("raw/owasp")
    try:
        for k, u in URLS.items():
            download_file(u, dest_dir / f"{k}.html")
        update_manifest("owasp", {"source_ref": "live", "files": list(URLS)})
    except Exception as e:
        append_fetch_error("owasp", e)

if __name__ == "__main__":
    main()
