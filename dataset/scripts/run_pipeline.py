"""Orchestrator: fetch->normalize per source -> near-dup -> merge -> dedup -> split -> synth -> report."""
import argparse, importlib, json, pathlib, sys, traceback
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.fetch_utils import append_fetch_error
REPORTS = ROOT / "reports"

SOURCES = [
    ("agentdojo","fetch_agentdojo","normalize_agentdojo"),
    ("injecagent","fetch_injecagent","normalize_injecagent"),
    ("bipia","fetch_bipia","normalize_bipia"),
    ("rjudge","fetch_rjudge","normalize_rjudge"),
    ("purplellama","fetch_purplellama","normalize_purplellama"),
    ("hf_injections","fetch_hf_injections","normalize_hf_injections"),
    ("jailbreakbench","fetch_jailbreakbench","normalize_jailbreakbench"),
    ("advbench","fetch_advbench","normalize_advbench"),
    ("gtfobins","fetch_gtfobins","normalize_gtfobins"),
    ("lolbas","fetch_lolbas","normalize_lolbas"),
    ("mitre_attack","fetch_mitre_attack","normalize_mitre_attack"),
    ("clawsentry_rules","fetch_clawsentry_rules","normalize_clawsentry_rules"),
    ("llamafirewall_rules","fetch_llamafirewall_rules","normalize_llamafirewall_rules"),
    ("owasp","fetch_owasp",None),
]

def _run(modname, fn="main"):
    m = importlib.import_module(f"scripts.{modname}")
    getattr(m, fn)()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", help="comma-separated source keys (fetch+normalize only)")
    ap.add_argument("--all", action="store_true", help="run full pipeline")
    args = ap.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    selected = set(args.sources.split(",")) if args.sources else set()
    plan = SOURCES if (args.all or not selected) else [s for s in SOURCES if s[0] in selected]
    log = {}
    # per-source fetch+normalize
    for key, fetch, norm in plan:
        step = {}
        for label, mod in (("fetch",fetch),("normalize",norm)):
            if mod is None: continue
            try: _run(mod); step[label] = "ok"
            except Exception as e:
                append_fetch_error(key, e); step[label] = f"fail:{type(e).__name__}"; traceback.print_exc()
        log[key] = step
    # cross-cutting
    for label, mod in [("near_dup_pairs","build_near_dup_pairs"),("merge","merge_unified"),
                       ("dedup","dedup"),("split","split"),("synth","synth_generate"),
                       ("report","build_report")]:
        try: _run(mod); log[label] = "ok"
        except Exception as e:
            append_fetch_error(label, e); log[label] = f"fail:{type(e).__name__}"; traceback.print_exc()
    (REPORTS/"pipeline_run.json").write_text(json.dumps(log, indent=2))
    print(json.dumps(log, indent=2))
if __name__ == "__main__": main()
