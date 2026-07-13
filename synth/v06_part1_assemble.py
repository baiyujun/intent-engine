"""v0.6 Part 1 split_exfil assembly + cross-turn resource QA.

ASSEMBLY: format concatenation of N independent LLM generate calls; no hand-written content.
QA (post-generation, regex/simple-match level — NOT LLM): detect whether turn-k names a concrete
resource noun that turn-(k-1) did NOT mention. Flag for human review — do NOT auto-drop/keep.
"""
import json, re, yaml

def clean_text(ui):
    t = ui.strip()
    META = re.compile(r"^(thinking:|we need to (output|generate)|now (output|ensure|format|write)|"
                      r"i'?ll (craft|write|remove|output)|make sure each line|these all are benign|prompt: prompt)", re.I)
    t = re.sub(r"\s*\(~?\s*\d+\s*chars?\s*\)\.?\s*$", "", t)
    t = re.sub(r"\s*\(longer,.*$", "", t)
    t = re.sub(r'^Prompt:\s*', '', t).strip()
    if META.match(t) or len(t) < 40:
        return None
    return t

def load_turns(path):
    d = yaml.safe_load(open(path))
    out = []
    for i, tc in enumerate(d["tests"]):
        c = clean_text(tc.get("vars", {}).get("user_input", ""))
        if c: out.append(c)
    return out

# concrete resource nouns — if turn2 names one that turn1 did NOT mention, flag (the anti-hallucination
# rule told turn2 to use generic deictics; a concrete noun here = hallucinated/leaked resource)
RESOURCE_RE = re.compile(
    r"\.env\b|~/?\.ssh/id_rsa|id_rsa|/etc/shadow|kubeconfig|\.kube/config|api\s+tokens?|"
    r"private\s+key|master\s+key|signing\s+key|aws\s+credentials|database\s+credentials|"
    r"secret\s+key|\.pem\b", re.I)

t1 = load_turns("synth/v06_split_turn1_out.yaml")
t2 = load_turns("synth/v06_split_turn2_out.yaml")
print("clean turn1:", len(t1), "| clean turn2:", len(t2))

convos = []
qa_flags = []
n = min(len(t1), len(t2))
for i in range(n):
    turn1, turn2 = t1[i], t2[i]
    t1_resources = set(m.group(0).lower() for m in RESOURCE_RE.finditer(turn1))
    t2_resources = set(m.group(0).lower() for m in RESOURCE_RE.finditer(turn2))
    new_in_t2 = t2_resources - t1_resources   # resources named in t2 NOT in t1
    flag = None
    if new_in_t2:
        flag = f"turn2 names resource(s) NOT in turn1: {sorted(new_in_t2)} — hallucinated cross-turn resource (human review)"
        qa_flags.append((f"split_exfil_{i:03d}", flag))
    convos.append({
        "id": f"split_exfil_{i:03d}",
        "attack_family": "split_exfil", "n_turns": 2,
        "is_malicious": True, "ground_truth_consistent": False, "ground_truth_verdict": "malicious",
        "annotation": "2-turn split-exfil: turn1=read secret under pretext; turn2=send to external. Content per-turn from LLM; turn2 purpose had anti-hallucination rule (generic deictic, no concrete resource).",
        "turns": [turn1, turn2],
        "qa_cross_turn_resource_flag": flag,
    })

out = {"attack_family": "split_exfil", "n_turns": 2, "n_conversations": len(convos),
       "assembly": "format concatenation of N independent LLM generate calls; no hand-written content",
       "qa": "post-gen regex: flag turn-k naming a resource noun not in turn-(k-1); flagged = human review, not auto-drop/keep",
       "conversations": convos}
json.dump(out, open("synth/partc_split_exfil_smoke.json", "w"), ensure_ascii=False, indent=2)
print(f"\nassembled {len(convos)} conversations; QA flags: {len(qa_flags)}")
for cid, f in qa_flags:
    print(f"  FLAG {cid}: {f}")

print("\n" + "="*70)
print("FULL TURNS[] for ALL conversations (raw, for review):")
print("="*70)
for c in convos:
    print(f"\n--- {c['id']} | QA flag: {c['qa_cross_turn_resource_flag'] or 'none'} ---")
    print(f"  TURN 1: {c['turns'][0]}")
    print(f"  TURN 2: {c['turns'][1]}")
