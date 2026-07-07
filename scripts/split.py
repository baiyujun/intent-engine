"""Split unified_dedup -> train/val/test_indist + test_holdout_family. ok-license only.
Stratified by risk_category; holdout families fully excluded from train/val; leakage check."""
import json, pathlib, random
import numpy as np
import yaml
from src.schema import canonical_text
from src.normalize_utils import iter_jsonl, write_jsonl, processed_dir, reports_dir
from src.licenses import load_license_config

def _embed_many(hold_texts, train_texts):
    """Embed holdout and train texts in a shared space (TF-IDF fallback needs one vocabulary)."""
    try:
        from sentence_transformers import SentenceTransformer
        m = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
        H = np.asarray(m.encode(hold_texts, normalize_embeddings=True))
        T = np.asarray(m.encode(train_texts, normalize_embeddings=True))
        return H, T
    except Exception:
        from sklearn.feature_extraction.text import TfidfVectorizer
        all_texts = list(hold_texts) + list(train_texts)
        v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), min_df=1)
        X = v.fit_transform(all_texts).toarray().astype(np.float32)
        n = np.linalg.norm(X,axis=1,keepdims=True); n[n==0]=1
        X = X/n
        return X[:len(hold_texts)], X[len(hold_texts):]

def main():
    cfg = load_license_config()
    hold = set(cfg.get("holdout_families", []))
    ratio = cfg.get("split_ratio", {"train":0.8,"val":0.1,"test_indist":0.1})
    leak = float(cfg.get("leakage_threshold", 0.85))
    recs = [r for r in iter_jsonl(processed_dir()/"unified_dedup.jsonl") if r.get("license_status")=="ok"]
    hold_recs = [r for r in recs if r["label"]["attack_family"] in hold]
    in_recs = [r for r in recs if r["label"]["attack_family"] not in hold]
    # stratified by risk_category
    by_cat = {}
    for r in in_recs: by_cat.setdefault(r["label"]["risk_category"], []).append(r)
    train, val, testi = [], [], []
    rng = random.Random(1337)
    for cat, lst in by_cat.items():
        lst = sorted(lst, key=lambda r: r["id"]); rng.shuffle(lst)
        n = len(lst); ntr = int(n*ratio["train"]); nv = int(n*ratio["val"])
        train += lst[:ntr]; val += lst[ntr:ntr+nv]; testi += lst[ntr+nv:]
    # leakage check: holdout vs train
    moved = 0
    if hold_recs and train:
        H, T = _embed_many([canonical_text(r) for r in hold_recs], [canonical_text(r) for r in train])
        S = H @ T.T
        # for each holdout, ensure max sim to train < leak
        # (here we only drop train samples that exceed leak with any holdout)
        offenders = set()
        for i in range(len(hold_recs)):
            for j in np.where(S[i] >= leak)[0]:
                offenders.add(j)
        if offenders:
            new_train = [r for k,r in enumerate(train) if k not in offenders]
            moved = len(train)-len(new_train); train = new_train
    for name, lst in (("train",train),("val",val),("test_indist",testi),("test_holdout_family",hold_recs)):
        lst.sort(key=lambda r: r["id"])
        write_jsonl(processed_dir()/f"{name}.jsonl", lst)
    rep = reports_dir(); rep.mkdir(parents=True, exist_ok=True)
    def dist(lst):
        d={}; [d.__setitem__(r["label"]["risk_category"], d.get(r["label"]["risk_category"],0)+1) for r in lst]; return d
    (rep/"split_report.json").write_text(json.dumps({
        "holdout_families": [f for f in cfg.get("holdout_families", []) if f in hold], "ratio": ratio, "leakage_threshold": leak,
        "sizes": {"train":len(train),"val":len(val),"test_indist":len(testi),"test_holdout_family":len(hold_recs)},
        "leakage_offenders_moved": moved,
        "distributions": {"train":dist(train),"val":dist(val),"test_indist":dist(testi),"holdout":dist(hold_recs)}
    }, indent=2))
if __name__ == "__main__": main()
