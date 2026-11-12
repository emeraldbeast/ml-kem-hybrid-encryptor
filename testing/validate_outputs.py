import csv, json
from pathlib import Path
root=Path(__file__).resolve().parent
out=root/"results"
status=(out/"status.txt").read_text()
required=["dependency-check","configure","build","python-tests","paper-demo","native-demo","secure-demo","kem-benchmark","ntt-benchmark","dashboard-health"]
missing=[n for n in required if f"EXIT {n}=0" not in status]
assert not missing, f"failed/missing stages: {missing}"
demo=json.loads((out/"paper-demo.log").read_text())
assert demo["ok"] and all(demo["checks"].values()), "paper demo checks failed"
assert "matching 32-byte secrets" in (out/"native-demo.log").read_text()
assert "message authenticated and recovered" in (out/"secure-demo.log").read_text()
health=json.loads((out/"dashboard-health.json").read_text())
assert health.get("ok") is True, health
with (out/"kem-batch.csv").open(newline="") as f: kem=list(csv.DictReader(f))
assert len(kem)>=2 and all(float(x["seconds"])>0 for x in kem)
with (out/"ntt.csv").open(newline="") as f: ntt=list(csv.DictReader(f))
assert len(ntt)>=5 and all(float(x["seconds"])>0 for x in ntt)
print(f"Validated {len(required)} run stages, paper-demo agreement, both native demos, dashboard health, {len(kem)} KEM rows, and {len(ntt)} NTT rows.")