import json, sys
from collections import defaultdict

events = []
for line in open(sys.argv[1]):
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError:
        pass  # skip broken lines (attacker-controlled names can break JSON)

children = defaultdict(list)
pids = {e["pid"] for e in events}
for e in events:
    children[e["ppid"]].append(e)

# roots = parents we never saw as a started program
roots = sorted({e["ppid"] for e in events if e["ppid"] not in pids})

def show(pid, depth=0):
    for e in children[pid]:
        print("  " * depth + f"{e['comm']} ({e['pid']}) -> {e['file']}")
        show(e["pid"], depth + 1)

for r in roots:
    print(f"[parent {r}]")
    show(r, 1)
