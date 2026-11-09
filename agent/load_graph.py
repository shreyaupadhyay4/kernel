import json, sys
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("", ""))

with driver.session() as s:
    s.run("MATCH (n) DETACH DELETE n")  # start clean
    count = 0
    for line in open(sys.argv[1]):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Values go in as parameters, never pasted into the query text,
        # because filenames come from whoever ran the program.
        s.run(
            """
            MERGE (parent:Process {pid: $ppid})
            MERGE (child:Process {pid: $pid})
            SET child.comm = $comm, child.file = $file, child.ts = $ts
            MERGE (parent)-[:SPAWNED]->(child)
            """,
            ppid=e["ppid"], pid=e["pid"], comm=e["comm"], file=e["file"], ts=e["ts"],
        )
        count += 1
    print(f"Loaded {count} events")
driver.close()
