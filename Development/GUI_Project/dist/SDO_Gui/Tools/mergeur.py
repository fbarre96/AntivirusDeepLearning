import sys
import json

if len(sys.argv) != 4:
    print("Usage: Trainer <carac1.json> <carac2.json> <outname.json>")
    sys.exit(0)
if not sys.argv[1].endswith(".json"):
    print("La liste de fichiers doit etre sous format json")
    sys.exit(0)

with open(sys.argv[1],"r") as f:
    di1 = json.loads(f.read())
with open(sys.argv[2],"r") as f:
    di2 = json.loads(f.read())
logs =[]
for key,val in di1.items():
    try:
        valsOf2 = di2[key]
        di1[key] += valsOf2
    except:
        logs.append(key)
for log in logs:
    del di1[log]
with open(sys.argv[3],"w") as f:
    f.write(json.dumps(di1))
if len(logs) > 0:
    print("Some caracs could not be merged : see error_logs.txt")
with open("error_logs.txt","w") as f:
    f.write(json.dumps(logs))