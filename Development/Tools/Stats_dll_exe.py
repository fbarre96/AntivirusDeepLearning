
import json
import pefile
from collections import OrderedDict
import sys
"""
Script extrayant les statistiques d'utilisations des dll et des imports
de tous les fichiers donnés dans la liste au format json donné en entrée.
"""
if len(sys.argv) != 2:
    print("Usage : python3 Stats_dll_exe.py <list_of_path.json>")
    sys.exit(0)
paths=[]

with open(sys.argv[1],"r") as f:
    paths = json.loads(f.read())
if len(paths)==0:
    exit(0)
if 1 == 1:
    dll_stats = dict()
    imports_stats = dict()
    final_size = len(paths)
    current_size = 0
    for path in paths:
        #Ãpath = "../../../Virus/"+path
        current_size+=1
        print("Processing "+str(current_size)+"/"+str(final_size)+" ("+str(path)+")")
        pe = None
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
        except Exception as e:
            pe = None
            print(str(e))
        if pe is not None:
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_stats[str(entry.dll).lower()] +=1
                    except:
                        dll_stats[str(entry.dll).lower()] = 1
                    for imp in entry.imports:
                        try:
                            imports_stats[str(imp.name).lower()] +=1
                        except:
                            imports_stats[str(imp.name).lower()] = 1
            except AttributeError:
                pass
    with open("dll_stats.txt","w") as f:
        dd = OrderedDict(sorted(dll_stats.items(), reverse=True,key=lambda x: x[1]))
        f.write(json.dumps(dd))
    with open("import_stats.txt","w") as f:
        total = len(imports_stats)
        for k,v in imports_stats.items():
            imports_stats[k] = float(v)/float(total)
        f.write(json.dumps(imports_stats))
