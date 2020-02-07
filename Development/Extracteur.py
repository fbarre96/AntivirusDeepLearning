import sys
import json
from Caracteristiques.executables.exe_extracteur import * 

def main():
    """
    Extrait les variables pour l'entrainement d'un modèle SDO depuis une liste de fichier PE donnée au format JSON.
    Ressort le résultat dans un autre fichier json.
    """
    if len(sys.argv) != 3:
        print("Usage: python3 Extracteur.py <ExeList.json> <outname.json>")
        sys.exit(0)
    if not sys.argv[1].endswith(".json"):
        print("La liste de fichiers doit etre sous format json")
        sys.exit(0)
    if not sys.argv[2].endswith(".json"):
        out_path = sys.argv[2]+".json"
    else:
        out_path = sys.argv[2]
    list_path = sys.argv[1]
    extract_list(list_path,out_path)

def extract_one(path_in):
    """
    Extrait les caractéristiques d'un fichier et les renvoie
    """
    dict_vars = extractAllExeVariables(path_in) 
    ext_data = None
    if dict_vars == None:
        print("could not load "+path_in)
    else:
        ext_data = list(dict_vars.values())
    return ext_data

def extract_list(path_in, path_out):
    """
    Extrait les caractéristiques d'une liste de et les renvoie.
    path_in est un chemin vers une liste d'exe au format json
    """
    with open(path_in,"r") as f:
        json_formatted_list = f.read()
        exe_list = json.loads(json_formatted_list)
    print("Extraction des caracteristiques")
    values = dict()
    compteur = 0
    for i,path in enumerate(exe_list):
        print("Extraction de "+str(i+1)+"/"+str(len(exe_list)))
        vals = extract_one(path)
        if vals is not None:
            compteur+=1
            values[path] = vals
    with open(path_out,"w") as f:
        f.write(json.dumps(values))
    return compteur

def extract_list_from_list(exe_list, path_out):
    """
    Extrait les caractéristiques d'une liste de et les renvoie
    exe_list est une liste python des chemisn de fichiers dont on veut extraire les variables
    """
    print("Extraction des caracteristiques")
    values = dict()
    compteur = 0
    for i,path in enumerate(exe_list):
        print("Extraction de "+str(i+1)+"/"+str(len(exe_list)))
        vals = extract_one(path)
        if vals is not None:
            compteur+=1
            values[path] = vals
    with open(path_out,"w") as f:
        f.write(json.dumps(values))
    return compteur
        
if __name__ == '__main__':
    main()