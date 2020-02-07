import os, glob
import json
import pefile
import sys

def isAnExe(filepath):
    """
    Renvoie vrai si le fichier donné est un PE
    """
    try:
        pefile.PE(filepath, fast_load=True)
    except Exception as e:
        return False
    return True

def recursListPath(path, nth = 1):
    """
    Renvoie tous les fichiers PE présents dans le dossier donné (récursif)
    """
    liste = []
    for i in range (1, nth+1):
        currentpath = path + (i * "/*")
        try:
            for name in glob.glob(currentpath):
                if isAnExe(name):
                    liste.append(str(name))
                    print("Found : "+str(len(liste)))
        except:
            pass
    return liste

def main():
    """
    Créer la liste de tous les fichiers PE présents dans le dossier donné (récursif)
    """
    if len(sys.argv) != 3:
        print("Usage : python3 Find_all_PE.py <starting_directory> <outlist_name>")
        sys.exit(0)
    DirPath = sys.argv[1]
    sortie = sys.argv[2] + ".json"
    liste = recursListPath(DirPath, 10)

    with open(sortie,"w", encoding = "ISO-8859-1") as f:
        f.write(json.dumps(liste))


if __name__ == '__main__':
    main()