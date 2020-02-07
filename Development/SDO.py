import sys
import numpy as np
from sklearn.externals import joblib
from Caracteristiques.executables.exe_extracteur import *
import Trainer as Trainer

def selecter(values,select_stat):
    """
    Garde uniquement les indices dans la liste values ou la valeur pour le meme indice dans select_stat est 1
    exemple:
    [10,20,30,40] , [1,0,1,0]
    renvoie
    [10,30]
    """
    ret = []
    for i,val in enumerate(values):
        if select_stat[i] == 1:
            ret.append(val)
    return ret

def selecter_on_list(values,select_stat):
    """
    Garde uniquement les indices dans la liste de liste values ou la valeur pour le meme indice dans select_stat est 1
    exemple:
    [[10,20,30,40],[50,60,70,80]] , [1,0,1,0]
    renvoie
    [[10,30],[50,70]]
    """
    ret = []
    for selecter_l in values:
        sub_ret = []
        for i,val in enumerate(selecter_l):
            if select_stat[i] == 1:
                sub_ret.append(val)
        ret.append(sub_ret)
    return ret

def main():
    """
    utilise le modèle donnée pour déterminer si les caractérisques d'un fichiers sont celles d'un malware.
    si l'option -e est donné, SDO attend un fichier PE ou une liste json de chemin de fichier PE.
    si l'option -c est donné à la place, SDO attend une liste de caractéristiques pré-extraites d'une liste de PE.
    """
    if len(sys.argv) != 3:
        print("Usage: python3 SDO.py <model_path.json> [-e <PathToExe.exe>|<ListOfExe> | -c <ListOfCaracs>]")
        sys.exit(0)
    values = dict()
    values_only = []
    names_only = []
    # récupère le modèle d'entrainement et les valeurs de selection de caractéristiques
    classifier, selection = Trainer.loadModel(sys.argv[1])
    # Si on a affaire à une liste de caractéristiques, on peut directement obtenir la liste des valeurs et noms de ficheirs associés
    if sys.argv[2] == "-c":
        with open(sys.argv[3], "r") as f:
            values = json.loads(f.read())
        
        for key,val in values.items():
            values_only.append(val)
            names_only.append(key)
    # Si on a affaire à un PE ou une liste de PE, on doit extraire la liste des valeurs et noms de ficheirs associés
    _isAnExe = False
    if sys.argv[2] == "-e":
        _isAnExe = isAnExe(sys.argv[3]) # test si le fichier donné est un PE. Sinon ce doit être une lsite de chemin PE au format JSON
        path_list = []
        if _isAnExe:
            path_list.append(sys.argv[3])
        else:
            with open(sys.argv[3], "r", encoding = "ISO-8859-1") as f:
                path_list = json.loads(f.read())
        # Extrait les variables des fichiers à analyser
        for i,path in enumerate(path_list):
            #print("Recuperation donnees "+str(i+1)+"/"+str(len(path_list)))
            dict_vars = extractAllExeVariables(path)
            if dict_vars == None:
                print("Le fichier donne n'a pas pu etre analyse.")
            else:
                values[path] = selecter(list(dict_vars.values()),selection)
                values_only.append(selecter(list(dict_vars.values()),selection))
                names_only.append(path)
    # values_only et names_only on était correctement rempli selon les différents cas
    # on peut commencer la prediction pour chaque fichier grace au modèle pré-entrainé.
    clean_list,malware_list = classify(sys.argv[1],values_only,names_only)

    if _isAnExe: # Un seul PE était analysé
        if len(malware_list) > 0:
            print("!!!"+malware_list[0] + "!!! is supsicious. The file has been removed.")

    else: # Plusieurs fichiers étaient analysé, on propose de garder une liste des résultats.
        print(str(len(clean_list))+" clean, "+str(len(malware_list))+" malwares identified")
        if len(malware_list) > 0:
            print("Extract malware list y/n?")
            ans = input()
            if str(ans) == "y":
                print("Enter list name")
                ans = input()
                with open(ans+".txt", "w") as f:
                    f.write(str(malware_list))
        if len(clean_list) > 0:
            print("Extract clean list y/n?")
            ans = input()
            if str(ans) == "y":
                print("Enter list name")
                ans = input()
                with open(ans+".txt", "w") as f:
                    f.write(str(clean_list))

def classify(model_path,values_only, names_only):
    """
    Prend un chemin vers un modèle entraîné et les caractéristiques extraites des fichiers.
    Renvoie ensuite une liste de ficheir classé sains et une autre liste de fichiers classés malwares.
    """
    #load model
    classifier, selection = Trainer.loadModel(model_path)
    #Extract only values trained for
    values_only = selecter_on_list(values_only,selection)
    np_values = np.array(values_only)
    # Use predict instead of fit
    predicted = classifier.predict(np_values)

    malware_list = []
    clean_list = []
    for i,label in enumerate(predicted):
        if label == "clean":
            clean_list.append(names_only[i])
        else:
            malware_list.append(names_only[i])
    return predicted

def classify_proba(model_path, values_only, name_only):
    """
    Prend un chemin vers un modèle entraîné et les caractéristiques extraites des fichiers.
    Renvoie ensuite une liste de liste de avec la probabilité que ce soit un fichier sain et la probabilité que ce soit un fichier malveillant pour chaque fichier.
    exemple:
    [[0.20,0.80],[1,0],[0.50,0.50],[0.91,0.09]]
    """
    classifier, selection = Trainer.loadModel(model_path)
    values_only = selecter_on_list(values_only,selection)
    np_values = np.array(values_only)
   
    
    predicted = classifier.predict_proba(np_values)
    return predicted
    

if __name__ == '__main__':
    main()