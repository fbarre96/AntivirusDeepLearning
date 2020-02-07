
import os
import sys
#from sklearn import datasets, svm, metrics
import numpy as np
from Caracteristiques.executables.exe_extracteur import * 
import json
from sklearn.externals import joblib

#TEST STAT
def selecter(values, select_stat):
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

def main():
    """
    Utilise un fichier de caractéristiques appartenant un des fichiers sains et un fichier de caractérstiques appartenant à des malwares.
    Créer un fichier contenant le modèle entraîné avec ces valeurs dans Models\\SDO_Model.joblib.json
    """
    if len(sys.argv) != 3:
        print("Usage: python3 Trainer.py <clean_caracs.json> <malware_caracs.json>")
        sys.exit(0)
    with open(sys.argv[1], "r") as f:
        cleans = json.loads(f.read())
    with open(sys.argv[2], "r") as f:
        malwares = json.loads(f.read())
    results = training(cleans,malwares,1,1, [1,1,1,1,1,1,1,0,1])
    print(str(results))
    print("Taux d'erreur : "+str(error_ratio(results)))

def error_ratio(results):
    """
    Renvoie le ratio d'erreur total à partir des résultats d'entrainements (faux-positifs + faux négatifs) / total
    """
    errors = results["Clean_incorrect"]+results["Malware_incorrect"]
    total = errors + results["Clean_correct"] + results["Malware_correct"]
    return float(errors)/float(total)

def saveModel(classifier,model_name,select_stat):
    """
    Sauvegarde le modèle entraîné avec le nom choisi.
    """
    print("Entrainement termine, sauvegarde...")
    abs_path = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(abs_path,'Models\\'+model_name)
    with open(model_path+".json","w") as f:
        f.write(json.dumps([select_stat,model_path]))
    joblib.dump(classifier, model_path)

def loadModel(model_name):
    """
    Charde le modèle entraîné.
    retourne le classifier et le tableau de selection des caractéristiques utilisés pour l'entraîner.
    """
    with open(model_name,"r") as f:
        datas = json.loads(f.read())
        classifier = joblib.load(datas[1])
        return classifier, datas[0]

def training(cleans, malwares, ratio_training_clean,ratio_training_malware, select_stat, nom_model="SDO_model",existing_model=None): 
    """
    Entraine un modèle avec les caractéristiques sains/malware données.
    Les ratios d'entrainements permettent de ne pas utiliser toutes les données pour l'entrainement afin d'en conserver pour tester le résultat de l'entrainement.
    
    """
    # PREPARATION DES VALEURS
    import random
    clean_keys =  list(cleans.keys())
    malware_keys = list(malwares.keys())
    #random.shuffle(clean_keys)
    #random.shuffle(malware_keys)
    values_training = []    
    targets_training = []
    values_test = []
    targets_test = []
    names = []
    i=0
    numberOfCleanForTrain = int(float(len(cleans))*float(ratio_training_clean))
    numberOfMalwareForTrain = int(float(len(malwares))*float(ratio_training_malware))
    for key in clean_keys:
        if i < numberOfCleanForTrain:
            values_training.append(np.array(selecter(cleans[key],select_stat)))
            targets_training.append("clean")
            names.append({key:cleans[key]})
        else:
            values_test.append(np.array(selecter(cleans[key],select_stat)))
            targets_test.append("clean")
        i+=1

    i=0
    for key in malware_keys:
        if i < numberOfMalwareForTrain:
            values_training.append(np.array(selecter(malwares[key],select_stat)))
            targets_training.append("malware")
            names.append({key:malwares[key]})
        else:
            values_test.append(np.array(selecter(malwares[key],select_stat)))
            targets_test.append("malware")
        i+=1
    
    n_samples = len(targets_training)
    print("Entrainement sur "+str(n_samples)+" samples")
    np_values = np.array(values_training)
    np_targets = np.array(targets_training)
    # Create a classifier: a support vector classifier
    #classifier = svm.SVC(gamma=0.0001)

    # Chargement d'un ancien modèle si donné
    from sklearn.ensemble import RandomForestClassifier
    classifier = None
    if existing_model != None:
        if existing_model != "":
            classifier = joblib.load(existing_model)
    if classifier is None:       
        classifier = RandomForestClassifier(n_estimators = 50, random_state = 1) 
    # Entrainement du modèle selon les paramètres 
    print("Debut de l'entrainement")
    
    classifier.fit(np_values, np_targets)
    # Sauvegarde du modèle avec le nom choisi
    saveModel(classifier,nom_model,select_stat)
    # Préparation du retour des résultats.
    retour = dict()
    if 1 > 0:
        np_values = np.array(values_test)
        predicted = classifier.predict(np_values)

        retour["Clean_correct"] = 0
        retour["Malware_correct"] = 0
        retour["Clean_incorrect"] = 0
        retour["Malware_incorrect"] = 0
        for i,label in enumerate(predicted):
            if label == "malware" and targets_test[i] == "malware":
                retour["Malware_correct"] +=1
            elif label == "clean" and targets_test[i] == "clean":
                retour["Clean_correct"] +=1
            elif label == "malware" and targets_test[i] == "clean":
                retour["Clean_incorrect"] += 1
            elif label == "clean" and targets_test[i] == "malware":
                retour["Malware_incorrect"] += 1
        return retour

if __name__ == '__main__':
    abs_path = os.path.dirname(os.path.abspath(__file__))
    main()