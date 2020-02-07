from Trainer import training,error_ratio
import sys
import json

def main():
    """
    Test toutes les combinaisons de caractéristiques possibles et donne le top des meilleurs
    Permet également de voir quelle score obtient chacun des caractéristiques individuellement
    """
    if len(sys.argv) != 4:
        print("Usage: python3 CaracStats.py <clean_caracs.json> <malware_caracs.json> [-stats|-brute]")
        sys.exit(0)
    with open(sys.argv[1], "r") as f:
        cleans = json.loads(f.read())
    with open(sys.argv[2], "r") as f:
        malwares = json.loads(f.read())
    stat_test = sys.argv[3]
    nb_stats = len(list(cleans.values())[0])
    clean_training_ratio = 0.5
    nb_samples_clean_training = int((1-clean_training_ratio) * len(cleans))
    malware_training_ratio = 0.5
    nb_samples_malware_training = int((1-malware_training_ratio) * len(malwares))
    if stat_test != "-brute":
        stats_results = []
        tab_selection = [0]*nb_stats
        for i in range(nb_stats):
            tab_selection[i] = 1
            results = training(cleans,malwares,clean_training_ratio,malware_training_ratio, tab_selection)
            stats_results.append([tab_selection.copy(),results])
            tab_selection[i] = 0
        for ligne in stats_results:
            selecter_used = ligne[0]
            results = ligne[1]
            taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
            taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
            
            print(str(selecter_used)+":"+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")
            
    else:
        stats_results = getTrainingsResults(cleans,malwares,nb_stats, clean_training_ratio, malware_training_ratio)
        print("Top lowest error :"+str(getTopLowestError(stats_results,3)))
        print("Top lowest faux-négatif :"+str(getTopLowestFalseNeg(stats_results,3)))

def getTrainingsResults(cleans,malwares,nb_stats, clean_training_ratio, malware_training_ratio):
    """
    Renvoie les résultats d'entraînement sur la liste de caractéristiques donnée
    avec les données dans un dictionnaire
    Clean_correct
    Clean_incorrect
    Malware_correct
    Malware_incorrect
    """
    stats_results = []
    tab_selection = [0]*nb_stats
    total_essais = 2 ** nb_stats
    for essai_en_cours in range(1,total_essais):
        print("Essaie : "+str(essai_en_cours)+"/"+str(total_essais - 1))
        select = bin(essai_en_cours)[2:]
        prefix = "0"*nb_stats
        prefixed_select = (prefix + select)[(0-1)*nb_stats:]
        tab_selection=list(map(lambda x:int(x),list(prefixed_select)))
        print(tab_selection)
        results = training(cleans,malwares,clean_training_ratio,malware_training_ratio, tab_selection, "temp.joblib")
        stats_results.append([tab_selection.copy(),results])
        
    return stats_results
    
    

        
def takeSecond(elem):
    """
    Retourne le 2 élément de la liste (utilisé pour le tri)
    """
    return elem[1]
def takeSecondAndThird(elem):
    """
    Retourne le couple (2,3) élément de la liste (utilisé pour le tri)
    """
    return (elem[1],elem[2])
def getTopLowestError(stats_results, topCombien):
    """
    Retourne le top X des résultats d'entrainement du taux d'erreur le plus faible
    le top est une liste triée. chaque élément du top comporte
    [La liste de caractéristiques, le taux d'erreur, le dictionnaire des résultats]
    """
    top = []
    for zipp in stats_results:
        selecter = zipp[0]
        results = zipp[1]
        taux_erreur = error_ratio(results)
        top.append([selecter,taux_erreur,results])
    top3 = sorted(top, key=takeSecond)[:topCombien]
    return top3

def getTopLowestFalseNeg(stats_results, topCombien):
    """
    Retourne le top X des résultats d'entrainement du taux de faux négatifs le plus faible
    le top est une liste triée. chaque élément du top comporte
    [La liste de caractéristiques, le taux de faux négatifs, le dictionnaire des résultats]
    """
    top = []
    for zipp in stats_results:
        selecter = zipp[0]
        results = zipp[1]
        taux_erreur = results["Malware_incorrect"]
        top.append([selecter,taux_erreur,results["Clean_incorrect"],results])
    top3 = sorted(top, key=takeSecondAndThird)[:topCombien]
    return top3

if __name__ == '__main__':
    main()