# SDO_Antivirus_DeepLearning

# Compilation du py
Antivirus Deep Learning Project

Génération de l'exe avec auto-py-to-exe

choisir SDO_GUI comme fichier
Ajouter fichiers Developpement\*.py, SDO_GUI\admin.py, path.txt
Ajouter Dossiers : Caracteristiques, Tools, Models, images

Ouvrir les options avancées et copiez dans le champ hidden-imports:
pefile,sklearn,sklearn.ensemble,sklearn.neighbors,sklearn.neighbors.typedefs,sklearn.neighbors.quad_tree,sklearn.tree._utils

Ou utiliser la commande

pyinstaller -y --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/GUI_Project/admin.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/CaracStats.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/Extracteur.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/path.txt";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/SDO.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/Trainer.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/watcher.py";"." --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/Models";"Models/" --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/Tools";"Tools/" --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/Caracteristiques";"Caracteristiques/" --add-data "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/GUI_Project/images";"images/" --hidden-import pefile --hidden-import sklearn --hidden-import sklearn.ensemble --hidden-import sklearn.neighbors --hidden-import sklearn.neighbors.typedefs --hidden-import sklearn.neighbors.quad_tree --hidden-import sklearn.tree._utils "D:/Dev/Python/Majeur/SDO_Antivirus_DeepLearning/Development/GUI_Project/SDO_Gui.py"