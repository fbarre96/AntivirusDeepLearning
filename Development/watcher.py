 # -*- coding: utf-8 -*
import logging
import sys
import time
import os
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import PatternMatchingEventHandler
import SDO
import Extracteur
import Trainer

class MonHandler(PatternMatchingEventHandler):
    """
    Classe définisant les fonctions à appeler pour les observeurs watchdog
    """
    def execute_scan(self, file_to_extract):
        caracs = Extracteur.extract_one(file_to_extract)
        if caracs is None:
            return
        caracs = Trainer.selecter(caracs,[1,1,1,1,1,1,1,0,1])
        probas = SDO.classify_proba("Models\SDO_model.joblib", [caracs], [file_to_extract])
        proba_sain = probas[0][0]
        if proba_sain > 0.5:
            print("Sain:"+ " Le fichier "+str(os.path.basename(file_to_extract))+ " est sain ("+str(round(proba_sain,3)*100)+" % de confiance)")
        else:
            print("Malware" + " /!\ Le fichier "+str(os.path.basename(file_to_extract))+ " est un malware ("+str(round(1-proba_sain,3)*100)+" % de confiance)")
    
    def on_modified(self, event):
        #Lancer python avec le script fabien + event.src_path
        self.execute_scan(event.src_path)
    def on_created(self, event):
        self.execute_scan(event.src_path)
    def on_moved(self, event):
        self.execute_scan(event.dest_path)
    def on_deleted(self, event):
        pass

def getObservers(paths, event_handler):
    """
    Prépare les observeurs de watchdog (récursif sur la liste des chemins données en premier paramètre)
    Les observeurs appelleront les fonctions dans le event_handler donné
    """
    # Create Observer to watch directories
    observer = Observer()
    # take in list of paths.
    
    # Empty list of observers.
    observers = []

    # iterate through paths and attach observers
    for line in paths:
        # convert line into string and strip newline character
        targetPath = str(line).rstrip()
        # Schedules watching of a given path
        if targetPath[0]=="%":
            #targetPath=targetPath[1:len(targetPath)-1]
            #Isolate the environment variable
            targetPath=targetPath.replace("%","")
            #Trying to find something like "APPDATA\Something"
            if targetPath.find("\\") != -1:
                #Isolation of the environment variable
                targetPath=targetPath[0:len(targetPath)]
                pourcent=targetPath.find("\\")
                var_debut=targetPath[0:pourcent]
                #Get the rest of the path back
                var_suite=targetPath[pourcent:len(targetPath)]
                #Get the full path of the environment variable
                var_env=os.getenv(var_debut)
                #slash="\\"
                #Adding \ if we have something after the environment variable
                #var_env=str(var_env)+slash
                #Concatenation of the result of our environment variable and the rest of the path
                var_path=str(var_env+var_suite)
                #Get the real path and not something like "User\Local\..\Downloads"
                real_path=os.path.realpath(var_path)
                #Running our observer
                print(real_path)
                observer.schedule(event_handler,real_path, recursive=True)
            else:
                env=os.getenv(targetPath)
                observer.schedule(event_handler,env, recursive=True)
        else:
            observer.schedule(event_handler, targetPath, recursive=True)
        # Add observable to list of observers
        observers.append(observer)

    # start observer
    observer.start()
    return observers
    
def clean(observers):
    """
    Libère les observeur de watchdog
    """
    for o in observers:
        o.unschedule_all()
        # stop observer if interrupted
        o.stop()
    for o in observers:
        # Wait until the thread terminates before exit
        o.join()
        
if __name__ == '__main__':
    abs_path = os.path.dirname(os.path.abspath(__file__))
    paths = open(sys.argv[2], 'r') if len(sys.argv) > 2 else '.'
    # Attach a event handler
    event_handler = MonHandler(patterns=["*.exe","*.dll"],ignore_directories=False)
    observers = getObservers(paths, event_handler)
    try:
        while True:
            # poll every second
            time.sleep(1)
    except KeyboardInterrupt:
        clean(observers)
    