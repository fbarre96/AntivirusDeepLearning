import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os
import sys
import json
sys.path.append("..")
import Extracteur as Extracteur
import Tools.Find_all_PE
import Trainer as Trainer
import SDO as SDO
from watchdog.observers import Observer
import time
from watchdog.events import PatternMatchingEventHandler
import CaracStats as CaracStats
from tkinter import ttk
import admin


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
def getObservers(paths, event_handler):
    """
    Prépare les observeurs de watchdog (récursif sur la liste des chemins données en premier paramètre)
    Les observeurs appelleront les fonctions dans le event_handler donné
    """
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
                # Create Observer to watch directories
                observer = Observer()
                observer.schedule(event_handler,real_path, recursive=True)
            else:
                env=os.getenv(targetPath)
                # Create Observer to watch directories
                observer = Observer()
                observer.schedule(event_handler,env, recursive=True)
        else:
            # Create Observer to watch directories
            observer = Observer()
            observer.schedule(event_handler, targetPath, recursive=True)
        # Add observable to list of observers
        observers.append(observer)

    # start observers
    for observer in observers:
        observer.start()
    return observers

def execute_detect_one_file(model_name, file_to_extract):
    """
    Renvoie la probabilité que le fichier donné soit un fichier sain selon le modèle entraîné donné
    """
    caracs = Extracteur.extract_one(file_to_extract)
    
    if caracs == None:
        return -1
    probas = SDO.classify_proba(model_name, [caracs], [file_to_extract])
    proba_sain = probas[0][0]
    return proba_sain

class VirusWindow(object):

    root = None
    alreadyOpen = False

    def __init__(self, path_prob_virus,proba_sain):
        
        
        tki = tk
        self.top = tki.Toplevel(VirusWindow.root)
        if VirusWindow.alreadyOpen == False:
            VirusWindow.alreadyOpen = True
        else:
            self.quit_window(True)
        
        abs_path = os.path.dirname(os.path.abspath(__file__))
        img_path = os.path.join(abs_path,"images\\computer-virus.gif")
        self.background_image = tk.PhotoImage(file=img_path)
        w = self.background_image.width()
        h = self.background_image.height()
        # size the window so the image will fill it
        self.top.geometry("%dx%d" % (w, h))
        self.panel1 = tk.Label(self.top, image=self.background_image)
        self.panel1.place(x=0,y=0,relheight=1,relwidth=1)
        #self.panel1.pack()
        frm = tki.Frame(self.panel1, borderwidth=4, relief='ridge')
        frm.pack(side=tk.BOTTOM, expand=True)
        msg = "/!\ Le fichier "+str(os.path.basename(path_prob_virus))+ " est un malware ("+str(round(1-proba_sain,3)*100)+" % de confiance). Voulez vous le supprimer?"
        label = tki.Label(frm, text=msg)
        label.pack(padx=4, pady=4)
        b_submit = tki.Button(frm, text='Oui')
        b_submit['command'] = lambda: self.delete_approved(path_prob_virus)
        b_submit.pack(side=tk.BOTTOM)

        b_cancel = tki.Button(frm, text='Cancel')
        b_cancel['command'] = lambda: self.quit_window(False)
        b_cancel.pack(padx=4, pady=4,side=tk.BOTTOM)

    def delete_approved(self, path_prob_virus):
        try:
            os.remove(path_prob_virus)
            
        except:
            pass
        self.quit_window(False)

    def quit_window(self,already_opened):
        VirusWindow.alreadyOpen = already_opened
        self.top.destroy()
        

class SDO_Handler(PatternMatchingEventHandler):
    """
    Classe définisant les fonctions à appeler pour les observeurs watchdog
    """
    def __init__(self,master, model,**kwargs):
        super().__init__(**kwargs)
        self.model = model
        self.master = master

    def apply_removal(self,path_to_remove,proba_sain):
        """
        Fonction appelé une fois la probabilité que le chemin donné soit calculée.
        Demandera confirmation pour la suppression du fichier s'il est potentiellement malveillant
        """
        if proba_sain == -1:
            return
        if 1-proba_sain >= 0.5:
            try:
                if VirusWindow.alreadyOpen == False:
                    reiconify = False
                    if self.master.state() == "iconic":
                        reiconify = True
                        self.master.deiconify()
                    #rep=messagebox.askquestion("Malware", " /!\ Le fichier "+str(os.path.basename(path_to_remove))+ " est un malware ("+str(round(1-proba_sain,3)*100)+" % de confiance). Voulez vous le supprimer?")
                    VirusWindow(path_to_remove,proba_sain)

                    if reiconify == True:
                        self.master.iconify()
            except Exception as e:
                pass

    def on_modified(self, event):
        """
        Fonction appelée par les observeurs de watchdog lorsqu'un fichier est modifié
        """
        print("Modifier "+event.src_path)
        proba_sain = execute_detect_one_file(self.model, event.src_path)
        self.apply_removal(event.src_path,proba_sain)
        
            
    def on_created(self, event):
        """
        Fonction appelée par les observeurs de watchdog lorsqu'un fichier est crée
        """
        print("Créer "+event.src_path)
        proba_sain = execute_detect_one_file(self.model, event.src_path)
        self.apply_removal(event.src_path,proba_sain)
    def on_moved(self, event):
        """
        Fonction appelée par les observeurs de watchdog lorsqu'un fichier est déplacé
        """
        print("Déplacer "+event.dest_path)
        proba_sain = execute_detect_one_file(self.model, event.dest_path)
        self.apply_removal(event.dest_path,proba_sain)
    def on_deleted(self, event):
        """
        Fonction appelée par les observeurs de watchdog lorsqu'un fichier est supprimé
        """
        pass


class SDO_GUI:
    """
    Classe définissant la fenêtre principale de l'interface graphique
    """
    def __init__(self, master, model_name):
        """
        Initialisation de tous composants graphique de la fenêtre principale
        Les Frames sont nombreuses et le code très similaire pour chaque section
        """
        self.master = master
        self.master.protocol("WM_DELETE_WINDOW", self.quit)
        self.wantToQuit = False
        self.watcher_started = False
        master.title("Projet SDO")

        self.notebook = ttk.Notebook(master)
        self.notebook_p1 = ttk.Frame(self.notebook)
        self.notebook_p2 = ttk.Frame(self.notebook)
        self.label = ttk.Label(master, text="Projet SDO")
        self.label.pack()
        separator = ttk.Separator(master)
        separator.pack(fill=tk.X, padx=5, pady=9)
        #Extraction
        panel_extraction = ttk.Frame(self.notebook_p1,relief=tk.SUNKEN)
        lbl_extraction = ttk.Label(panel_extraction, text="Extraire des caracteristiques :")
        lbl_extraction.pack(side=tk.LEFT)
        btn_import_one = ttk.Button(panel_extraction, text="D'un fichier", command=self.add_one_file)
        btn_import_list = ttk.Button(panel_extraction, text="D'une liste fichier Json ", command=self.add_json_list)
        btn_import_whole_dir = ttk.Button(panel_extraction, text="D'un dossier", command=self.add_whole_dir)
        btn_import_one.pack(side=tk.LEFT,padx=5,pady=9)
        btn_import_list.pack(side=tk.LEFT,padx=5,pady=9)
        btn_import_whole_dir.pack(side=tk.LEFT,padx=5,pady=9)
        panel_extraction.pack(fill=tk.X, padx=5, pady=9)

        separator = ttk.Separator(self.notebook_p1)
        separator.pack(fill=tk.X, padx=5, pady=9)
        #Entrainement
        panel_entrainement = ttk.Frame(self.notebook_p1,relief=tk.SUNKEN)
        lbl_entrainement = ttk.Label(panel_entrainement, text="Entrainement modèle :")
        lbl_entrainement.pack(side=tk.LEFT)
        panel_path_clean = ttk.Frame(panel_entrainement)
        lbl_path_clean = ttk.Label(panel_path_clean, text="Caractéristiques de fichiers sains:")
        lbl_path_clean.pack(side=tk.LEFT)
        self.ent_path_clean = tk.Entry(panel_path_clean)
        self.ent_path_clean.pack(side=tk.LEFT)
        btn_path_clean = ttk.Button(panel_path_clean, text="...", command=self.renseigneFichierClean)
        btn_path_clean.pack(side=tk.LEFT)
        panel_path_clean.pack(fill=tk.X, padx=5, pady=9)

        panel_path_malware= ttk.Frame(panel_entrainement)
        lbl_path_malware = ttk.Label(panel_path_malware, text="Caractéristiques   de    malwares:")
        lbl_path_malware.pack(side=tk.LEFT)
        self.ent_path_malware = tk.Entry(panel_path_malware)
        self.ent_path_malware.pack(side=tk.LEFT)
        btn_path_malware = ttk.Button(panel_path_malware, text="...", command=self.renseigneFichierMalware)
        btn_path_malware.pack(side=tk.LEFT)
        panel_path_malware.pack(fill=tk.X, padx=5, pady=9)

        panel_ratio_clean= ttk.Frame(panel_entrainement)
        lbl_ratio_clean = ttk.Label(panel_ratio_clean, text="Ratio   entrainement / test     sains :")
        lbl_ratio_clean.pack(side=tk.LEFT)
        self.ent_ratio_clean = tk.Entry(panel_ratio_clean, width=5)
        self.ent_ratio_clean.insert(tk.END, '0.8')
        self.ent_ratio_clean.pack(side=tk.LEFT)
        panel_ratio_clean.pack(fill=tk.X)

        panel_ratio_malware = ttk.Frame(panel_entrainement)
        lbl_ratio_malware = ttk.Label(panel_ratio_malware, text="Ratio entrainement / test malware :")
        lbl_ratio_malware.pack(side=tk.LEFT)
        self.ent_ratio_malware = tk.Entry(panel_ratio_malware, width=5)
        self.ent_ratio_malware.insert(tk.END, '0.8')
        self.ent_ratio_malware.pack(side=tk.LEFT)
        panel_ratio_malware.pack(fill=tk.X)
        panel_model = ttk.Frame(panel_entrainement)
        lbl_model = ttk.Label(panel_model, text="Nom du futur modèle:")
        lbl_model.pack(side=tk.LEFT)
        self.ent_model = tk.Entry(panel_model)
        self.ent_model.insert(tk.END, 'SDO_model')
        self.ent_model.pack(side=tk.LEFT)
        panel_model.pack(fill=tk.X)
        panel_model_old = ttk.Frame(panel_entrainement)
        lbl_model_old = ttk.Label(panel_model_old, text="(optionel) partir d'un modèle existant:")
        lbl_model_old.pack(side=tk.LEFT)
        self.ent_model_old = tk.Entry(panel_model_old)
        self.ent_model_old.pack(side=tk.LEFT)
        btn_path_model_old = ttk.Button(panel_model_old, text="...", command=self.renseigneFichierModelOld)
        btn_path_model_old.pack(side=tk.LEFT)
        panel_model_old.pack(fill=tk.X)
        self.check_basic = tk.IntVar()
        self.check_te = tk.IntVar()
        self.check_fn = tk.IntVar()
        chk_simple = ttk.Checkbutton(panel_entrainement, text="Rapide", variable=self.check_basic)
        chk_te = ttk.Checkbutton(panel_entrainement, text="Optimiser le TE", variable=self.check_te)
        chk_fn = ttk.Checkbutton(panel_entrainement, text="Optimiser les FN", variable=self.check_fn)
        btn_training = ttk.Button(panel_entrainement, text="Entraînement!", command=self.training)
        btn_training.pack(side=tk.RIGHT,padx=5,pady=9)
        chk_fn.pack(side=tk.RIGHT,padx=5,pady=9)
        chk_te.pack(side=tk.RIGHT,padx=5,pady=9)
        chk_simple.pack(side=tk.RIGHT,padx=5,pady=9)
        panel_entrainement.pack(fill=tk.X, padx=5, pady=9)
        
        #Detection
        panel_detection = ttk.Frame(self.notebook_p2)
        
        panel_sel_modele = ttk.Frame(panel_detection)
        lbl_model_ent = ttk.Label(panel_sel_modele, text="Sélection du modèle :")
        lbl_model_ent.pack(side=tk.LEFT)
        self.ent_path_model = tk.Entry(panel_sel_modele)
        self.ent_path_model.pack(side=tk.LEFT)
        if model_name != None:
            self.ent_path_model.insert(0,model_name)
        btn_path_model = ttk.Button(panel_sel_modele, text="...", command=self.renseigneFichierModel)
        btn_path_model.pack(side=tk.LEFT)
        panel_sel_modele.pack(fill=tk.X, padx=5, pady=9)
        lbl_detection = ttk.Label(panel_detection, text="Appliquer le modèle :")
        lbl_detection.pack(side=tk.LEFT)
        btn_detect_one = ttk.Button(panel_detection, text="Sur un fichier", command=self.detect_one_file)
        btn_detect_list = ttk.Button(panel_detection, text="Sur un fichier de caracs", command=self.detect_list_file)
        btn_detect_one.pack(side=tk.LEFT,padx=5)
        btn_detect_list.pack(side=tk.LEFT,padx=5)
        panel_detection.pack(fill=tk.X, padx=5, pady=9)

        # Watcher
        panel_start_stop = ttk.Frame(self.notebook_p2)
        lbl_watcher = ttk.Label(panel_start_stop, text="Démarrer le watcher :")
        lbl_watcher.pack(side=tk.LEFT)
        self.btn_start_stop = ttk.Button(panel_start_stop, text="Start", command=self.start_stop_watcher)
        self.btn_start_stop.pack(side=tk.LEFT,padx=5)
        panel_start_stop.pack(fill=tk.X, padx=5, pady=9)
        import win32com.client as win32com_client
        scheduler = win32com_client.Dispatch("Schedule.Service")
        scheduler.Connect("" or None, "" or None, "" or None, "" or None)
        rootFolder = scheduler.GetFolder("\\")
        try:
            task = rootFolder.GetTask("SDO_GUI_TASK")
        except:
            task = None
        if task is None:
            self.btn_persist = ttk.Button(panel_start_stop, text="Start on boot", command=self.start_on_boot)
        else:
            if task.Enabled == False:
                self.btn_persist = ttk.Button(panel_start_stop, text="Start on boot", command=self.start_on_boot)
            else:
                self.btn_persist = ttk.Button(panel_start_stop, text="Remove start on boot", command=self.start_on_boot)
        self.btn_persist.pack(side=tk.LEFT,padx=5)
        self.notebook.add(self.notebook_p1,text="Entrainement")
        self.notebook.add(self.notebook_p2,text="Utilisation")
        self.notebook.pack(padx=5,pady=5)
        separator = ttk.Separator(master)
        separator.pack(fill=tk.X, padx=5, pady=9,side=tk.BOTTOM)
        self.close_button = ttk.Button(master, text="Fermer", command=self.quit)
        self.close_button.pack()
        if model_name != None:
            self.start_stop_watcher()

    def start_on_boot(self):
        import win32com.client as win32com_client
        scheduler = win32com_client.Dispatch("Schedule.Service")
        scheduler.Connect("" or None, "" or None, "" or None, "" or None)
        rootFolder = scheduler.GetFolder("\\")
        try:
            task = rootFolder.GetTask("SDO_GUI_TASK")
        except:
            task = None
        to_be_enabled = True
        if task is not None:
            if task.Enabled == True:
                to_be_enabled = False
        if to_be_enabled:
            model = self.ent_path_model.get()
            if model == "":
                messagebox.showerror("Erreur", "Un modèle doit être renseigné.")
                return
            computer_name = "" #leave all blank for current computer, current user
            computer_username = ""
            computer_userdomain = ""
            computer_password = ""
            abs_path = os.path.dirname(os.path.abspath(__file__))
            action_path = abs_path+"\\SDO_Gui.exe" #executable path (could be python.exe)
            action_workdir = abs_path #working directory for action executable
            action_id = "SDO_GUI" #arbitrary action ID
            
            action_arguments = model #arguments (could be something.py)
            author = "SDO TEAM" #so that end users know who you are
            description = "START SDO watcher" #so that end users can identify the task
            task_id = "SDO_GUI_TASK"
            task_hidden = False #set this to True to hide the task in the interface
            username = ""
            password = ""
            run_flags = "TASK_RUN_NO_FLAGS" #see dict below, use in combo with username/password
            #define constants
            TASK_TRIGGER_LOGON = 9
            TASK_CREATE = 2
            TASK_CREATE_OR_UPDATE = 6
            TASK_ACTION_EXEC = 0
            TASK_LOGON_INTERACTIVE_TOKEN = 3

            IID_ITask = "{148BD524-A2AB-11CE-B11F-00AA00530503}"
            RUNFLAGSENUM = {
                "TASK_RUN_NO_FLAGS"              : 0,
                "TASK_RUN_AS_SELF"               : 1,
                "TASK_RUN_IGNORE_CONSTRAINTS"    : 2,
                "TASK_RUN_USE_SESSION_ID"        : 4,
                "TASK_RUN_USER_SID"              : 8 
            }
            #connect to the scheduler (Vista/Server 2008 and above only)
            import win32com.client as win32com_client
            scheduler = win32com_client.Dispatch("Schedule.Service")
            scheduler.Connect(computer_name or None, computer_username or None, computer_userdomain or None, computer_password or None)
            rootFolder = scheduler.GetFolder("\\")

            
            #(re)define the task
            taskDef = scheduler.NewTask(0)
            colTriggers = taskDef.Triggers
            trigger = colTriggers.Create(TASK_TRIGGER_LOGON)
            trigger.Id = "LogonTriggerId"
            #trigger.UserId = os.environ.get('USERNAME') # current user account
            #trigger.Enabled = False
            colActions = taskDef.Actions
            action = colActions.Create(TASK_ACTION_EXEC)
            action.ID = action_id
            action.Path = action_path
            action.WorkingDirectory = action_workdir
            action.Arguments = action_arguments
            info = taskDef.RegistrationInfo
            info.Author = author
            info.Description = description
            settings = taskDef.Settings
            settings.Enabled = False
            settings.Hidden = task_hidden
            principal = taskDef.Principal
            principal.RunLevel = 1
            #register the task (create or update, just keep the task name the same)
            result = rootFolder.RegisterTaskDefinition(task_id, taskDef, TASK_CREATE_OR_UPDATE, "", "", TASK_LOGON_INTERACTIVE_TOKEN)
            task = rootFolder.GetTask(task_id)
            task.Enabled = True
            self.btn_persist["text"] = "Remove start on boot"
        else:
            self.btn_persist["text"] = "Start on boot"
            task.Enabled = False

    def start_stop_watcher(self):
        """
        Fonction appelé lorsque le bouton start/stop de la section watcher est appuyé
        Démarre les observeurs watchdog ou les arrêtes
        """
        # Si les watchers n'étaient pas lancés alors il s'agit d'un start
        if self.watcher_started == False:
            model = self.ent_path_model.get()
            if model == "":
                messagebox.showerror("Erreur", "Un modèle doit être renseigné.")
                return
            
            self.event_handler = SDO_Handler(self.master,model,patterns=["*.exe","*.dll"],ignore_directories=False)
            self.watcher_started = True
            self.btn_start_stop["text"] = "Stop"
            try:
                paths = open("../path.txt", "r")
            except:
                paths = ["%APPDATA%","%APPDATA%\\..\\Local\\Temp","%PUBLIC%","%ALLUSERSPROFILE%","C:\\Windows\\System32","C:\\Windows\\Temp","%CommonProgramFiles%","%ProgramFiles%","%APPDATA%\\Microsoft\\Windows\\AccountPictures","%APPDATA%\\Microsoft\\Windows\\CloudStore","%APPDATA%\\Microsoft\\Windows\\Libraries","%APPDATA%\\Microsoft\\Windows\\Start Menu","%APPDATA%\\Microsoft\\Windows\\Network Shortcuts","%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts","%APPDATA%\\Microsoft\\Windows\\SendTo","%APPDATA%\\Microsoft\\Windows\\Templates","%APPDATA%\\Microsoft\\Windows\\Themes"]
            self.observers = getObservers(paths, self.event_handler)
            self.master.iconify()

        else:
            # Si les watchers étaient lancés alors il s'agit d'un stop
            self.watcher_started = False
            self.btn_start_stop["text"] = "Start"
            clean(self.observers)
            self.master.deiconify()

    def quit(self):
        """
        Fonction de fermeture de la fenêtre
        """
        self.wantToQuit = True
        self.master.quit()

    def add_one_file(self):
        """
        Fonction appelé lorsque le bouton d'Extraction des caractéristiques d'un fichier est appuyé:
        Demande à l'utilisateur le fichier à extraire avec une fenêtre de dialogue
        Puis demande à l'utilisateur le nom du fichier qui contiendra les caractéristiques extraites.
        Enfin extrait les caractéristiques et les places au format json.
        """
        file_to_extract = filedialog.askopenfilename(initialdir = ".",title = "Choisir un PE",filetypes = (("exe","*.exe"),("dll","*.dll"),("all files","*.*")))
        if file_to_extract == "":
            return
        save_file = filedialog.asksaveasfilename(initialdir = ".",title = "Sauvegardez sous",defaultextension = 'json',filetypes = (("json files","*.json"),("all files","*.*")))
        if save_file == "":
            return
        values = dict()
        caracs = Extracteur.extract_one(file_to_extract)
        values[file_to_extract] = caracs
        with open(save_file,"w") as f:
            f.write(json.dumps(values))
        messagebox.showinfo("Succès", file_to_extract+" a été extrait vers "+save_file)

    def add_json_list(self):
        """
        Fonction appelé lorsque le bouton d'Extraction des caractéristiques d'une liste de fichier est appuyé:
        Demande à l'utilisateur la liste de chemin de fichier à extraire avec une fenêtre de dialogue
        Puis demande à l'utilisateur le nom du fichier qui contiendra les caractéristiques extraites.
        Enfin extrait les caractéristiques pour chaque fichier et les places au format json.
        """
        list_to_extract = filedialog.askopenfilename(initialdir = ".",title = "Choisir une liste de PE",filetypes = (("json files","*.json"),("all files","*.*")))
        if list_to_extract == "":
            return
        save_file = filedialog.asksaveasfilename(initialdir = ".",title = "Sauvegardez sous",defaultextension = 'json',filetypes = (("json files","*.json"),("all files","*.*")))
        if save_file == "":
            return
        compteur = Extracteur.extract_list(list_to_extract,save_file)
        messagebox.showinfo("Succès", str(compteur)+"fichiers ont été extraits vers "+save_file)

    def add_whole_dir(self):
        """
        Fonction appelé lorsque le bouton d'Extraction des caractéristiques de tous les fichiers d'un dossier est appuyé:
        Demande à l'utilisateur le chemin du dossier à extraire avec une fenêtre de dialogue
        Puis demande à l'utilisateur le nom du fichier qui contiendra les caractéristiques extraites.
        Enfin extrait les caractéristiques pour chaque fichier du dossier et les places au format json.
        """
        dir_to_extract = filedialog.askdirectory(initialdir = ".", title = "Choisir un dossier d'import")
        if dir_to_extract == "":
            return
        save_file = filedialog.asksaveasfilename(initialdir = ".",title = "Sauvegardez sous",defaultextension = 'json',filetypes = (("json files","*.json"),("all files","*.*")))
        if save_file == "":
            return
        print("Listing des fichiers...")
        exe_liste = Tools.Find_all_PE.recursListPath(dir_to_extract,10)
        compteur = Extracteur.extract_list_from_list(exe_liste,save_file)
        messagebox.showinfo("Succès", str(compteur)+"fichiers ont été extraits vers "+save_file)

    def renseigneFichierClean(self):
        """
        Fonction appelé lorsque le bouton "..." à côté de l'entrée de chemin pour les fichiers sains est appuyé
        Ouvre une fenêtre de dialogue demandant un fichier
        Puis insère le chemin du fichier dans l'entrée utilisateur correspondante.
        """
        list_clean = filedialog.askopenfilename(initialdir = "../Models",title = "Choisir une extraction de fichier sains",filetypes = (("json files","*.json"),("all files","*.*")))
        self.ent_path_clean.delete(0,tk.END)
        self.ent_path_clean.insert(0,list_clean)

    def renseigneFichierMalware(self):
        """
        Fonction appelé lorsque le bouton "..." à côté de l'entrée de chemin pour les fichiers malwares est appuyé
        Ouvre une fenêtre de dialogue demandant un fichier
        Puis insère le chemin du fichier dans l'entrée utilisateur correspondante.
        """
        list_malware = filedialog.askopenfilename(initialdir = "../Models",title = "Choisir une extraction de malware",filetypes = (("json files","*.json"),("all files","*.*")))
        self.ent_path_malware.delete(0,tk.END)
        self.ent_path_malware.insert(0,list_malware)

    def renseigneFichierModel(self):
        """
        Fonction appelé lorsque le bouton "..." à côté de l'entrée de chemin pour le modèle est appuyé
        Ouvre une fenêtre de dialogue demandant un fichier
        Puis insère le chemin du fichier dans l'entrée utilisateur correspondante.
        """
        path_model = filedialog.askopenfilename(initialdir = "../Models",title = "Choisir un modèle entraîné",filetypes = (("json files","*.json"),("all files","*.*")))
        self.ent_path_model.delete(0,tk.END)
        self.ent_path_model.insert(0,path_model)
    def renseigneFichierModelOld(self):
        """
        Fonction appelé lorsque le bouton "..." à côté de l'entrée de chemin pour le modèle préexistant est appuyé
        Ouvre une fenêtre de dialogue demandant un fichier
        Puis insère le chemin du fichier dans l'entrée utilisateur correspondante.
        """
        path_model = filedialog.askopenfilename(initialdir = "../Models",title = "Choisir un modèle entraîné",filetypes = (("json files","*.json"),("all files","*.*")))
        self.ent_model_old.delete(0,tk.END)
        self.ent_model_old.insert(0,path_model)

    def trainingTE(self):
        """
        Fonction appelée lorsque le bouton d'entraînement optimisé T.E est appuyé
        Récupère les informations pour l'entrainement
        puis entraîne (2^nombre de stats ici 9) modèles puis selectionne celui obtenant le plus faible taux d'erreur
        """
        cleans, malwares, ratio_clean, ratio_malware, nom_model, model_old = self.get_data_training()
        results = CaracStats.trainingTE(cleans, malwares,ratio_clean,ratio_malware,nom_model,model_old)
        taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
        taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
        
        messagebox.showinfo("Succès", "Test du modèle avec données non utilisées : "+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")
        self.ent_path_model.delete(0,tk.END)
        self.ent_path_model.insert(0,nom_model)
    
    def trainingFN(self):
        """
        Fonction appelée lorsque le bouton d'entraînement optimisé F.N est appuyé
        Récupère les informations pour l'entrainement
        puis entraîne (2^nombre de stats ici 9) modèles puis selectionne celui obtenant le plus faible taux de faux négatif
        """
        cleans, malwares, ratio_clean, ratio_malware, nom_model, model_old = self.get_data_training()
        results = CaracStats.trainingFN(cleans, malwares,ratio_clean,ratio_malware,nom_model,model_old)
        taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
        taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
        
        messagebox.showinfo("Succès", "Test du modèle avec données non utilisées : "+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")
        self.ent_path_model.delete(0,tk.END)
        self.ent_path_model.insert(0,nom_model)

    def doTraining(self, cleans, malwares, ratio_clean, ratio_malware, nom_model, model_old):
        """
        entraîne le modèle [1,1,1,1,1,1,1,1,1] avec les caractéristiques données
        """
        results = Trainer.training(cleans, malwares,ratio_clean,ratio_malware,[1,1,1,1,1,1,1,1,1],nom_model,model_old)
        taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
        taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
        
        messagebox.showinfo("Succès entraînement rapide", "Test du modèle avec données non utilisées : "+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")

    def training(self):
        """
        Fonction appelée lorsque le bouton d'entraînement classique est appuyé
        Récupère les informations pour l'entrainement
        puis entraîne un modèle communément le meilleur
        """
        cleans, malwares, ratio_clean, ratio_malware, nom_model, model_old, opti_simple, opti_te, opti_fn = self.get_data_training()
        if opti_simple:
            self.doTraining(cleans, malwares, ratio_clean, ratio_malware, nom_model+"_rapide", model_old)
        if opti_te or opti_fn:
            opti_results = CaracStats.getTrainingsResults(cleans, malwares,9,ratio_clean,ratio_malware)
            if opti_te:
                top = CaracStats.getTopLowestError(opti_results,1)
                selecter_used = top[0][0]
                results = Trainer.training(cleans,malwares,ratio_clean,ratio_malware,selecter_used,nom_model+"_te",model_old)
                taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
                taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
                
                messagebox.showinfo("Succès entraînement taux erreur", "Test du modèle avec données non utilisées : "+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")
            if opti_fn:
                top = CaracStats.getTopLowestFalseNeg(opti_results,1)
                selecter_used = top[0][0]
                results = Trainer.training(cleans,malwares,ratio_clean,ratio_malware,selecter_used,nom_model+"_fn",model_old)
                taux_faux_pos = float(results["Clean_incorrect"])/float(results["Clean_incorrect"]+results["Clean_correct"])
                taux_faux_neg = float(results["Malware_incorrect"])/float(results["Malware_incorrect"]+results["Malware_correct"])
                
                messagebox.showinfo("Succès entraînement faux négatifs", "Test du modèle avec données non utilisées : "+str(round(taux_faux_neg,3)*100)+ "% malwares non détectés "+str(round(taux_faux_pos,3)*100)+" % de sains flaggés")

        

    def get_data_training(self):
        """
        Récupère les informations données par l'utilisateur pour l'entrainement
        """
        path_clean = self.ent_path_clean.get()
        path_malware = self.ent_path_malware.get()
        nom_model = self.ent_model.get()
        model_old = self.ent_model_old.get()
        opti_simple = self.check_basic.get()
        opti_te = self.check_te.get()
        opti_fn = self.check_fn.get()
        if opti_simple + opti_fn + opti_te == 0:
            messagebox.showinfo("Erreur", "Au moins un type d'entraînement doit être sélectionné")
            return
        if nom_model == "":
            nom_model = "SDO_model"
        nom_model = nom_model+".joblib"
        try:
            ratio_clean = float(self.ent_ratio_clean.get())
            ratio_malware = float(self.ent_ratio_malware.get())
            if ratio_clean > 1 or ratio_malware > 1 or ratio_clean < 0 or ratio_clean < 0:
                messagebox.showinfo("Erreur", "Les ratios sont entre 0 et 1")
                return
        except:
            messagebox.showinfo("Erreur", "Les ratios sont des flottants entre 0 et 1")
            return
        if path_clean == "" and path_malware == "":
            messagebox.showinfo("Erreur", "Au moins un fichier de caractéristique doit être renseigné.")
            return
        with open(path_clean, "r") as f:
            cleans = json.loads(f.read())
        with open(path_malware, "r") as f:
            malwares = json.loads(f.read())
        return cleans, malwares, ratio_clean, ratio_malware, nom_model, model_old, opti_simple, opti_te, opti_fn
        

    

    def detect_one_file(self):
        """
        Fonction appelé lorsque le bouton d'analyse d'un fichier est appuyé
        Demande à l'utilisateur le chemin du fichier à analyser puis lance l'analyse
        """
        model_name = self.ent_path_model.get()
        file_to_extract = filedialog.askopenfilename(initialdir = ".",title = "Choisir un PE",filetypes = (("exe","*.exe"),("dll","*.dll"),("all files","*.*")))
        if file_to_extract == "":
            return
        proba_sain = execute_detect_one_file(model_name, file_to_extract)
        if proba_sain >0.5:
            messagebox.showinfo("Sain", file_to_extract+" : est un fichier sain avec "+str(proba_sain*100)+"% de confiance")
        else:
            messagebox.showinfo("Malware", file_to_extract+" : est un malware avec "+str((1-proba_sain)*100)+"% de confiance")



    
    def detect_list_file(self):
        """
        Fonction appelé lorsque le bouton d'analyse d'une lsite de caractéristiques pré-extraite est appuyé
        Demande à l'utilisateur le chemin de la liste à analyser puis lance l'analyse
        Demande ensuite à l'utilisateur s'il souhaite sauvegardés les résultats pour vérification
        """
        model_name = self.ent_path_model.get()
        file_to_extract = filedialog.askopenfilename(initialdir = ".",title = "Choisir une liste de caractéristique",filetypes = (("json","*.json"),("all files","*.*")))
        if file_to_extract == "":
            return
        with open(file_to_extract, "r") as f:
            values = json.loads(f.read())
        values_only = []
        names_only = []
        for key,val in values.items():
            values_only.append(val)
            names_only.append(key)
        probas_list = SDO.classify_proba(model_name, values_only, names_only)
        clean_list = []
        malware_list = []
        for i,elem in enumerate(probas_list):
            if elem[0] > 0.5:
                clean_list.append([names_only[i], elem[0]])
            else:
                malware_list.append([names_only[i], elem[1]])
        import operator
        clean_list.sort(key=operator.itemgetter(1),reverse=True)
        malware_list.sort(key=operator.itemgetter(1),reverse=True)
        result = messagebox.askquestion("Résultats", str(len(clean_list))+ " fichiers sains et "+str(len(malware_list))+" malwares identifiés. Voulez vous extraire la liste des fichiers sains ?")
        if result == "yes":
            save_file = filedialog.asksaveasfilename(initialdir = ".",title = "Sauvegardez sous",defaultextension = 'json',filetypes = (("json files","*.json"),("all files","*.*")))
            if save_file != "":
                with open(save_file,"w") as f:
                    f.write(json.dumps(clean_list))
        
        result = messagebox.askquestion("Résultats", "Rappel : "+str(len(clean_list))+ " fichiers sains et "+str(len(malware_list))+" malwares identifiés. Voulez vous extraire la liste des malwares ?")
        if result == "yes":
            save_file = filedialog.asksaveasfilename(initialdir = ".",title = "Sauvegardez sous",defaultextension = 'json',filetypes = (("json files","*.json"),("all files","*.*")))
            if save_file != "":
                with open(save_file,"w") as f:
                    f.write(json.dumps(malware_list))
        
if not admin.isUserAdmin():
    admin.runAsAdmin()
else:
    model_name = None
    if len(sys.argv) >= 2:
        if type(sys.argv[-1]) == str:
            if sys.argv[-1].endswith(".joblib.json"):
                model_name = sys.argv[-1]
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("vista")
    root.geometry("600x430")
    my_gui = SDO_GUI(root,model_name)



    root.mainloop()