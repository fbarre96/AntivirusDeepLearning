# -*- mode: python -*-

block_cipher = None


a = Analysis(['D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/GUI_Project/SDO_Gui.py'],
             pathex=['D:\\Dev\\Python\\SDO_Antivirus_DeepLearning-dev_ml\\SDO_Antivirus_DeepLearning-dev_ml\\Development\\GUI_Project'],
             binaries=[],
             datas=[('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/GUI_Project/admin.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/CaracStats.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/Extracteur.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/SDO.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/Trainer.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/watcher.py', '.'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/Caracteristiques', 'Caracteristiques/'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/Tools', 'Tools/'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/Models', 'Models/'), ('D:/Dev/Python/SDO_Antivirus_DeepLearning-dev_ml/SDO_Antivirus_DeepLearning-dev_ml/Development/GUI_Project/images', 'images/')],
             hiddenimports=['pefile', 'sklearn', 'sklearn.ensemble', 'sklearn.neighbors', 'sklearn.neighbors.typedefs', 'sklearn.neighbors.quad_tree', 'sklearn.tree._utils'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='SDO_Gui',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='SDO_Gui')
