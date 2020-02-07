
import os
import re
import pefile
import json

def isAnExe(filepath):
    """
    Renvoie vrai si le chemin de fichier donné est au format PE
    """
    try:
        pe = pefile.PE(filepath)
        del pe
    except Exception as e:
        return False
    return True

def extractAllExeVariables(filepath):
    """
    Renvoie un dictionnaire avec les valeurs extraites dans le PE au chemin donné.
    Les variables se rapportant aux sections sont rapides à récupérer.
    la récupération des imports et dll utilisés dans le PE est plus longue
    """
    variables = dict()
    try:
        pe =  pefile.PE(filepath)
    except Exception as e:
        print("Error loading : "+str(e))
        return None
    
    bin_size = os.path.getsize(filepath)
    
    sections_infos = getSectionsInfo(pe)
    try:
        variables["text_size"] = sections_infos[".text"]["raw_data_size"]
    except:
        variables["text_size"] = 0
    try:
        variables["data_size"] = sections_infos[".data"]["raw_data_size"]
    except:
        variables["data_size"] = 0
    try:
        variables["bss_size"] = sections_infos[".bss"]["raw_data_size"]
    except:
        variables["bss_size"] = 0
    try:
        variables["rdata_size"] = sections_infos[".rdata"]["raw_data_size"]
    except:
        variables["rdata_size"] = 0
    try:
        variables["tls_size"] = sections_infos[".tls"]["raw_data_size"]
    except:
        variables["tls_size"] = 0
    try:
        variables["ratio_text_data"] = float(sections_infos[".text"]["raw_data_size"])/float(sections_infos[".data"]["raw_data_size"])
    except:
        variables["ratio_text_data"] = 1
    imports_info = getDllsAndImportsInfos(pe)
    variables["most_suspect_import"],variables["import_stat_score"]= getImportVars(imports_info)
    variables["bin_size"] = bin_size
    pe.close()
    del pe
    
    return variables

def getImportVars(imports_info):
    """
    Renvoie la variables sur les imports 
    (l'import le plus suspect statistiquement et la moyenne de suspicion des imports)
    """
    maximum = 0
    total = 0
    this_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(this_dir,"clean_import_stats.json"),"r") as f:
        clean_stats = json.loads(f.read())
    with open(os.path.join(this_dir,"virus_import_stats.json"),"r") as f:
        virus_stats = json.loads(f.read())
    for import_name in imports_info:
        
        try:
            clean_res = clean_stats[str(import_name)]
        except KeyError:
            clean_res = 0.0
        try:
            virus_res = virus_stats[str(import_name)]
        except KeyError:
            virus_res = 0.0
        
        diff = virus_res-clean_res
        if diff > maximum:
            maximum = diff
        total += diff
    return maximum,total
    

def getDllsAndImportsInfos(pe):
    """
    Renvoie la liste des imports utilisés dans un PE
    """
    # TODO implement statsitique analysis on imports and dll
    # implement
    imports = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imports.append(imp.name)
    except:
        pass
    return imports
    

def getStringsInfos(pe):
    # TODO implement statsitique analysis on imports and dll
    # implement
    strings = getStrings(pe)

def getSectionsInfo(pe):
    """
    Renvoie la liste des sections présentes dans un PE
    """
    sections=dict()
    for section in pe.sections:
        section_ret = dict()
        section_ret["virtual_address"] = section.VirtualAddress
        section_ret["misc_virtual_size"] = section.Misc_VirtualSize
        section_ret["raw_data_size"] = section.SizeOfRawData
        try:
            section_ret["name"] = section.Name.decode("ascii").replace("\x00","")
            sections[section_ret["name"]] = section_ret
        except:
            pass
    return sections

def getStrings(pe):
    """
    Renvoie la liste des strings présentes dans un PE
    """
    strings = list()
    # Fetch the index of the resource directory entry containing the strings
    #
    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])
    # Get the directory entry
    #
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    # For each of the entries (which will each contain a block of 16 strings)
    #
    for entry in rt_string_directory.directory.entries:
        # Get the RVA of the string data and
        # size of the string data
        #
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))

        # Retrieve the actual data and start processing the strings
        #
        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
        offset = 0
        while True:
            # Exit once there's no more data to read
            if offset>=size:
                break
            # Fetch the length of the unicode string
            #
            ustr_length = pe.get_word_from_data(data[offset:offset+2], 0)
            offset += 2

            # If the string is empty, skip it
            if ustr_length==0:
                continue

            # Get the Unicode string
            #
            ustr = pe.get_string_u_at_rva(data_rva+offset, max_length=ustr_length)
            offset += ustr_length*2
            strings.append(ustr)
            print('String of length', ustr_length, 'at offset', offset)

    return strings
