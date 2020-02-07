from oletools import mraptor3
from oletools import olevba3 as olevba
from oletools.olevba3 import TYPE2TAG
import os
import re

def extractAllVariables(filepath):
    variables = dict()
    vba_code = extract_vba(filepath)
    bin_size = os.path.getsize(filepath)
    if vba_code is None:
        return None
    if type(vba_code) is not str:
        return None
    strings = extractStrings(vba_code)

    # ratio macro / reste
    variables["macro_size_ratio"] = str(float(len(vba_code))/float(bin_size))
    # ratio macro / reste
    variables["comment_macro_ratio"] = str(extractCommentRatio(vba_code))
    # mean string size
    nb_strings = len(strings)
    len_all_strings = sum([len(stringi) for stringi in strings])
    variables["mean_string_size"] = str(float(len_all_strings)/float(nb_strings))
    # mraptor
    mraptor = mraptor3.MacroRaptor(vba_code)
    mraptor.scan()
    variables["mraptor"] = "1" if mraptor.suspicious else "0"
    # ips strings, domain strings
    ip_count = 0
    domain_count = 0
    reg_count = 0
    
    for string in strings:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", string):
            ip_count += 1
        if re.match(r"^([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+$", string):
            domain_count += 1
        if string.startswith("HKEY_CURRENT_USER\\") or string.startswith("HKEY_CLASSES_ROOT\\") or string.startswith("HKEY_LOCAL_MACHINE\\") or string.startswith("HKEY_USERS\\") or string.startswith("HKEY_CURRENT_CONFIG\\"):
            reg_count += 1
        elif string.startswith("HKCU\\") or string.startswith("HKLM\\"):
            reg_count += 1
    variables["nb_ip_string"] = str(ip_count)
    variables["nb_domain_strings"] = str(domain_count)
    variables["nb_registry"] = str(reg_count)

    #Persistence
    persistence_count = getNbPersistenceMechanism(vba_code, strings)
    variables["nb_persistence_mechanism"] = str(persistence_count)
    # Extern call
    extern_call,hosting_websites  = getExternCall(vba_code)
    variables["nb_extern_call"] = str(extern_call)
    variables["nb_hosting_websites"] = str(hosting_websites)
    return variables

def getExternCall(vba_code):
    triggers_call = ["cmd","powershell","msbuild","script","shell","cscript","ftp","bitsadmin","netcat","wget"]
    triggers_hosting = ["pastebin","dropbox","github","gitlab"]
    count_call = 0
    count_hosting = 0
    for line in vba_code.split("\n"):
        for trigger in triggers_call:
            if trigger in line:
                count_call += 1
        for trigger in triggers_hosting:
            if trigger in line:
                count_hosting += 1
    return count_call,count_hosting

def getNbPersistenceMechanism(vba_code, strings):
    keys = ["""HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run""",
            """HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run""",
            """HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce""",
            """HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce""",
            """HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run""",
            """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run""",
            """HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce""",
            """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce""",
            """HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run""",
            """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run""",
            """HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders""",
            """HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders""",
            """HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders""",
            """HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders""",
            """HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders""",
            """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders""",
            """HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders""",
            """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"""]
    count = 0
    for string in strings:
        if string in keys:
            count += 1
        if ".dll" in  string:
            count += 1
    return count

def extract_vba(filepath):
    vba_code_all_modules = None
    try:
        vba_parser = olevba.VBA_Parser(filename=filepath)
    except Exception as e:
        print(e)
        return None
    if vba_parser.detect_vba_macros():
        vba_code_all_modules = ''
        try:
            for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_all_macros():
                vba_code_all_modules += vba_code.decode('utf-8','replace') + '\n'
        except Exception as e:
            return ""
    return vba_code_all_modules

def extractCommentRatio(macro):
    comment_re = r"^\s*\'"
    lines = macro.split("\n")
    nb_lines = len(lines)
    matches = re.findall(comment_re,macro, re.M)
    return float(len(matches))/float(nb_lines)
    
def extractStrings(macro):
    strings_re = r"\"([^\"]*(?:'.[^\"]*)*)\""
    matches = re.findall(strings_re,macro)
    return matches