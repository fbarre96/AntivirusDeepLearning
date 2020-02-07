import requests

def downloadFile(URL=None):
    import httplib2
    h = httplib2.Http(".cache")
    resp, content = h.request(URL, "GET")
    return content

content = downloadFile("https://github.com/malwares/DangerousZone/raw/master/vBot.rar")
with open("save.rar","wb") as f:
    f.write(content)
