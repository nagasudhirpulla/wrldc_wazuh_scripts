# get all packages installed in less than ten agents
import json

import requests
import urllib3

from src.appConfig import getWazuhConfig
from src.getActiveAgents import getActiveAgents
from src.getWazuhApiToken import getWazuhApiToken

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

wazuhConf = getWazuhConfig()

# Configuration
protocol = wazuhConf["protocol"]
host = wazuhConf["host"]
port = wazuhConf["port"]
user = wazuhConf["username"]
password = wazuhConf["password"]

excludedVendors = ["Microsoft Corporation", "HP Inc."]
numPcThreshold = 5

token = getWazuhApiToken(wazuhConf)
fetchedAgents = getActiveAgents(wazuhConf, token)

requestHeaders = {'Content-Type': 'application/json',
                  'Authorization': f'Bearer {token}'}

agents = []
for a in fetchedAgents:
    if not "os" in a:
        continue
    osPlatform = a["os"]["platform"].lower()
    if not osPlatform == "windows":
        continue
    agents.append({
        "id": a["id"], "name": a["name"], "platform": osPlatform
    })


packageDict = {}

for a in agents:
    agentName = a["name"]
    agentId = a["id"]
    response = requests.get(
        f"{protocol}://{host}:{port}/syscollector/{agentId}/packages", headers=requestHeaders, verify=False)
    respJson = response.json()
    if not "data" in respJson:
        print(f"Packages not found for {agentName}")
        continue
    packages = respJson["data"]["affected_items"]
    for p in packages:
        packageVendor = p.get("vendor", "--unknown--")
        if packageVendor in excludedVendors:
            continue
        packageName = p["name"]
        if not packageName in packageDict:
            packageDict[packageName] = [a["name"]]
        else:
            packageDict[packageName].append(a["name"])

packageUserMapDict = {}
for pName in packageDict:
    agentNames = packageDict[pName]
    if len(agentNames) <= numPcThreshold:
        packageUserMapDict[pName] = agentNames

usersList = []
for p in packageUserMapDict:
    usersList.extend(packageUserMapDict[p])
    usersList = list(set(usersList))

resDict = {
    "users": sorted(usersList),
    "packages": sorted(list(packageUserMapDict.keys())),
    "packageUserMap": packageUserMapDict
}

# print(packageDict)
with open("output/test.json", mode='w') as f:
    f.write(json.dumps(resDict))
