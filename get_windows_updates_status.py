# GET /vulnerability/008/summary/name
import pandas as pd
import requests
import urllib3

from src.appConfig import getWazuhConfig
from src.getActiveAgents import getActiveAgents
from src.getWazuhApiToken import getWazuhApiToken

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

wazuhConf = getWazuhConfig()
token = getWazuhApiToken(wazuhConf)

print("\nGetting active agents summary:")

activeAgents = getActiveAgents(wazuhConf, token)

requiredAgents = []

for agnt in activeAgents:
    agentId = agnt.get("id", None)
    agentName = agnt.get("name", None)
    agentIp = agnt.get("ip", None)
    osName = agnt.get("os", None).get("name", None)
    osPlatform = agnt.get("os", None).get("platform", None)
    osVersion = agnt.get("os", None).get("version", None)
    lastKeepAlive = agnt.get("lastKeepAlive", None)

    if osPlatform is None:
        continue

    if not osPlatform.lower() == "windows":
        continue

    requiredAgents.append(
        {
            "agentId": agentId,
            "agentName": agentName,
            "agentIp": agentIp,
            "osName": osName,
            "osPlatform": osPlatform,
            "osVersion": osVersion,
            "lastKeepAlive": lastKeepAlive
        })

requestHeaders = {'Content-Type': 'application/json',
                  'Authorization': f'Bearer {token}'}

print("\ngetting windows vulnerabilities in all agents:")

for agntItr, agnt in enumerate(requiredAgents):
    agentId = agnt["agentId"]
    response = requests.get(
        f"{wazuhConf['protocol']}://{wazuhConf['host']}:{wazuhConf['port']}/vulnerability/{agentId}/summary/name",
        headers=requestHeaders, verify=False)
    agentVulJson = response.json().get("data", {}).get("name", {})
    agentWindowsVulnList = []
    for vulName in agentVulJson:
        if vulName.lower().startswith("windows"):
            agentWindowsVulnList.append(f"{vulName} ({agentVulJson[vulName]})")
    requiredAgents[agntItr]["osVulnerability"] = ", ".join(
        agentWindowsVulnList)

# with open("test.json", mode='w') as f:
#     f.write(json.dumps(agentsList, indent=4))

agentsSummaryDf = pd.DataFrame(requiredAgents).drop(columns=["osPlatform"])
agentsSummaryDf.to_csv("output/windows_vulnerability_summary.csv", index=False)

print("\nEnd of the script.\n")
