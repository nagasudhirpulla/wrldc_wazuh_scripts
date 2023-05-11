# /syscollector/008/ports?state=listening&local.ip=0.0.0.0
import pandas as pd
import requests
import urllib3

from src.appConfig import getWazuhConfig
from src.getActiveAgents import getActiveAgents
from src.getWazuhApiToken import getWazuhApiToken

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

specialPortChecks = [("SMB_445", 445), ("RDP_3389", 3389), ("FTP_21", 21),
                     ("SSH_22", 22), ("Telnet_23", 23), ("RPC_135", 135),
                     ("NetBios_139", 139), ("HTTP_80", 80)]

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
            "osVersion": osVersion
        })

print("\ngetting listening ports in all agents:")

# New authorization header with the JWT token we got
requestHeaders = {'Content-Type': 'application/json',
                  'Authorization': f'Bearer {token}'}

for agntItr, agnt in enumerate(requiredAgents):
    agentId = agnt["agentId"]
    response = requests.get(
        f"{wazuhConf['protocol']}://{wazuhConf['host']}:{wazuhConf['port']}/syscollector/{agentId}/ports?state=listening&local.ip=0.0.0.0",
        headers=requestHeaders, verify=False)
    agentPortsJson = response.json().get("data", {}).get("affected_items", [])
    agentPorts = [x.get("local", {}).get("port", 1000000)
                  for x in agentPortsJson]
    agentRequiredListeningPorts = sorted([p for p in agentPorts if p < 10000])
    for portInfo in specialPortChecks:
        requiredAgents[agntItr][portInfo[0]] = ""
    # set special ports info in agent summary dictionary
    for agentPort in agentPorts:
        for portInfo in specialPortChecks:
            if agentPort == portInfo[1]:
                requiredAgents[agntItr][portInfo[0]] = "YES"
                break

    requiredAgents[agntItr]["listening_ports"] = str(
        agentRequiredListeningPorts)[1:-1]

# with open("test.json", mode='w') as f:
#     f.write(json.dumps(agentsList, indent=4))

agentsPortsInfoDf = pd.DataFrame(requiredAgents).drop(columns=["osPlatform"])
agentsPortsInfoDf.to_csv("output/listening_ports_summary.csv", index=False)
print("\nEnd of the script.\n")
