# GET /syscollector/010/netproto?iface=Ethernet
# GET /syscollector/010/netiface?state=up&type=ethernet
# GET /syscollector/010/netaddr?iface=Ethernet

from typing import List, TypedDict
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

print("\ngetting ethernet interfaces summary in all agents:")

requestHeaders = {'Content-Type': 'application/json',
                  'Authorization': f'Bearer {token}'}

# for each agent, get the ethernet interface name, MAC, adapter - GET /syscollector/010/netiface?state=up&type=ethernet
# for each agent, get the gateway IP, DHCP status, protocol - GET /syscollector/010/netproto?iface=Ethernet
# for each agent, get the IP, subnet mask  - GET /syscollector/010/netaddr?iface=Ethernet


class IAgentInterfaceInfo(TypedDict):
    interfaceName: str
    mac: str
    adapter: str
    gatewayIp: str
    dhcpStatus: str
    protocol: str
    ip: str
    subnetMask: str


protocol = wazuhConf['protocol']
host = wazuhConf['host']
port = wazuhConf['port']
for agntItr, agnt in enumerate(requiredAgents):
    agentId = agnt["agentId"]
    agentInterfaces: List[IAgentInterfaceInfo] = []

    response = requests.get(
        f"{protocol}://{host}:{port}/syscollector/{agentId}/netiface?state=up&type=ethernet",
        headers=requestHeaders, verify=False)
    agentEthernetInterfacesJson = response.json().get(
        "data", {}).get("affected_items", [])
    agentInterfaces = [{
        "interfaceName": x["name"],
        "mac": x["mac"],
        "adapter":x["adapter"]
    } for x in agentEthernetInterfacesJson]

    if len(agentInterfaces) == 0:
        continue

    for ifaceItr, iface in enumerate(agentInterfaces):
        response = requests.get(
            f"{protocol}://{host}:{port}/syscollector/{agentId}/netproto?iface={iface['interfaceName']}",
            headers=requestHeaders, verify=False)
        interfaceProtocolInfo = response.json().get(
            "data", {}).get("affected_items", [])[0]
        agentInterfaces[ifaceItr]["dhcpStatus"] = interfaceProtocolInfo["dhcp"]
        agentInterfaces[ifaceItr]["gatewayIp"] = interfaceProtocolInfo["gateway"]
        agentInterfaces[ifaceItr]["protocol"] = interfaceProtocolInfo["type"]

        response = requests.get(
            f"{protocol}://{host}:{port}/syscollector/{agentId}/netaddr?iface={iface['interfaceName']}",
            headers=requestHeaders, verify=False)
        interfaceAddressInfo = response.json().get(
            "data", {}).get("affected_items", [])[0]
        agentInterfaces[ifaceItr]["ip"] = interfaceAddressInfo["address"]
        agentInterfaces[ifaceItr]["subnetMask"] = interfaceAddressInfo["netmask"]

    interfaceSummaryProps = agentInterfaces[0].keys()
    for interfaceProp in interfaceSummaryProps:
        requiredAgents[agntItr][interfaceProp] = ", ".join(
            [str(x[interfaceProp]) for x in agentInterfaces])

# with open("test.json", mode='w') as f:
#     f.write(json.dumps(requiredAgents, indent=4))

agentsInterfacesInfoDf = pd.DataFrame(
    requiredAgents).drop(columns=["osPlatform"])
agentsInterfacesInfoDf.to_csv("output/interfaces_info.csv", index=False)
print("\nEnd of the script.\n")
