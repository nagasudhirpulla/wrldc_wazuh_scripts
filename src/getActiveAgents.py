import json
from typing import List

import requests
import urllib3

from src.typeDefs import IWazuhConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def getActiveAgents(wazuhConf: IWazuhConfig, token: str) -> List[object]:
    requests_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'}

    response = requests.get(
        f"{wazuhConf['protocol']}://{wazuhConf['host']}:{wazuhConf['port']}/agents?status=active",
        headers=requests_headers, verify=False)

    # print(response.text)
    agentsJson: List[object] = json.loads(response.text).get(
        "data", {}).get("affected_items", [])
    return agentsJson
