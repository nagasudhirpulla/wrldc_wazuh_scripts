# /syscollector/008/ports?state=listening&local.ip=0.0.0.0
import json
import requests
import urllib3
from base64 import b64encode
from src.typeDefs import IWazuhConfig


def getWazuhApiToken(wazuhConf: IWazuhConfig) -> str:
    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    loginEndpoint = 'security/user/authenticate'
    loginUrl = f"{wazuhConf['protocol']}://{wazuhConf['host']}:{wazuhConf['port']}/{loginEndpoint}"
    basicAuth = f"{wazuhConf['username']}:{wazuhConf['password']}".encode()
    loginHeaders = {'Content-Type': 'application/json',
                    'Authorization': f'Basic {b64encode(basicAuth).decode()}'}

    response = requests.get(loginUrl, headers=loginHeaders, verify=False)
    token = json.loads(response.content.decode())['data']['token']
    return token
