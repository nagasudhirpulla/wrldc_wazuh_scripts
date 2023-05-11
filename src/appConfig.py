from src.typeDefs import IWazuhConfig
import json


def getWazuhConfig(fName="config.json") -> IWazuhConfig:
    with open(fName) as f:
        data = json.load(f)
        return data