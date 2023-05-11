from typing import TypedDict


class IWazuhConfig(TypedDict):
    protocol: str
    host: str
    port: int
    username: str
    password: str
    loginEndPoint: str