from pydantic import BaseModel, Field, SecretStr

class InfoBloxConfig(BaseModel):
    host: str
    username: str
    password: SecretStr
    port: int = 443
    version: str = '2.12'
    ssl_verify: bool | str = True # Allow bool or path to CA bundle
    timeout: int = 30
