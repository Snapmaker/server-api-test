from dotenv import load_dotenv

from pydantic_settings import BaseSettings

load_dotenv()
class Settings(BaseSettings):
    API_BASE_URL: str = [] #服务器的基本地址
    VERIFICATION_CODE_ENDPOINT: str = [] #短信验证码的地址
    OAUTH_TOKEN_ENDPOINT: str = []#身份认证的地址
    CLIENT_ID: str = []
    CLIENT_SECRET: str = []
    REQUEST_TIMEOUT: int = []
    FEISHU_API: str =[] #飞书API
    URLS :list[str]=[]
    USER : str =[]
    PAW : str =[]

    class Config:
        env_file = "../.env"  # 正确指向环境文件路径
        env_file_encoding = 'utf-8'

# 确保实例化对象
settings = Settings()
