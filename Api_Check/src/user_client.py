from typing import Dict, Any
import requests
from .config import settings
from .auth import generate_basic_auth
from requests.exceptions import RequestException
import datetime
class UserClient:
    def __init__(self):
        self.base_url = settings.API_BASE_URL
        self.timeout = settings.REQUEST_TIMEOUT
        self.feishu_api=settings.FEISHU_API
    # def assert_error(self,result: ):

    #登录头的生成
    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": generate_basic_auth(),
            "Content-Type": "application/x-www-form-urlencoded"

        }
    #登录服务API检查
    def login(self ):

      try:
        response = requests.post(
            verify=False,
            url=f"{self.base_url}{settings.OAUTH_TOKEN_ENDPOINT}",
            data={
                "grant_type": "password",
                "username": settings.USER,
                "password": settings.PAW,
                "scope": "openid profile"
            },
            headers=self._get_headers(),
            timeout=self.timeout
        )
        response.raise_for_status()
        return None
      except RequestException as e:
          error_info ={
              "error_type": e.__class__.__name__,
              "error_message": str(e),
              "request_url": f"{self.base_url}{settings.OAUTH_TOKEN_ENDPOINT}",
              "timestamp": datetime.datetime.now().isoformat()
          }
          self.feishusend(error_info)
          return None

    #使用GET方法检查URL是否能正常访问
    def urlcheck(self) :

        for url in settings.URLS:
         try:
          requests.get(
            url=f"{url}",
            timeout=self.timeout
        )
         except RequestException as e:
          error_info = {
             "error_type": e.__class__.__name__,
             "error_message": str(e),
             "request_url": f"{self.base_url}{settings.OAUTH_TOKEN_ENDPOINT}",
             "timestamp": datetime.datetime.now().isoformat()
         }
          self.feishusend(error_info)


    #使用post方法验证短信验证码服务是否能正常使用
    def getcode(self, username):
      try:
        response = requests.post(
            verify=False,
            url=f"{self.base_url}{settings. VERIFICATION_CODE_ENDPOINT}",

            json={
                "account": username,
                "action": "oauth"
            },
            timeout=self.timeout
        )
        response.raise_for_status()  # 如果状态码非 2xx，抛出 HTTPError
        return None  # 成功时不返回数据
      except RequestException as e:
        # 统一处理所有 requests 异常（超时、连接错误、HTTP 错误等）
        error_info = {
            "error_type": e.__class__.__name__,
            "error_message": str(e),
            "request_url": f"{self.base_url}{settings.VERIFICATION_CODE_ENDPOINT}",
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.feishusend(error_info)
        return None


    def feishusend(self,error_info: Dict[str, Any]= None) :
        message = {
            "msg_type": "text",  # 文本消息类型（或根据需求使用 "interactive"）
            "content": {
                "text": f"⚠️ 系统异常通知 ⚠️\n"
                        f"- 错误类型: {error_info['error_type']}\n"
                        f"- 错误信息: {error_info['error_message']}\n"
                        f"- 请求地址: {error_info['request_url']}\n"
                        f"- 发生时间: {error_info['timestamp']}"
            }

        }
        requests.post(
            verify=False,
            url=f"{self.feishu_api}",
            timeout=10,
            json=message)
        return None
