from typing import Dict, Any
import requests
from .config import settings
from .auth import generate_basic_auth
from requests.exceptions import RequestException
from urllib.parse import urlencode
import datetime
import json
import time
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
            "Content-Type": "multipart/form-data",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36"

        }

    def login(self):
        try:
            start_time = time.time()
            url = f"{self.base_url}{settings.OAUTH_TOKEN_ENDPOINT}"
            data = {
                "grant_type": "password",
                "username": settings.USER,
                "password": settings.PAW,
                "scope": "openid profile"
            }
            headers = self._get_headers()
            data_string= urlencode(data)
            full_url = f"{url}?{data_string}"
            proxies = {
                "http": "http://127.0.0.1:8080",
                "https": "http://127.0.0.1:8080"
            }

            response = requests.post(
                verify=False,
                url=full_url,
                headers=headers,
                timeout=self.timeout,
                #proxies=proxies  # 👈 加代理
            )
            request_duration = time.time() - start_time

            print(response)
            print("响应体:", response.text)
            print(f"请求耗时: {request_duration:.2f}秒")
            response.raise_for_status()
            print("登录服务无异常")
            return None

        except RequestException as e:
            request_duration = time.time() - start_time
            error_info = {
                "error_type": e.__class__.__name__,
                "error_message": str(e),
                "request_url": url,
                "request_data": data,
                "request_headers": headers,
                "timestamp": datetime.datetime.now().isoformat(),
                "request_duration": f"{request_duration:.2f}秒",
            }
            print("请求异常，详细信息如下：")
            print(json.dumps(error_info, indent=2, ensure_ascii=False))
            self.feishusend(error_info)
            return None
    #使用GET方法检查URL是否能正常访问
    def urlcheck(self) :
        for url in settings.URLS:
            max_retries = 3
            retries = 0
            last_exception = None  # 记录最后一次异常
            while retries < max_retries:
                try:
                    # 发起请求并校验状态码
                    response = requests.get(url=url, timeout=self.timeout)
                    response.raise_for_status()
                    break  # 请求成功，退出重试循环
                except RequestException as e:
                    last_exception = e
                    retries += 1
                    if retries < max_retries:
                        # 指数退避：1s, 2s, 4s（可选）
                        time.sleep(2 ** retries)
            # 如果重试3次后仍失败，发送错误报告
            if retries >= max_retries and last_exception:
                error_info = {
                    "error_type": last_exception.__class__.__name__,
                    "error_message": str(last_exception),
                    "request_url": url,
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
        response.raise_for_status()
        print("验证码无异常")
        return None  # 成功时不返回数据
      except RequestException as e:
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
