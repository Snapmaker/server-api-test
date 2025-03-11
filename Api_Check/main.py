import sys
import os
from dotenv import load_dotenv
load_dotenv()
sys.path.append(os.path.dirname(__file__))  # 添加项目根目录到路径
import json
from src import UserClient, settings


def main():
   # 显示当前配置验证
   #  print(f"当前API端点: {settings.API_BASE_URL}")
   #
    client = UserClient()
    result = client.login()
    # result=client.getcode(username=os.getenv("USER"))
    # client.urlcheck()


if __name__ == "__main__":
    main()