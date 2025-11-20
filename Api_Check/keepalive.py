"""保活脚本 - 每天定时发送保活消息到飞书"""
import sys
import os
from dotenv import load_dotenv

load_dotenv()
sys.path.append(os.path.dirname(__file__))

from src import APIMonitor


def main():
    """发送保活通知"""
    print("=" * 60)
    print("API 监控服务 - 保活通知")
    print("=" * 60)

    monitor = APIMonitor()
    success = monitor.send_keepalive_notification()

    if success:
        print("\n保活通知发送成功！")
        sys.exit(0)
    else:
        print("\n保活通知发送失败！")
        sys.exit(1)


if __name__ == "__main__":
    main()
