"""证书检查脚本 - 每天定时检查所有 HTTPS 端点的证书"""
import sys
import os
from dotenv import load_dotenv

load_dotenv()
sys.path.append(os.path.dirname(__file__))

from src import APIMonitor


def main():
    """运行证书检查并发送通知"""
    print("=" * 60)
    print("SSL 证书检查")
    print("=" * 60)

    monitor = APIMonitor()

    # 检查证书检查功能是否启用
    if not monitor.cert_checker:
        print("⚠ 证书检查功能已禁用（CERT_CHECK_ENABLED=False）")
        print("\n证书检查跳过！")
        sys.exit(0)

    # 运行证书检查
    success = monitor.check_certificates()

    if success:
        print("\n证书检查完成！")
        sys.exit(0)
    else:
        print("\n证书检查发现问题！")
        sys.exit(1)


if __name__ == "__main__":
    main()
