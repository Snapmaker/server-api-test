"""API 监控脚本 - 主程序"""
import sys
import os
from dotenv import load_dotenv

load_dotenv()
sys.path.append(os.path.dirname(__file__))

from src import APIMonitor


def main():
    """运行所有监控检查"""
    monitor = APIMonitor()
    monitor.run_all_checks()
    # monitor._print_summary()


if __name__ == "__main__":
    main()

    # 如果需要运行自定义检查，取消下面的注释
    # custom_check_example()
