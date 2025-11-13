"""配置管理"""
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    """环境变量配置"""
    # ============================================
    # API 配置（在这里修改你的 API 地址）
    # ============================================
    API_BASE_URL: str = "https://id.snapmaker.com/api"
    API_CN_BASE_URL: str = "https://api.snapmaker.cn/api/"

    # ============================================
    # 认证凭证（必需，从环境变量读取）
    # ============================================
    CLIENT_ID: str
    CLIENT_SECRET: str
    USER: str
    PAW: str
    CN_USER: str
    CN_PAW: str
    DEVICE_SECRET_REGISTER_URL: str   # 密钥注册激活接口
    DEVICE_SECRET_CHECK_URL: str   # 密钥签名校验接口

    # ============================================
    # 设备认证配置（可选，从环境变量读取）
    # ============================================
    DEVICE_SN: str = "SN12345"  # 设备序列号
    DEVICE_PRIVATE_KEY: str = ""  # 设备私钥（Base64 编码的 DER 格式）
    DEVICE_PUBLIC_KEY: str = ""  # 设备公钥（Base64 编码的 DER 格式，用于签名自校验）
    PRODUCT_CODE: str = "U1"  # 产品代码（用于密钥注册激活）

    # ============================================
    # 其他配置
    # ============================================
    REQUEST_TIMEOUT: int = 30
    FEISHU_API: str = ""  # 飞书 Webhook，不配置则不发送通知

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        case_sensitive = False  # 环境变量不区分大小写
        # 允许从系统环境变量读取，优先级：系统环境变量 > .env 文件 > 默认值
        extra = 'ignore'  # 忽略额外的环境变量


settings = Settings()


# ============================================
# 监控配置（在这里添加或修改监控项）
# ============================================
MONITOR_CONFIG = {
    # API 端点配置（相对路径，会自动拼接 API_BASE_URL）
    "endpoints": {
        "login": "/oauth2/token",
        "verification_code": "/common/accounts/sendVerificationCod",
    },

    # 需要监控的 URL 列表（完整 URL）
    # 👇 在这里添加需要监控的健康检查 URL
    "health_check_urls": [
        "https://www.snapmaker.com/en-US",
        "https://www.snapmaker.cn",
        "https://wiki.snapmaker.com",
        "https://forum.snapmaker.com"

    ],

    # 重试配置
    "retry": {
        "max_retries": 3,
        "retry_delay": 2  # 秒
    }
}
