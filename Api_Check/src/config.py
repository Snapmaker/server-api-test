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
    # 认证凭证（从环境变量读取，不要在这里填写）
    # ============================================
    CLIENT_ID: str
    CLIENT_SECRET: str
    USER: str
    PAW: str
    CN_USER: str
    CN_PAW: str

    # ============================================
    # 设备认证配置（可选，用于设备认证接口检查）
    # ============================================
    DEVICE_SN: str = "SN123456"  # 设备序列号
    DEVICE_PRIVATE_KEY: str = ""  # 设备私钥（Base64 编码的 DER 格式）
    DEVICE_PUBLIC_KEY: str = ""  # 设备公钥（Base64 编码的 DER 格式，用于签名自校验）
    PRODUCT_CODE: str = "U1"  # 产品代码（用于密钥注册激活）
    DEVICE_SECRET_REGISTER_URL: str = "https://n8n.kuaizao.org/webhook/device/secret/register"  # 密钥注册激活接口
    DEVICE_SECRET_CHECK_URL: str = "https://n8n.kuaizao.org/webhook/device/secret/check"  # 密钥签名校验接口

    # ============================================
    # 其他配置
    # ============================================
    REQUEST_TIMEOUT: int = 30
    FEISHU_API: str = "https://open.feishu.cn/open-apis/bot/v2/hook/f97c7ac6-6a24-48e6-af1e-4a1faad95c09"  # 飞书 Webhook，不配置则不发送通知

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'


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
