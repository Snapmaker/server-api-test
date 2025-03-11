import base64
from typing import Dict, Any
from .config import settings  # 使用相对导入

def generate_basic_auth() -> str:
    """生成当前配置的 Basic Auth"""
    credentials = f"{settings.CLIENT_ID}:{settings.CLIENT_SECRET}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"