# 显式导出关键模块
from .config import settings
from .auth import generate_basic_auth
from .user_client import UserClient
__all__ = ['settings', 'generate_basic_auth' , 'UserClient']