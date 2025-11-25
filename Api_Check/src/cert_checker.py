"""SSL 证书检查器"""
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse


class CertificateChecker:
    """SSL 证书检查器 - 检查证书有效期、颁发者等信息"""

    def __init__(self, warning_days: int = 15, timeout: int = 10):
        """
        初始化证书检查器

        Args:
            warning_days: 提前告警天数（证书到期前N天开始告警）
            timeout: 连接超时时间（秒）
        """
        self.warning_days = warning_days
        self.timeout = timeout

    def check_certificate(self, url: str) -> Dict[str, Any]:
        """
        检查单个 URL 的证书

        Args:
            url: 要检查的 HTTPS URL

        Returns:
            证书检查结果字典:
            {
                "url": "https://example.com",
                "status": "ok" | "warning" | "error",
                "valid_from": "2024-01-01 00:00:00",
                "valid_until": "2025-01-01 00:00:00",
                "days_remaining": 365,
                "issuer": "Let's Encrypt Authority X3",
                "subject": "example.com",
                "chain_valid": True,
                "message": "证书正常"
            }
        """
        try:
            # 1. 解析 URL
            hostname, port = self._extract_hostname(url)

            # 2. 创建 SSL 上下文
            context = ssl.create_default_context()

            # 3. 建立连接并获取证书
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            # 4. 解析证书信息
            return self._parse_certificate(url, cert)

        except ssl.SSLError as e:
            return {
                "url": url,
                "status": "error",
                "message": f"SSL 错误: {e}",
                "chain_valid": False
            }
        except socket.timeout:
            return {
                "url": url,
                "status": "error",
                "message": f"连接超时（{self.timeout}秒）"
            }
        except Exception as e:
            return {
                "url": url,
                "status": "error",
                "message": f"检查失败: {e.__class__.__name__}: {e}"
            }

    def _extract_hostname(self, url: str) -> Tuple[str, int]:
        """
        从 URL 提取主机名和端口

        Args:
            url: 完整 URL（如 https://example.com:8443/path）

        Returns:
            (hostname, port) 元组
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        port = parsed.port or 443
        return hostname, port

    def _parse_certificate(self, url: str, cert: dict) -> Dict[str, Any]:
        """
        解析证书信息

        Args:
            url: 原始 URL
            cert: getpeercert() 返回的证书字典

        Returns:
            格式化的证书信息
        """
        try:
            # 解析有效期
            not_after = cert.get('notAfter')
            not_before = cert.get('notBefore')

            # 转换日期格式：'Jan 1 00:00:00 2025 GMT'
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            start_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')

            # 计算剩余天数
            days_remaining = (expiry_date - datetime.now()).days

            # 提取颁发者和主题
            issuer = self._format_dn(cert.get('issuer', []))
            subject = self._format_dn(cert.get('subject', []))

            # 判断状态
            if days_remaining < 0:
                status = "error"
                message = f"证书已过期 {abs(days_remaining)} 天"
            elif days_remaining <= self.warning_days:
                status = "warning"
                message = f"证书即将过期（剩余 {days_remaining} 天）"
            else:
                status = "ok"
                message = f"证书正常（剩余 {days_remaining} 天）"

            return {
                "url": url,
                "status": status,
                "valid_from": start_date.strftime('%Y-%m-%d %H:%M:%S'),
                "valid_until": expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                "days_remaining": days_remaining,
                "issuer": issuer,
                "subject": subject,
                "chain_valid": True,  # 如果走到这里说明链验证通过
                "message": message
            }

        except Exception as e:
            return {
                "url": url,
                "status": "error",
                "message": f"证书解析失败: {e}",
                "raw_cert": str(cert)[:200]  # 保留部分原始数据用于调试
            }

    def _format_dn(self, dn_tuple: tuple) -> str:
        """
        格式化 Distinguished Name

        Args:
            dn_tuple: 如 (('CN', 'example.com'),)

        Returns:
            格式化字符串: "CN=example.com"
        """
        if not dn_tuple:
            return "N/A"

        parts = []
        for rdn in dn_tuple:
            for attr in rdn:
                parts.append(f"{attr[0]}={attr[1]}")
        return ", ".join(parts)
