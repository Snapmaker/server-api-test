"""简单的 API 监控器"""
import base64
import requests
import time
import datetime
import random
import json
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlencode
from .config import settings, MONITOR_CONFIG
from .cert_checker import CertificateChecker

# ECC 签名相关
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class APIMonitor:
    """API 监控器 - 检查各个服务并发送通知"""

    def __init__(self):
        self.base_url = settings.API_BASE_URL.rstrip('/')
        self.cn_base_url = settings.API_CN_BASE_URL.rstrip('/')
        self.timeout = settings.REQUEST_TIMEOUT
        self.config = MONITOR_CONFIG
        self.results = []  # 存储所有检查结果
        self.privatekey = None  # ECC 私钥
        self.publickey = None  # ECC 公钥
        self.key_registration_status = None  # 密钥注册状态: None/pending/registered/failed
        self.sn = settings.DEVICE_SN  # 设备序列号
        self.product_code = settings.PRODUCT_CODE  # 产品代码
        self.ecc_sign = None  # ECC 签名
        self.params = None  # 签名参数
        self.nonce = None  # 随机数

        # 初始化证书检查器
        if settings.CERT_CHECK_ENABLED:
            self.cert_checker = CertificateChecker(
                warning_days=settings.CERT_EXPIRY_WARNING_DAYS,
                timeout=self.config['certificate']['timeout']
            )
        else:
            self.cert_checker = None

    # ==================== 辅助方法 ====================

    def _get_verify_param(self):
        """
        获取 requests 的 verify 参数

        根据配置返回合适的 SSL 验证参数:
        - False: 禁用 SSL 验证（兼容自签名证书）
        - True: 启用 SSL 验证（使用 certifi CA 证书包）
        - str: 自定义 CA 证书路径

        Returns:
            verify 参数值
        """
        # 如果禁用 SSL 验证，直接返回 False
        if not settings.ENABLE_SSL_VERIFY:
            return False

        # 如果配置了自定义 CA 证书路径，使用自定义证书
        if settings.SSL_CERT_PATH:
            import os
            if os.path.exists(settings.SSL_CERT_PATH):
                return settings.SSL_CERT_PATH
            else:
                print(f"⚠ 自定义 CA 证书不存在: {settings.SSL_CERT_PATH}")
                print("  降级为使用默认 CA 证书")

        # 尝试使用 certifi 提供的 CA 证书包
        try:
            import certifi
            return certifi.where()
        except ImportError:
            print("⚠ certifi 库未安装，使用系统默认 CA 证书")
            return True

    def _generate_basic_auth(self) -> str:
        """生成 Basic Auth"""
        credentials = f"{settings.CLIENT_ID}:{settings.CLIENT_SECRET}"
        return f"Basic {base64.b64encode(credentials.encode()).decode()}"

    def _retry_request(self, func, *args, retry_on_status_codes=[500, 502, 503, 504], max_retries_override=None, **kwargs):
        """
        重试请求辅助方法

        Args:
            func: 要执行的函数
            retry_on_status_codes: 需要重试的HTTP状态码列表
            max_retries_override: 自定义最大重试次数（优先级高于配置文件）
            *args, **kwargs: 传递给func的参数

        Returns:
            函数执行结果和重试次数的元组 (result, retry_count)
        """
        max_retries = max_retries_override if max_retries_override is not None else self.config['retry']['max_retries']
        retry_delay = self.config['retry']['retry_delay']

        for attempt in range(max_retries):
            try:
                result = func(*args, **kwargs)
                return result, attempt  # 成功，返回结果和重试次数
            except requests.exceptions.Timeout as e:
                if attempt < max_retries - 1:
                    print(f"  ⚠ 请求超时，{retry_delay}秒后重试 ({attempt + 1}/{max_retries})")
                    time.sleep(retry_delay)
                    continue
                else:
                    raise  # 最后一次重试失败，抛出异常
            except requests.exceptions.ConnectionError as e:
                if attempt < max_retries - 1:
                    print(f"  ⚠ 连接错误，{retry_delay}秒后重试 ({attempt + 1}/{max_retries})")
                    time.sleep(retry_delay)
                    continue
                else:
                    raise
            except requests.exceptions.HTTPError as e:
                # 检查是否是可重试的状态码
                if hasattr(e, 'response') and e.response.status_code in retry_on_status_codes:
                    if attempt < max_retries - 1:
                        print(f"  ⚠ HTTP {e.response.status_code}错误，{retry_delay}秒后重试 ({attempt + 1}/{max_retries})")
                        time.sleep(retry_delay)
                        continue
                raise  # 不可重试的HTTP错误或最后一次重试失败
            except Exception as e:
                # 其他异常不重试，直接抛出
                raise

        # 理论上不应该到这里
        return None, max_retries

    def _safe_json_parse(self, response, context: str = ""):
        """
        安全地解析JSON响应，并在失败时自动重试

        Args:
            response: requests.Response 对象
            context: 上下文描述，用于日志记录（如 "密钥注册"）

        Returns:
            tuple: (json_data, error_info)
                - 成功时: (parsed_json, None)
                - 失败时: (None, error_dict)
        """
        max_json_retries = 2  # JSON解析失败额外重试次数
        retry_delay = 1  # JSON解析重试延迟（秒）

        for attempt in range(max_json_retries + 1):
            try:
                json_data = response.json()
                if attempt > 0:
                    print(f"  ✓ JSON解析在第{attempt + 1}次尝试后成功")
                return json_data, None

            except requests.exceptions.JSONDecodeError as e:
                # 记录详细的JSON解析错误信息
                error_detail = {
                    "error": "JSONDecodeError",
                    "message": str(e),
                    "response_text": response.text[:500] if response.text else "(empty)",
                    "content_type": response.headers.get('Content-Type', 'unknown'),
                    "http_status": response.status_code,
                    "context": context
                }

                if attempt < max_json_retries:
                    # 还有重试机会，等待后重新发起请求
                    print(f"  ⚠ JSON解析失败 ({context})，{retry_delay}秒后重试 ({attempt + 1}/{max_json_retries + 1})")
                    print(f"    Content-Type: {error_detail['content_type']}")
                    print(f"    响应内容预览: {error_detail['response_text'][:100]}...")
                    time.sleep(retry_delay)
                    continue
                else:
                    # 所有重试都失败
                    print(f"  ✗ JSON解析失败 ({context})，已重试{max_json_retries}次")
                    print(f"    HTTP状态码: {response.status_code}")
                    print(f"    Content-Type: {error_detail['content_type']}")
                    print(f"    响应内容: {error_detail['response_text']}")
                    return None, error_detail

        return None, {"error": "UnexpectedError", "message": "JSON解析重试逻辑异常"}

    def _generate_ecc_signature(self, sn: str, private_key_b64: str, public_key_b64: str = None) -> Dict[str, Any]:
        """
        生成 ECC 签名（用于设备认证）

        Args:
            sn: 设备序列号
            private_key_b64: Base64 编码的私钥（DER 格式）
            public_key_b64: Base64 编码的公钥（DER 格式，可选，用于自校验）

        Returns:
            包含签名信息的字典: {'sign': str, 'nonce': int, 'params': str}
            如果失败返回 None
        """
        if not HAS_CRYPTO:
            print("✗ 缺少 cryptography 库，无法生成 ECC 签名")
            print("  请安装: pip install cryptography")
            return None

        try:
            # 1. 加载私钥
            private_bytes = base64.b64decode(private_key_b64)
            private_key = serialization.load_der_private_key(private_bytes, password=None)

            # 2. 生成随机 nonce 并准备签名消息
            nonce = random.randint(100000, 999999)
            params = f"{sn}&nonce={nonce}"
            message_bytes = params.encode('utf-8')

            # 3. 使用 ECDSA (SHA256) 进行签名
            signature = private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )

            # 4. 对签名进行 Base64 编码
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # 5. 如果提供了公钥，进行自校验
            if public_key_b64:
                try:
                    pub_bytes = base64.b64decode(public_key_b64)
                    public_key = serialization.load_der_public_key(pub_bytes)
                    public_key.verify(
                        signature,
                        message_bytes,
                        ec.ECDSA(hashes.SHA256())
                    )
                    print("  ✓ ECC 签名自校验成功")
                except InvalidSignature:
                    print("  ✗ ECC 签名自校验失败")
                    return None

            return {
                'sign': signature_b64,
                'nonce': nonce,
                'params': params,
                'sn': sn
            }

        except Exception as e:
            print(f"  ✗ ECC 签名生成失败: {e}")
            return None

    def get_privatekey(self):
        """生成 ECC 私钥和公钥（使用 secp256r1 曲线）"""
        check_name = "ECC密钥对生成"

        if not HAS_CRYPTO:
            error_msg = "缺少 cryptography 库，无法生成 ECC 密钥对"
            print(f"✗ {error_msg}")
            print("  请安装: pip install cryptography")
            error_info = {
                "type": "DependencyError",
                "message": error_msg,
                "url": "N/A",
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

        try:
            from loguru import logger
        except ImportError:
            logger = None

        try:
            # 生成 ECC 私钥（使用 secp256r1 曲线）
            private_key = ec.generate_private_key(ec.SECP256R1())
            # 获取公钥
            public_key = private_key.public_key()

            # 序列化私钥为 PKCS#8 DER 格式（标准格式）
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # 序列化公钥为 X.509 DER 格式（适用于 Java KeyFactory 的 PublicKey）
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Base64 编码
            self.privatekey = base64.b64encode(private_bytes).decode()
            self.publickey = base64.b64encode(public_bytes).decode()
            self.key_registration_status = "pending"  # 新生成的密钥，待注册

            print("✓ ECC 密钥对生成成功")
            print(f"  SN: {self.sn}")
            print(f"  公钥: {self.publickey[:50]}...")
            print(f"  注册状态: {self.key_registration_status}")

            # 使用 logger 记录日志（如果可用）
            if logger:
                logger.debug(f"签名需要生成并且通过接口激活")
            else:
                print("  ⚠ loguru 库未安装，跳过详细日志记录")

            return True

        except ImportError:
            print("✗ 需要安装 loguru 库")
            print("  私钥和公钥已生成，但无法记录日志")
            return True
        except Exception as e:
            error_msg = f"ECC 密钥对生成失败: {e}"
            print(f"✗ {error_msg}")
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": "N/A",
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def ecc_action(self):
        """激活注册密钥（需要先调用 get_privatekey() 生成密钥）"""
        check_name = "密钥注册激活"
        url = settings.DEVICE_SECRET_REGISTER_URL

        # 检查必需参数
        if not self.sn or not self.privatekey or not self.publickey:
            error_msg = f"密钥注册失败：缺少必要参数 ({self.sn}, {self.privatekey}, {self.publickey})"
            print(f"✗ {error_msg}")
            error_info = {
                "type": "ParameterError",
                "message": error_msg,
                "url": url,
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

        if not self.product_code:
            error_msg = "密钥注册失败：缺少 product_code"
            print(f"✗ {error_msg}")
            print("  请在配置文件中设置 PRODUCT_CODE 或手动设置 monitor.product_code")
            error_info = {
                "type": "ConfigError",
                "message": error_msg,
                "url": url,
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

        try:
            from loguru import logger
        except ImportError:
            logger = None

        try:
            start_time = time.time()

            data = {
                "productCode": self.product_code,
                "devices": [
                    {
                        "sn": self.sn,
                        "private": self.privatekey,
                        "public": self.publickey
                    },
                ]
            }

            # 定义请求函数用于重试
            def make_request():
                return requests.request(method="POST", url=url, json=data, timeout=self.timeout, verify=self._get_verify_param())

            # 使用加强的重试机制（5次重试）
            print(f"  发送密钥注册请求: {url}")
            print(f"  ℹ 关键API - 使用加强重试策略（最多5次）")
            response, retry_count = self._retry_request(make_request, max_retries_override=5)
            duration = time.time() - start_time

            if retry_count > 0:
                print(f"  ℹ 经过 {retry_count} 次重试后成功")

            # 使用安全JSON解析
            rq_json, json_error = self._safe_json_parse(response, "密钥注册")

            # 如果JSON解析失败
            if json_error:
                error_info = {
                    "type": "ResponseParseError",
                    "message": f"服务器返回了非JSON响应: {json_error.get('message', 'Unknown')}",
                    "http_status": json_error.get('http_status', response.status_code),
                    "response_body": json_error.get('response_text', ''),
                    "content_type": json_error.get('content_type', 'unknown'),
                    "url": url,
                    "duration": duration,
                    "retry_count": retry_count,
                    "severity": "WARNING"  # 临时错误
                }
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

            if rq_json.get('code') == 200:
                self.key_registration_status = "registered"  # 标记为已注册
                if logger:
                    logger.info("密钥注册成功")
                    logger.debug(f"设备sn: {self.sn}, 设备私钥：{self.privatekey}")
                print("✓ 密钥注册成功")
                print(f"  注册状态: {self.key_registration_status}")
                return True
            else:
                self.key_registration_status = "failed"  # 标记为注册失败，保留密钥以便重试
                error_msg = rq_json.get('message', rq_json.get('msg', '未知错误'))
                error_code = rq_json.get('code', 'N/A')
                if logger:
                    logger.info("密钥注册失败")
                    logger.info(rq_json)
                print(f"✗ 密钥注册失败 [code: {error_code}]: {error_msg}")
                print(f"  注册状态: {self.key_registration_status} (密钥已保留，下次运行将重试注册)")
                error_info = {
                    "type": "BusinessError",
                    "message": f"{error_msg} (密钥已保留，下次将重试)",
                    "http_status": response.status_code,
                    "error_code": error_code,
                    "response_body": rq_json,
                    "url": url,
                    "duration": duration,
                    "retry_count": retry_count,
                    "severity": "ERROR"  # 业务错误，需人工介入
                }
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

        except ImportError:
            print("✗ 需要安装 loguru 库")
            print("  密钥注册请求已发送，但无法记录日志")
            return False
        except Exception as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0
            error_msg = f"密钥注册过程出错: {e}"
            print(f"✗ {error_msg}")

            # 构建详细错误信息
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url,
                "duration": duration
            }

            # 如果是HTTP错误，添加状态码和响应信息
            if isinstance(e, requests.exceptions.HTTPError) and hasattr(e, 'response'):
                error_info["http_status"] = e.response.status_code
                try:
                    error_info["response_body"] = e.response.json()
                    error_info["error_code"] = e.response.json().get('code', 'N/A')
                except:
                    error_info["response_body"] = e.response.text

            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def chack_private_key(self):
        """通过 webhook 校验签名"""
        check_name = "签名校验"
        url = settings.DEVICE_SECRET_CHECK_URL

        if not HAS_CRYPTO:
            error_msg = "缺少 cryptography 库，无法校验签名"
            print(f"✗ {error_msg}")
            error_info = {
                "type": "DependencyError",
                "message": error_msg,
                "url": url,
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

        # 检查必需参数
        if not self.sn or not self.privatekey:
            error_msg = "校验失败：缺少设备序列号或私钥"
            error_info = {
                "type": "ParameterError",
                "message": error_msg,
                "url": url,
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

        try:
            from loguru import logger
        except ImportError:
            logger = None

        try:
            start_time = time.time()

            # 生成签名
            sign_data = self._generate_ecc_signature(self.sn, self.privatekey, self.publickey)
            if not sign_data:
                error_msg = "签名生成失败"
                print(f"✗ {error_msg}")
                error_info = {
                    "type": "SignatureError",
                    "message": error_msg,
                    "url": url,
                    "duration": time.time() - start_time
                }
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

            # 保存签名和参数到实例变量
            self.ecc_sign = sign_data['sign']
            self.params = sign_data['params']
            self.nonce = sign_data['nonce']

            # 调用 webhook 校验接口
            data = {
                "sn": self.sn,
                "sign": self.ecc_sign,
                "params": self.params,
            }

            # 定义请求函数用于重试
            def make_request():
                return requests.request(method="POST", url=url, json=data, timeout=self.timeout, verify=self._get_verify_param())

            # 使用加强的重试机制（5次重试）
            print(f"  发送签名校验请求: {url}")
            print(f"  ℹ 关键API - 使用加强重试策略（最多5次）")
            response, retry_count = self._retry_request(make_request, max_retries_override=5)
            duration = time.time() - start_time

            if retry_count > 0:
                print(f"  ℹ 经过 {retry_count} 次重试后成功")

            # 使用安全JSON解析
            rq_json, json_error = self._safe_json_parse(response, "签名校验")

            # 如果JSON解析失败
            if json_error:
                error_info = {
                    "type": "ResponseParseError",
                    "message": f"服务器返回了非JSON响应: {json_error.get('message', 'Unknown')}",
                    "http_status": json_error.get('http_status', response.status_code),
                    "response_body": json_error.get('response_text', ''),
                    "content_type": json_error.get('content_type', 'unknown'),
                    "url": url,
                    "duration": duration,
                    "retry_count": retry_count,
                    "severity": "WARNING"  # 临时错误
                }
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

            if rq_json.get('code') == 200:
                if logger:
                    logger.info("验证通过")
                print("✓ 签名校验通过")
                return True
            else:
                error_msg = rq_json.get('message', rq_json.get('msg', '未知错误'))
                error_code = rq_json.get('code', 'N/A')
                if logger:
                    logger.info("校验失败")
                print(f"✗ 签名校验失败 [code: {error_code}]: {error_msg}")
                error_info = {
                    "type": "BusinessError",
                    "message": error_msg,
                    "http_status": response.status_code,
                    "error_code": error_code,
                    "response_body": rq_json,
                    "url": url,
                    "duration": duration,
                    "retry_count": retry_count,
                    "severity": "ERROR"  # 业务错误，需人工介入
                }
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

        except ImportError:
            error_msg = "需要安装 loguru 库"
            print(f"✗ {error_msg}")
            error_info = {
                "type": "DependencyError",
                "message": error_msg,
                "url": url,
                "duration": 0
            }
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False
        except Exception as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0
            error_msg = f"签名校验过程出错: {e}"
            print(f"✗ {error_msg}")

            # 构建详细错误信息
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url,
                "duration": duration
            }

            # 如果是HTTP错误，添加状态码和响应信息
            if isinstance(e, requests.exceptions.HTTPError) and hasattr(e, 'response'):
                error_info["http_status"] = e.response.status_code
                try:
                    error_info["response_body"] = e.response.json()
                    error_info["error_code"] = e.response.json().get('code', 'N/A')
                except:
                    error_info["response_body"] = e.response.text

            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def _build_error_detail(self, url: str, error_type: str, error_message: str,
                            http_status: Any = "N/A", error_code: Any = "N/A",
                            response_body: Any = "", retry_count: int = 0,
                            duration: float = 0) -> Dict[str, Any]:
        """构建标准化错误详情"""
        return {
            "region": "国际区域" if "snapmaker.com" in url else "国内区域",
            "url": url,
            "error_type": error_type,
            "error_message": error_message,
            "http_status": http_status,
            "error_code": error_code,
            "response_body": response_body,
            "retry_count": retry_count,
            "duration": duration
        }

    def device_token_auth(self,url) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """设备 Token 认证（向 OAuth2 端点请求设备 token）"""
        check_name = "设备Token认证"

        try:
            from loguru import logger
        except ImportError:
            logger = None

        # 检查必需参数
        if not self.sn or not self.ecc_sign or not self.nonce:
            error_msg = "设备Token认证失败：缺少必要参数 (sn, ecc_sign, nonce)"
            print(f"✗ {error_msg}")
            error_detail = self._build_error_detail(
                url=f"{self.base_url}/oauth2/token" if 'url' not in locals() else url,
                error_type="ParameterError",
                error_message=error_msg
            )
            return False, error_detail

        try:
            start_time = time.time()

            # 构建请求参数
            url = url

            params = {
                "grant_type": "snapmaker_device",
                "sign": self.ecc_sign,
                "scope": "mqtt",
                "sn": self.sn,
                "nonce": str(self.nonce),  # 转换为字符串
                "refresh": "false"
            }

            headers = {
                "Authorization": self._generate_basic_auth(),
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            if logger:
                logger.debug(f"请求 URL: {url}")
                logger.debug(f"请求参数: {params}")
                logger.debug(f"请求头: {headers}")

            # 定义请求函数用于重试
            def make_request():
                return requests.post(
                    url=url,
                    data=params,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self._get_verify_param()
                )

            # 使用重试机制
            print(f"  发送设备Token认证请求: {url}")
            response, retry_count = self._retry_request(make_request)
            duration = time.time() - start_time

            if retry_count > 0:
                print(f"  ℹ 经过 {retry_count} 次重试后成功")

            # 使用安全JSON解析
            resp_json, json_error = self._safe_json_parse(response, "设备Token认证")

            # 如果JSON解析失败
            if json_error:
                error_detail = self._build_error_detail(
                    url=url,
                    error_type="ResponseParseError",
                    error_message=f"服务器返回了非JSON响应: {json_error.get('message', 'Unknown')}",
                    http_status=json_error.get('http_status', response.status_code),
                    response_body=json_error.get('response_text', ''),
                    retry_count=retry_count,
                    duration=duration
                )
                return False, error_detail

            # print(f"  响应状态码: {response.status_code}")
            # print(f"  响应内容: {resp_json}")

            if logger:
                logger.debug(f"响应数据: {resp_json}")

            # 检查业务返回码
            if resp_json.get('code') == 200:
                if logger:
                    logger.info(f"成功获取Token，HTTP状态码: {response.status_code}")
                print(f"✓ 设备Token认证成功 {url}")
                print(f"  Access Token: {resp_json.get('data', {}).get('access_token', 'N/A')[:50]}...")
                return True, None
            else:
                error_msg = resp_json.get('message', resp_json.get('msg', '未知错误'))
                error_code = resp_json.get('code', 'N/A')
                if logger:
                    logger.error(f"设备Token认证失败: {error_msg}")
                print(f"✗ 设备Token认证失败 [code: {error_code}]: {error_msg}")
                error_detail = self._build_error_detail(
                    url=url,
                    error_type="BusinessError",
                    error_message=error_msg,
                    http_status=response.status_code,
                    error_code=error_code,
                    response_body=resp_json,
                    retry_count=retry_count,
                    duration=duration
                )
                return False, error_detail

        except requests.exceptions.HTTPError as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0
            error_msg = f"HTTP错误: {e}"
            print(f"✗ {error_msg}")

            error_info = {
                "type": "HTTPError",
                "message": str(e),
                "url": url if 'url' in locals() else 'N/A',
                "duration": duration
            }

            if hasattr(e, 'response'):
                error_info["http_status"] = e.response.status_code
                try:
                    error_info["response_body"] = e.response.json()
                    error_info["error_code"] = e.response.json().get('code', 'N/A')
                except:
                    error_info["response_body"] = e.response.text

            error_detail = self._build_error_detail(
                url=error_info.get("url", "N/A"),
                error_type="HTTPError",
                error_message=str(e),
                http_status=error_info.get("http_status", "N/A"),
                error_code=error_info.get("error_code", "N/A"),
                response_body=error_info.get("response_body", ""),
                duration=error_info.get("duration", 0)
            )
            return False, error_detail
        except Exception as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0
            error_msg = f"设备Token认证过程出错: {e}"
            print(f"✗ {error_msg}")

            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url if 'url' in locals() else 'N/A',
                "duration": duration
            }

            # 如果是HTTP相关错误，尝试获取更多信息
            if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response') and e.response is not None:
                error_info["http_status"] = e.response.status_code
                try:
                    error_info["response_body"] = e.response.json()
                    error_info["error_code"] = e.response.json().get('code', 'N/A')
                except:
                    error_info["response_body"] = e.response.text

            error_detail = self._build_error_detail(
                url=error_info.get("url", "N/A"),
                error_type=error_info.get("type", "UnknownError"),
                error_message=error_info.get("message", str(e)),
                http_status=error_info.get("http_status", "N/A"),
                error_code=error_info.get("error_code", "N/A"),
                response_body=error_info.get("response_body", ""),
                duration=error_info.get("duration", 0)
            )
            return False, error_detail

    def _send_feishu_notification(self, message: str,feishu_url=settings.FEISHU_API):
        """发送飞书通知"""
        if not feishu_url:
            print("⚠ 未配置飞书 Webhook，跳过通知")
            return

        try:
            requests.post(
                url=feishu_url,
                json={"msg_type": "text", "content": {"text": message}},
                timeout=10,
                verify=False
            )
            print("✓ 飞书通知已发送")
        except Exception as e:
            print(f"✗ 飞书通知发送失败: {e}")

    def send_keepalive_notification(self):
        """发送保活通知（每天定时发送，证明服务正常运行）"""
        if not settings.FEISHU_API:
            print("⚠ 未配置飞书 Webhook，无法发送保活消息")
            return False

        try:
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message = (
                f"🟢 API监控服务保活通知\n"
                f"- 服务状态: 正常运行中\n"
                f"- 当前时间: {current_time}\n"
                f"- 监控地址: {self.base_url}\n"
                f"- 检测区域: {settings.CHECK_REGION}\n"
                f"✅ 系统运行正常，持续为您服务"
            )

            requests.post(
                url=settings.FEISHU_API,
                json={"msg_type": "text", "content": {"text": message}},
                timeout=10,
                verify=False
            )
            print("✓ 保活通知已发送")
            return True
        except Exception as e:
            print(f"✗ 保活通知发送失败: {e}")
            return False

    def _format_error_notification(self, check_name: str, error_info: Dict) -> str:
        """格式化错误通知消息"""
        # 根据严重级别设置告警图标
        severity = error_info.get('severity', 'ERROR')
        if severity == 'WARNING':
            alert_icon = "⚠️"
            severity_text = "警告 (临时错误，可能自动恢复)"
        else:
            alert_icon = "🔴"
            severity_text = "错误 (需人工介入)"

        notification = (
            f"{alert_icon} API 监控告警 {alert_icon}\n"
            f"- 严重级别: {severity_text}\n"
            f"- 检查项: {check_name}\n"
            f"- 错误类型: {error_info.get('type', 'Unknown')}\n"
            f"- 错误信息: {error_info.get('message', 'Unknown')}\n"
        )

        # 添加HTTP状态码（如果有）
        if 'http_status' in error_info:
            notification += f"- HTTP状态码: {error_info['http_status']}\n"

        # 添加业务错误码（如果有）
        if 'error_code' in error_info:
            notification += f"- 业务错误码: {error_info['error_code']}\n"

        # 添加Content-Type（如果有）
        if 'content_type' in error_info:
            notification += f"- Content-Type: {error_info['content_type']}\n"

        # 添加响应内容（如果有）
        if 'response_body' in error_info:
            response_str = str(error_info['response_body'])
            # 限制响应内容长度，避免通知过长
            if len(response_str) > 500:
                response_str = response_str[:500] + "..."
            notification += f"- 响应内容: {response_str}\n"

        notification += (
            f"- 请求地址: {error_info.get('url', 'N/A')}\n"
            f"- 发生时间: {datetime.datetime.now().isoformat()}\n"
            f"- 请求耗时: {error_info.get('duration', 0):.2f}秒\n"
        )

        # 添加重试信息（如果有）
        if 'retry_count' in error_info:
            notification += f"- 重试次数: {error_info['retry_count']}\n"

        return notification

    def _format_multi_region_error_notification(self, check_name: str, failed_regions: List[Dict]) -> str:
        """
        格式化多区域错误通知消息

        Args:
            check_name: 检查项名称
            failed_regions: 失败区域的详细信息列表

        Returns:
            格式化的飞书通知消息
        """
        notification = (
            f"🔴 API 监控告警 🔴\n"
            f"- 检查项: {check_name}\n"
            f"- 失败区域数: {len(failed_regions)}\n"
            f"- 发生时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        for idx, region_info in enumerate(failed_regions, 1):
            notification += f"【失败区域 {idx}】\n"
            notification += f"- 区域名称: {region_info.get('region', 'Unknown')}\n"
            notification += f"- 请求地址: {region_info.get('url', 'N/A')}\n"
            notification += f"- HTTP状态码: {region_info.get('http_status', 'N/A')}\n"
            notification += f"- 业务错误码: {region_info.get('error_code', 'N/A')}\n"
            notification += f"- 错误类型: {region_info.get('error_type', 'Unknown')}\n"
            notification += f"- 错误信息: {region_info.get('error_message', 'Unknown')}\n"

            # 响应体内容（限制长度避免消息过长）
            response_body = region_info.get('response_body', '')
            if isinstance(response_body, dict):
                response_str = json.dumps(response_body, ensure_ascii=False)
            else:
                response_str = str(response_body)

            if len(response_str) > 500:
                response_str = response_str[:500] + "...(已截断)"
            notification += f"- 响应内容: {response_str}\n"

            notification += f"- 重试次数: {region_info.get('retry_count', 0)}\n"
            notification += f"- 请求耗时: {region_info.get('duration', 0):.2f}秒\n\n"

        return notification

    def _log_result(self, check_name: str, success: bool, details: str = ""):
        """记录检查结果"""
        result = {
            "check": check_name,
            "success": success,
            "details": details,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.results.append(result)

        status = "✓" if success else "✗"
        print(f"{status} {check_name}: {details}")

    # ==================== 检查方法 ====================

    def check_login(self,check_name,url_type) -> bool:
        """检查登录服务"""
        check_name = check_name
        try:
            start_time = time.time()
            if url_type=="cn":
            # 拼接完整 URL
                endpoint = self.config['endpoints']['login']
                url = f"{self.cn_base_url}{endpoint}"
                data = urlencode({
                    "grant_type": "password",
                    "username": settings.CN_USER,
                    "password": settings.CN_PAW,
                    "scope": "openid profile"
                })
            else:
                endpoint = self.config['endpoints']['login']
                url = f"{self.base_url}{endpoint}"
                data = urlencode({
                    "grant_type": "password",
                    "username": settings.USER,
                    "password": settings.PAW,
                    "scope": "openid profile"
                })
            full_url = f"{url}?{data}"

            headers = {
                "Authorization": self._generate_basic_auth(),
                "Content-Type": "multipart/form-data",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            # 发送请求
            response = requests.post(
                url=full_url,
                headers=headers,
                timeout=self.timeout,
                verify=self._get_verify_param()
            )
            duration = time.time() - start_time

            response.raise_for_status()
            self._log_result(check_name, True, f"正常 (耗时 {duration:.2f}秒)")
            return True

        except Exception as e:
            duration = time.time() - start_time
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url,
                "duration": duration
            }
            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def check_verification_code(self, account: str = None) -> bool:
        """检查验证码服务"""
        check_name = "验证码服务"
        try:
            start_time = time.time()

            # 拼接完整 URL
            endpoint = self.config['endpoints']['verification_code']
            url = f"{self.base_url}{endpoint}"
            account = account or settings.USER

            # 发送请求
            response = requests.post(
                url=url,
                json={"account": account, "action": "oauth"},
                timeout=self.timeout,
                verify=self._get_verify_param()
            )
            duration = time.time() - start_time

            response.raise_for_status()
            self._log_result(check_name, True, f"正常 (耗时 {duration:.2f}秒)")
            return True

        except Exception as e:
            duration = time.time() - start_time
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url,
                "duration": duration
            }
            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def check_device_auth(self, sn: str = None, private_key: str = None, public_key: str = None) -> bool:
        """
        检查设备认证服务（密钥注册和签名校验）

        包含：
        1. ECC 密钥对生成
        2. 密钥注册激活
        3. Webhook 签名校验

        注意：不包含设备 Token 认证，Token 认证已拆分到 check_device_token_auth() 方法

        Args:
            sn: 设备序列号，默认使用配置中的 DEVICE_SN
            private_key: 设备私钥（Base64），默认使用配置中的 DEVICE_PRIVATE_KEY
            public_key: 设备公钥（Base64），默认使用配置中的 DEVICE_PUBLIC_KEY

        Returns:
            检查是否成功
        """
        check_name = "设备密钥注册服务"
        url=""
        try:
            start_time = time.time()
            key_generated = False  # 标记是否生成了新密钥

            # 1. 设置设备序列号
            if sn:
                self.sn = sn

            if not self.sn:
                print("⚠ 设备认证检查已跳过（未配置 DEVICE_SN）")
                return True  # 返回 True 避免影响整体检查结果

            # 2. 检查是否提供了现有密钥
            if private_key and public_key:
                # 使用提供的密钥
                self.privatekey = private_key
                self.publickey = public_key
                self.key_registration_status = "registered"  # 假设外部提供的密钥已注册
                print("  使用提供的密钥对")
            elif self.privatekey and self.publickey:
                # 使用实例变量中已有的密钥
                print("  使用已生成的密钥对")
                print(f"  当前注册状态: {self.key_registration_status}")
            else:
                # 没有密钥，需要生成新的密钥对
                print("  未找到密钥对，正在生成新的 ECC 密钥对...")
                if not self.get_privatekey():
                    raise Exception("密钥对生成失败")
                key_generated = True

            # 3. 检查密钥注册状态并决定是否需要注册
            needs_registration = False
            if key_generated:
                print("  检测到新生成的密钥，需要注册激活")
                needs_registration = True
            elif self.key_registration_status == "failed":
                print("  检测到上次注册失败的密钥，将重试注册")
                needs_registration = True
            elif self.key_registration_status == "pending":
                print("  检测到待注册的密钥，需要注册激活")
                needs_registration = True

            # 4. 执行密钥注册
            if needs_registration:
                print("  开始密钥注册激活...")
                if not self.ecc_action():
                    url=settings.DEVICE_SECRET_REGISTER_URL
                    raise Exception("密钥注册激活失败 (密钥已保留，可下次重试)")

            # 5. 调用 webhook 校验签名
            print("  开始 webhook 签名校验...")
            if not self.chack_private_key():
                url = settings.DEVICE_SECRET_CHECK_URL
                raise Exception("Webhook 签名校验失败")

            # 6. 设备 Token 认证
            # print("  开始设备密钥校验...")
            # url=f"{self.base_url}{self.config['endpoints']['login']}"
            # url_cn = f"{self.cn_base_url}{self.config['endpoints']['login']}"
            # check_region = settings.CHECK_REGION.lower()
            #
            # auth_failed = False
            # if check_region in ["intl", "both"]:
            #     if not self.device_token_auth(url):
            #         auth_failed = True
            # if check_region in ["cn", "both"]:
            #     if not self.device_token_auth(url_cn):
            #         auth_failed = True
            # if auth_failed:
            #     raise Exception("设备Token认证失败"
            duration = time.time() - start_time
            self._log_result(check_name, True, f"正常 (耗时 {duration:.2f}秒)")
            return True
        except Exception as e:
            duration = time.time() - start_time
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url,
                "duration": duration
            }
            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False

    def check_device_token_auth(self) -> bool:
        """
        检查设备 Token 认证服务

        前置条件：需要先执行 check_device_auth() 确保密钥已注册和签名已生成

        Returns:
            检查是否成功
        """
        check_name = "设备Token认证服务"

        # 检查前置条件
        if not self.sn or not self.ecc_sign or not self.nonce:
            error_msg = "设备Token认证失败：缺少必要参数 (sn, ecc_sign, nonce)"
            print(f"⚠ {error_msg}")
            print("  提示：请先执行设备认证服务检查")
            return True  # 返回 True 避免影响整体检查结果

        try:
            start_time = time.time()
            print("  开始设备Token认证...")

            # 构建 URL
            url = f"{self.base_url}{self.config['endpoints']['login']}"
            url_cn = f"{self.cn_base_url}{self.config['endpoints']['login']}"
            check_region = settings.CHECK_REGION.lower()

            failed_regions = []  # 收集所有失败区域的详细信息

            # 检查国际区域
            if check_region in ["intl", "both"]:
                print(f"  检查国际区域: {url}")
                success, error_detail = self.device_token_auth(url)
                if not success:
                    failed_regions.append(error_detail)

            # 检查国内区域
            if check_region in ["cn", "both"]:
                print(f"  检查国内区域: {url_cn}")
                success, error_detail = self.device_token_auth(url_cn)
                if not success:
                    failed_regions.append(error_detail)

            duration = time.time() - start_time

            if failed_regions:
                self._log_result(check_name, False,
                                f"部分/全部区域认证失败 ({len(failed_regions)}个区域，耗时 {duration:.2f}秒)")
                self._send_feishu_notification(
                    self._format_multi_region_error_notification(check_name, failed_regions)
                )
                return False
            else:
                self._log_result(check_name, True, f"所有区域认证成功 (耗时 {duration:.2f}秒)")
                return True

        except Exception as e:
            duration = time.time() - start_time if 'start_time' in locals() else 0
            error_msg = f"设备Token认证过程出错: {e}"
            print(f"✗ {error_msg}")

            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": url if 'url' in locals() else 'N/A',
                "duration": duration
            }

            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(
                self._format_error_notification(check_name, error_info)
            )
            return False

    def check_url(self, url: str, retry: bool = True) -> bool:
        """检查单个 URL"""
        check_name = f"URL检查: {url}"
        max_retries = self.config['retry']['max_retries'] if retry else 1
        retry_delay = self.config['retry']['retry_delay']

        for attempt in range(max_retries):
            try:
                start_time = time.time()
                response = requests.get(url=url, timeout=self.timeout, verify=self._get_verify_param())
                duration = time.time() - start_time

                response.raise_for_status()
                self._log_result(check_name, True, f"正常 (耗时 {duration:.2f}秒)")
                return True

            except Exception as e:
                duration = time.time() - start_time

                # 如果还有重试机会，等待后继续
                if attempt < max_retries - 1:
                    print(f"  ⚠ 失败，{retry_delay}秒后重试 ({attempt + 1}/{max_retries})")
                    time.sleep(retry_delay)
                    continue

                # 所有重试都失败
                error_info = {
                    "type": e.__class__.__name__,
                    "message": str(e),
                    "url": url,
                    "duration": duration
                }
                self._log_result(check_name, False, f"失败 (已重试{max_retries}次)")
                self._send_feishu_notification(self._format_error_notification(check_name, error_info))
                return False

        return False

    def check_health_urls(self) -> int:
        """检查所有健康检查 URL"""
        urls = self.config['health_check_urls']
        if not urls:
            print("⚠ 没有配置健康检查 URL")
            return 0

        print(f"\n开始检查 {len(urls)} 个健康检查 URL...")
        success_count = 0

        for url in urls:
            if self.check_url(url):
                success_count += 1

        return success_count

    def _collect_https_urls(self) -> list:
        """
        收集所有需要检查证书的 HTTPS URL

        Returns:
            HTTPS URL 列表（去重）
        """
        urls = set()

        # 1. API 基础地址
        if self.base_url.startswith('https://'):
            urls.add(self.base_url)
        if self.cn_base_url.startswith('https://'):
            urls.add(self.cn_base_url)

        # 2. 健康检查 URL
        for url in self.config.get('health_check_urls', []):
            if url.startswith('https://'):
                urls.add(url)

        # 3. 设备认证 URL
        if settings.DEVICE_SECRET_REGISTER_URL.startswith('https://'):
            urls.add(settings.DEVICE_SECRET_REGISTER_URL)
        if settings.DEVICE_SECRET_CHECK_URL.startswith('https://'):
            urls.add(settings.DEVICE_SECRET_CHECK_URL)

        return sorted(list(urls))

    def check_certificates(self) -> bool:
        """
        检查所有 HTTPS 端点的证书

        Returns:
            检查是否全部通过
        """
        check_name = "SSL证书检查"

        if not self.cert_checker:
            print("⚠ 证书检查功能已禁用（CERT_CHECK_ENABLED=False）")
            return True

        try:
            start_time = time.time()

            # 1. 收集所有 HTTPS URL
            urls = self._collect_https_urls()
            if not urls:
                print("  未发现 HTTPS 端点，跳过证书检查")
                return True

            print(f"  检查 {len(urls)} 个 HTTPS 端点的证书...")

            # 2. 逐一检查证书
            results = []
            for url in urls:
                print(f"  检查: {url}")
                result = self.cert_checker.check_certificate(url)
                results.append(result)

                # 实时输出结果
                status_icon = {
                    'ok': '✓',
                    'warning': '⚠',
                    'error': '✗'
                }.get(result['status'], '?')
                print(f"    {status_icon} {result.get('message', 'Unknown')}")

            duration = time.time() - start_time

            # 3. 统计结果
            ok_count = sum(1 for r in results if r['status'] == 'ok')
            warning_count = sum(1 for r in results if r['status'] == 'warning')
            error_count = sum(1 for r in results if r['status'] == 'error')

            # 4. 判断整体状态
            if error_count > 0:
                self._log_result(check_name, False,
                               f"发现 {error_count} 个错误，{warning_count} 个警告 (耗时 {duration:.2f}秒)")
                # 发送通知
                self._send_feishu_notification(
                    self._format_cert_notification(results, "error"),feishu_url=settings.FEISHU_CERT_API
                )
                return False
            elif warning_count > 0:
                self._log_result(check_name, True,
                               f"发现 {warning_count} 个警告 (耗时 {duration:.2f}秒)")
                # 发送警告通知
                self._send_feishu_notification(
                    self._format_cert_notification(results, "warning"),feishu_url=settings.FEISHU_CERT_API
                )
                return True
            else:
                self._log_result(check_name, True,
                               f"所有证书正常 (耗时 {duration:.2f}秒)")
                return True

        except Exception as e:
            error_info = {
                "type": e.__class__.__name__,
                "message": f"证书检查过程出错: {e}",
                "url": "N/A",
                "duration": 0
            }
            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(
                self._format_error_notification(check_name, error_info)
            )
            return False

    def _format_cert_notification(self, results: list, level: str = "warning") -> str:
        """
        格式化证书检查通知消息

        Args:
            results: 证书检查结果列表
            level: 通知级别 (warning/error)

        Returns:
            格式化的飞书通知消息
        """
        # 统计
        ok_count = sum(1 for r in results if r['status'] == 'ok')
        warning_count = sum(1 for r in results if r['status'] == 'warning')
        error_count = sum(1 for r in results if r['status'] == 'error')

        # 图标
        icon = "🔴" if level == "error" else "⚠️"

        # 构建消息
        message = f"{icon} SSL 证书检查报告\n"
        message += f"- 检查时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"- 检查端点数: {len(results)}\n"
        message += f"- 正常: {ok_count}\n"
        message += f"- 警告: {warning_count}\n"
        message += f"- 错误: {error_count}\n\n"

        # 错误项详情
        if error_count > 0:
            message += "🔴 错误项:\n"
            for r in results:
                if r['status'] == 'error':
                    message += f"- {r['url']}\n"
                    message += f"  {r.get('message', 'Unknown error')}\n"
            message += "\n"

        # 警告项详情
        if warning_count > 0:
            message += "⚠️ 警告项:\n"
            for r in results:
                if r['status'] == 'warning':
                    message += f"- {r['url']}\n"
                    message += f"  {r.get('message', 'Unknown warning')}\n"
                    if 'valid_until' in r:
                        message += f"  过期时间: {r['valid_until']}\n"
                    if 'issuer' in r:
                        message += f"  颁发者: {r['issuer']}\n"
            message += "\n"

        return message

    # ==================== 主要方法 ====================

    def run_all_checks(self):
        """运行所有检查"""
        print("=" * 60)
        print("API 监控检查")
        print("=" * 60)
        print(f"开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"API 地址: {self.base_url}")
        print(f"SSL 验证: {'已启用' if settings.ENABLE_SSL_VERIFY else '已禁用'}")
        print("=" * 60)

        # 清空之前的结果
        self.results = []

        # 执行各项检查
        print("\n[1] 检查登录服务...")
        check_region = settings.CHECK_REGION.lower()
        if check_region in ["intl", "both"]:
            self.check_login("国际登录服务", "intl")
        if check_region in ["cn", "both"]:
            self.check_login("国内登录服务","cn")


        print("\n[2] 检查验证码服务...")
        import os
        test_account = os.getenv("USER_CODE") or settings.USER
        self.check_verification_code(test_account)

        print("\n[3] 检查设备密钥注册服务...")
        self.check_device_auth()

        print("\n[4] 检查设备Token认证服务...")
        self.check_device_token_auth()

        print("\n[5] 检查健康检查 URL...")
        self.check_health_urls()

        # 输出总结
        self._print_summary()

    def _print_summary(self):
        """打印检查总结"""
        print("\n" + "=" * 60)
        print("检查结果汇总")
        print("=" * 60)

        total = len(self.results)
        passed = sum(1 for r in self.results if r['success'])
        failed = total - passed

        print(f"总检查项: {total}")
        print(f"通过: {passed}")
        print(f"失败: {failed}")
        print("=" * 60)

        if failed > 0:
            print("\n失败项目:")
            for r in self.results:
                if not r['success']:
                    print(f"  ✗ {r['check']}: {r['details']}")

    # ==================== 可扩展：添加自定义检查 ====================

    def add_custom_check(self, check_name: str, check_url: str, method: str = "GET", **kwargs):
        """
        添加自定义检查（可扩展）

        Args:
            check_name: 检查名称
            check_url: 检查的 URL
            method: HTTP 方法
            **kwargs: 其他请求参数
        """
        try:
            start_time = time.time()
            response = requests.request(
                method=method,
                url=check_url,
                timeout=self.timeout,
                verify=self._get_verify_param(),
                **kwargs
            )
            duration = time.time() - start_time

            response.raise_for_status()
            self._log_result(check_name, True, f"正常 (耗时 {duration:.2f}秒)")
            return True

        except Exception as e:
            duration = time.time() - start_time
            error_info = {
                "type": e.__class__.__name__,
                "message": str(e),
                "url": check_url,
                "duration": duration
            }
            self._log_result(check_name, False, str(e))
            self._send_feishu_notification(self._format_error_notification(check_name, error_info))
            return False
