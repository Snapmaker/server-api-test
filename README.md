# API 监控脚本

简单的 API 监控脚本，自动检查各个服务并在出现问题时通过飞书发送通知。

## 特点

- **简单易用**：一个脚本完成所有监控
- **配置清晰**：URL 在代码中，凭证在环境变量中
- **自动通知**：服务异常时自动发送飞书通知
- **可扩展**：轻松添加新的检查项
- **自动重试**：URL 检查失败时自动重试

## 配置说明

项目采用分离配置方式：
- **API 地址和监控 URL** - 在代码中配置（`Api_Check/src/config.py`）
- **认证凭证和密码** - 在环境变量中配置（`.env` 文件或 GitHub Secrets）

这样做的好处：
- URL 不是敏感信息，直接在代码中配置更方便
- 敏感信息（凭证、密码）通过环境变量保护
- GitHub Secrets 配置项更少，更简洁

## 快速开始

### 1. 安装依赖

```bash
pip install -r Api_Check/requirements.txt
```

### 2. 配置 API 地址和监控项

编辑 `Api_Check/src/config.py`，修改 API 地址和监控列表：

```python
class Settings(BaseSettings):
    # API 配置（在代码中配置）
    API_BASE_URL: str = "https://api.example.com"  # 修改为你的 API 地址
    # ...

# 监控配置
MONITOR_CONFIG = {
    # API 端点配置
    "endpoints": {
        "login": "/oauth/token",
        "verification_code": "/api/verification/code",
    },

    # 需要监控的 URL 列表
    "health_check_urls": [
        "https://example.com/api/health",
        "https://example.com/api/status",
    ],
}
```

### 3. 配置环境变量（敏感信息）

复制 `.env.example` 为 `.env`：

```bash
cp .env.example .env
```

编辑 `.env` 文件，只需配置认证凭证等敏感信息：

```env
# 认证凭证
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
USER=your_username
PAW=your_password

# 飞书通知（可选）
FEISHU_API=https://open.feishu.cn/open-apis/bot/v2/hook/xxxxx
```

### 4. 运行监控

```bash
python Api_Check/main.py
```

## 文件结构

```
Api_Check/
├── src/
│   ├── config.py      # 配置文件（在这里配置监控项）
│   ├── monitor.py     # 监控核心类
│   └── __init__.py
└── main.py           # 主程序
```

## 监控项说明

脚本会自动检查以下服务：

1. **登录服务** - 测试 OAuth 登录接口
2. **验证码服务** - 测试验证码发送接口
3. **设备认证服务** - 测试设备 ECC 签名认证接口（需要配置设备私钥）
4. **健康检查 URL** - 检查 config.py 中配置的 URL 列表

如果任何检查失败，会：
- 在控制台输出错误信息
- 自动发送飞书通知（如果配置了 FEISHU_API）

### 关于设备认证

设备认证服务使用 ECC（椭圆曲线）签名算法进行身份验证：
- 需要配置设备序列号（`DEVICE_SN`）和设备私钥（`DEVICE_PRIVATE_KEY`）
- 支持签名自校验（可选配置公钥 `DEVICE_PUBLIC_KEY`）
- 如果未配置设备认证参数，该检查会自动跳过
- 需要安装 `cryptography` 库（已包含在 requirements.txt 中）

## 扩展使用

### 添加自定义检查

在 `main.py` 中使用 `add_custom_check` 方法：

```python
from src import APIMonitor

monitor = APIMonitor()

# 添加自定义 GET 检查
monitor.add_custom_check(
    check_name="自定义服务",
    check_url="https://your-api.com/custom",
    method="GET"
)

# 添加自定义 POST 检查
monitor.add_custom_check(
    check_name="自定义 POST",
    check_url="https://your-api.com/api",
    method="POST",
    json={"key": "value"}
)

# 运行所有检查
monitor.run_all_checks()
```

### 在 GitHub Actions 中使用

项目已配置 GitHub Actions 自动监控，每 10 分钟运行一次。

**配置步骤：**

1. 在 GitHub 仓库设置中添加以下 Secrets（Settings > Secrets and variables > Actions > New repository secret）：

   **必需配置（仅敏感信息）：**
   - `CLIENT_ID` - 客户端 ID
   - `CLIENT_SECRET` - 客户端密钥
   - `USER` - 用户名
   - `PAW` - 密码

   **可选配置：**
   - `REQUEST_TIMEOUT` - 请求超时时间（默认 30）
   - `FEISHU_API` - 飞书 Webhook 地址（不配置则不发送通知）
   - `USER_CODE` - 验证码测试账号（不配置则使用 USER）
   - `DEVICE_SN` - 设备序列号（用于设备认证检查）
   - `DEVICE_PRIVATE_KEY` - 设备私钥 Base64（用于设备认证检查）
   - `DEVICE_PUBLIC_KEY` - 设备公钥 Base64（用于签名自校验）

2. 修改代码中的 API 地址和监控列表

   编辑 `Api_Check/src/config.py`：
   ```python
   API_BASE_URL: str = "https://your-api.example.com"  # 修改为你的 API 地址

   MONITOR_CONFIG = {
       "health_check_urls": [
           "https://your-api.com/health",
           # 添加更多监控 URL
       ],
   }
   ```

3. 推送代码到 main 分支，Actions 将自动运行

4. 手动触发：在 Actions 标签页选择 "API 监控检查" > Run workflow

> **配置说明：**
> - API_BASE_URL 和监控 URL 在代码中配置（`config.py`）
> - 只有敏感信息（凭证、密码）需要在 GitHub Secrets 中配置
> - 修改监控配置后，提交代码即可生效

**调整运行频率：**

编辑 `.github/workflows/check-api-status.yml` 中的 cron 表达式：

```yaml
schedule:
  - cron: '*/5 * * * *'  # 每 5 分钟
  - cron: '0 * * * *'     # 每小时
  - cron: '0 0 * * *'     # 每天
```

### 本地定时运行

使用 cron (Linux/Mac) 或任务计划程序 (Windows) 定时运行：

**Linux/Mac (crontab):**
```bash
# 每 5 分钟运行一次
*/5 * * * * cd /path/to/server-api-test && python Api_Check/main.py
```

**Windows (任务计划程序):**
创建任务，设置触发器为定时运行，操作为运行 Python 脚本。

## 输出示例

```
============================================================
API 监控检查
============================================================
开始时间: 2025-01-12 10:30:00
API 地址: https://api.example.com
============================================================

[1] 检查登录服务...
✓ 登录服务: 正常 (耗时 0.85秒)

[2] 检查验证码服务...
✓ 验证码服务: 正常 (耗时 0.42秒)

[3] 检查健康检查 URL...
开始检查 2 个健康检查 URL...
✓ URL检查: https://example.com/api/health: 正常 (耗时 0.21秒)
✓ URL检查: https://example.com/api/status: 正常 (耗时 0.19秒)

============================================================
检查结果汇总
============================================================
总检查项: 4
通过: 4
失败: 0
============================================================
```

## 注意事项

- 确保 `.env` 文件不要提交到版本控制系统
- FEISHU_API 为可选配置，不配置则不发送通知
- SSL 验证默认关闭（`verify=False`），生产环境建议开启

## 许可证

MIT
