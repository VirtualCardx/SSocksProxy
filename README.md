# SSocksProxy

一个基于 Python 3.13 的安全 SOCKS5 代理软件，使用 AES-256-GCM 加密保护数据传输。

## 功能特性

- 🔒 **AES-256-GCM 加密**: 使用高强度的 AES-256-GCM 加密算法保护所有数据传输
- 🚀 **异步高性能**: 基于 asyncio 实现，支持高并发连接
- 🔧 **易于配置**: 支持环境变量和配置文件配置
- 📊 **详细日志**: 提供详细的连接和错误日志
- 🛡️ **安全可靠**: 支持密码派生密钥，防止密钥泄露

## 系统要求

- Python 3.13+
- 支持的操作系统: Windows, Linux, macOS

## 安装

1. 克隆项目
```bash
git clone [<https://github.com/VirtualCardx/SSocksProxy>](https://github.com/VirtualCardx/SSocksProxy)
cd SSocksProxy
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

## 配置

### 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `SSOCKS_PASSWORD` | `your-secret-password` | 加密密码 |
| `CLIENT_HOST` | `127.0.0.1` | 客户端监听地址 |
| `CLIENT_PORT` | `1080` | 客户端监听端口 |
| `SERVER_HOST` | `your-server-ip` | 远程服务器地址 |
| `SERVER_PORT` | `12345` | 远程服务器端口 |
| `SERVER_LISTEN_HOST` | `0.0.0.0` | 服务端监听地址 |
| `SERVER_LISTEN_PORT` | `12345` | 服务端监听端口 |
| `BUFFER_SIZE` | `8192` | 缓冲区大小 |
| `CONNECTION_TIMEOUT` | `30` | 连接超时时间(秒) |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `ENABLE_DEBUG` | `false` | 是否启用调试模式 |

## 使用方法

### 方法一：一键演示（推荐）

```bash
# 激活虚拟环境
.\venv\Scripts\activate  # Windows
# 或
source venv/bin/activate  # Linux/macOS

# 运行演示脚本（会自动启动服务端和客户端）
python run_demo.py
```

### 方法二：手动启动

#### 1. 启动服务端

```bash
# Windows
.\venv\Scripts\activate
python server.py

# Linux/macOS
source venv/bin/activate
python server.py
```

#### 2. 启动客户端（新终端窗口）

```bash
# Windows
.\venv\Scripts\activate
python client.py

# Linux/macOS
source venv/bin/activate
python client.py
```

#### 3. 测试代理功能

```bash
# 激活虚拟环境后运行测试
python test_proxy.py
```

#### 4. 配置应用程序使用代理

将应用程序的 SOCKS5 代理设置为：
- 地址: `127.0.0.1`
- 端口: `1080`

## 项目结构

```
SSocksProxy/
├── client.py          # 客户端主程序
├── server.py          # 服务端主程序
├── crypto.py          # 加密工具模块
├── socks5.py          # SOCKS5协议处理
├── config.py          # 配置管理
├── requirements.txt   # 项目依赖
└── README.md         # 项目说明
```

## 工作原理

1. **客户端**:
   - 监听本地 1080 端口，接受 SOCKS5 请求
   - 处理 SOCKS5 握手和请求解析
   - 将目标地址信息加密后发送到远程服务器
   - 在本地客户端和远程服务器之间转发加密数据

2. **服务端**:
   - 监听指定端口，接受客户端连接
   - 解密目标地址信息，连接目标服务器
   - 在客户端和目标服务器之间转发数据
   - 所有数据都经过 AES-256-GCM 加密

## 安全说明

- 使用 AES-256-GCM 加密算法，提供高强度的数据保护
- 支持密码派生密钥，使用 PBKDF2 算法
- 每个数据包使用随机 nonce，防止重放攻击
- 建议在生产环境中使用强密码

## 故障排除

### 常见问题

1. **连接超时**
   - 检查网络连接
   - 确认服务端地址和端口正确
   - 检查防火墙设置

2. **加密错误**
   - 确认客户端和服务端使用相同的密码
   - 检查系统时间是否同步

3. **端口被占用**
   - 修改配置文件中的端口设置
   - 检查是否有其他程序占用端口

### 调试模式

启用调试模式查看详细日志：

```bash
export ENABLE_DEBUG=true
python client.py
```

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 免责声明

本软件仅供学习和研究使用，使用者需要遵守当地法律法规。开发者不对使用本软件造成的任何后果承担责任。 
