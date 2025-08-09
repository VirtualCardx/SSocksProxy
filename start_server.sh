#!/bin/bash

echo "SSocksProxy 服务端启动脚本"
echo "================================"

# 激活虚拟环境
source venv/bin/activate

# 设置环境变量
export SSOCKS_PASSWORD="your-secret-password"
export SERVER_LISTEN_HOST="0.0.0.0"
export SERVER_LISTEN_PORT="12345"

echo "配置信息:"
echo "密码: $SSOCKS_PASSWORD"
echo "监听地址: $SERVER_LISTEN_HOST:$SERVER_LISTEN_PORT"
echo

echo "正在启动服务端..."
python3 server.py 
