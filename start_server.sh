#!/bin/bash

echo "SSocksProxy 客户端启动脚本"
echo "================================"

# 激活虚拟环境
source venv/bin/activate

# 设置环境变量
export SSOCKS_PASSWORD="your-secret-password"
export SERVER_HOST="your-server-ip"
export SERVER_PORT="12345"
export CLIENT_HOST="127.0.0.1"
export CLIENT_PORT="1080"

echo "配置信息:"
echo "密码: $SSOCKS_PASSWORD"
echo "服务器: $SERVER_HOST:$SERVER_PORT"
echo "本地监听: $CLIENT_HOST:$CLIENT_PORT"
echo

echo "正在启动客户端..."
python3 client.py 
