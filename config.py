"""
配置文件
"""
import os
from typing import Optional


class Config:
    """配置类"""
    
    def __init__(self):
        # 加密配置
        self.password: Optional[str] = os.getenv('SSOCKS_PASSWORD', 'your-secret-password')
        self.key: Optional[bytes] = None
        
        # 客户端配置
        self.client_host: str = os.getenv('CLIENT_HOST', '127.0.0.1')
        self.client_port: int = int(os.getenv('CLIENT_PORT', '1080'))
        self.server_host: str = os.getenv('SERVER_HOST', '127.0.0.1')
        self.server_port: int = int(os.getenv('SERVER_PORT', '12345'))
        
        # 服务端配置
        self.server_listen_host: str = os.getenv('SERVER_LISTEN_HOST', '0.0.0.0')
        self.server_listen_port: int = int(os.getenv('SERVER_LISTEN_PORT', '12345'))
        
        # 连接配置
        self.buffer_size: int = int(os.getenv('BUFFER_SIZE', '8192'))
        self.connection_timeout: int = int(os.getenv('CONNECTION_TIMEOUT', '30'))
        
        # 日志配置
        self.log_level: str = os.getenv('LOG_LEVEL', 'INFO')
        self.enable_debug: bool = os.getenv('ENABLE_DEBUG', 'false').lower() == 'true'


# 全局配置实例
config = Config()


def get_config() -> Config:
    """获取配置实例"""
    return config


def print_config():
    """打印配置信息"""
    print("=== SSocksProxy 配置 ===")
    print(f"客户端监听: {config.client_host}:{config.client_port}")
    print(f"服务端地址: {config.server_host}:{config.server_port}")
    print(f"服务端监听: {config.server_listen_host}:{config.server_listen_port}")
    print(f"缓冲区大小: {config.buffer_size}")
    print(f"连接超时: {config.connection_timeout}秒")
    print(f"调试模式: {config.enable_debug}")
    print("=======================") 
