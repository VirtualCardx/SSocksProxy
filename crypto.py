"""
加密工具模块
提供AES-256-GCM加密解密功能
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """加密管理器"""
    
    def __init__(self, password: str = None, key: bytes = None):
        """
        初始化加密管理器
        
        Args:
            password: 密码字符串，用于生成密钥
            key: 直接提供的密钥字节
        """
        if key:
            self.key = key
        elif password:
            # 从密码生成密钥
            salt = b'ssocksproxy_salt'  # 固定盐值，生产环境建议随机
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.key = kdf.derive(password.encode())  # 直接使用派生的32字节密钥
        else:
            # 使用默认密钥（仅用于测试）
            self.key = b'default-32-byte-key-for-testing!'  # 正好32字节
    
    def encrypt(self, data: bytes) -> bytes:
        """
        加密数据
        
        Args:
            data: 要加密的数据
            
        Returns:
            加密后的数据（nonce + 密文）
        """
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # 96位随机nonce
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def decrypt(self, data: bytes) -> bytes:
        """
        解密数据
        
        Args:
            data: 加密的数据（nonce + 密文）
            
        Returns:
            解密后的原始数据
        """
        aesgcm = AESGCM(self.key)
        nonce = data[:12]
        ciphertext = data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def get_key_hex(self) -> str:
        """获取密钥的十六进制表示"""
        return self.key.hex()


# 全局加密管理器实例
crypto_manager = None


def init_crypto(password: str = None, key: bytes = None):
    """初始化全局加密管理器"""
    global crypto_manager
    crypto_manager = CryptoManager(password, key)


def encrypt(data: bytes) -> bytes:
    """加密数据（使用全局管理器）"""
    if not crypto_manager:
        raise RuntimeError("加密管理器未初始化，请先调用init_crypto()")
    return crypto_manager.encrypt(data)


def decrypt(data: bytes) -> bytes:
    """解密数据（使用全局管理器）"""
    if not crypto_manager:
        raise RuntimeError("加密管理器未初始化，请先调用init_crypto()")
    return crypto_manager.decrypt(data) 
