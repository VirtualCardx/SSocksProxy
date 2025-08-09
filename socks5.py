"""
SOCKS5协议处理模块
实现SOCKS5协议的解析和处理
"""
import socket
import struct
import asyncio
from typing import Tuple, Optional


class Socks5Error(Exception):
    """SOCKS5协议错误"""
    pass


class Socks5Handler:
    """SOCKS5协议处理器"""
    
    # SOCKS5版本
    VERSION = 0x05
    
    # 认证方法
    AUTH_NO_AUTH = 0x00
    AUTH_USERNAME_PASSWORD = 0x02
    AUTH_NO_ACCEPTABLE = 0xFF
    
    # 命令类型
    CMD_CONNECT = 0x01
    CMD_BIND = 0x02
    CMD_UDP_ASSOCIATE = 0x03
    
    # 地址类型
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04
    
    # 响应状态
    STATUS_SUCCESS = 0x00
    STATUS_GENERAL_FAILURE = 0x01
    STATUS_CONNECTION_NOT_ALLOWED = 0x02
    STATUS_NETWORK_UNREACHABLE = 0x03
    STATUS_HOST_UNREACHABLE = 0x04
    STATUS_CONNECTION_REFUSED = 0x05
    STATUS_TTL_EXPIRED = 0x06
    STATUS_COMMAND_NOT_SUPPORTED = 0x07
    STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
    
    async def handle_handshake(self) -> bool:
        """
        处理SOCKS5握手
        
        Returns:
            bool: 握手是否成功
        """
        try:
            # 读取客户端支持的认证方法
            version = await self.reader.readexactly(1)
            if version[0] != self.VERSION:
                raise Socks5Error(f"不支持的SOCKS版本: {version[0]}")
            
            nmethods = await self.reader.readexactly(1)
            methods = await self.reader.readexactly(nmethods[0])
            
            # 检查是否支持无认证方法
            if self.AUTH_NO_AUTH in methods:
                # 回复选择无认证方法
                response = struct.pack('!BB', self.VERSION, self.AUTH_NO_AUTH)
                self.writer.write(response)
                await self.writer.drain()
                return True
            else:
                # 回复没有可接受的认证方法
                response = struct.pack('!BB', self.VERSION, self.AUTH_NO_ACCEPTABLE)
                self.writer.write(response)
                await self.writer.drain()
                return False
                
        except Exception as e:
            raise Socks5Error(f"握手失败: {e}")
    
    async def handle_request(self) -> Tuple[str, int, int]:
        """
        处理SOCKS5请求
        
        Returns:
            Tuple[str, int, int]: (目标地址, 目标端口, 命令类型)
        """
        try:
            # 读取请求头
            version, cmd, rsv, atyp = struct.unpack('!BBBB', await self.reader.readexactly(4))
            
            if version != self.VERSION:
                raise Socks5Error(f"不支持的SOCKS版本: {version}")
            
            if cmd != self.CMD_CONNECT:
                raise Socks5Error(f"不支持的命令: {cmd}")
            
            # 解析目标地址
            if atyp == self.ATYP_IPV4:
                # IPv4地址
                addr_bytes = await self.reader.readexactly(4)
                target_addr = socket.inet_ntoa(addr_bytes)
            elif atyp == self.ATYP_DOMAIN:
                # 域名
                domain_len = await self.reader.readexactly(1)
                domain = await self.reader.readexactly(domain_len[0])
                target_addr = domain.decode('utf-8')
            elif atyp == self.ATYP_IPV6:
                # IPv6地址
                addr_bytes = await self.reader.readexactly(16)
                target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                raise Socks5Error(f"不支持的地址类型: {atyp}")
            
            # 读取端口
            port_bytes = await self.reader.readexactly(2)
            target_port = struct.unpack('!H', port_bytes)[0]
            
            return target_addr, target_port, cmd
            
        except Exception as e:
            raise Socks5Error(f"请求解析失败: {e}")
    
    async def send_response(self, status: int, addr: str = '0.0.0.0', port: int = 0):
        """
        发送SOCKS5响应
        
        Args:
            status: 状态码
            addr: 绑定地址
            port: 绑定端口
        """
        try:
            # 构造响应
            response = struct.pack('!BBBB', self.VERSION, status, 0x00, self.ATYP_IPV4)
            
            # 添加地址和端口
            addr_bytes = socket.inet_aton(addr)
            response += addr_bytes + struct.pack('!H', port)
            
            self.writer.write(response)
            await self.writer.drain()
            
        except Exception as e:
            raise Socks5Error(f"发送响应失败: {e}")
    
    async def send_success_response(self, addr: str = '0.0.0.0', port: int = 0):
        """发送成功响应"""
        await self.send_response(self.STATUS_SUCCESS, addr, port)
    
    async def send_error_response(self, status: int):
        """发送错误响应"""
        await self.send_response(status)


def parse_socks5_request(data: bytes) -> Tuple[str, int, int]:
    """
    解析SOCKS5请求数据包
    
    Args:
        data: SOCKS5请求数据
        
    Returns:
        Tuple[str, int, int]: (目标地址, 目标端口, 命令类型)
    """
    if len(data) < 7:
        raise Socks5Error("数据包太短")
    
    version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])
    
    if version != 0x05:
        raise Socks5Error(f"不支持的SOCKS版本: {version}")
    
    if cmd != 0x01:  # CONNECT
        raise Socks5Error(f"不支持的命令: {cmd}")
    
    offset = 4
    
    if atyp == 0x01:  # IPv4
        if len(data) < offset + 6:
            raise Socks5Error("IPv4地址数据不完整")
        addr_bytes = data[offset:offset+4]
        target_addr = socket.inet_ntoa(addr_bytes)
        offset += 4
    elif atyp == 0x03:  # Domain
        if len(data) < offset + 1:
            raise Socks5Error("域名长度数据不完整")
        domain_len = data[offset]
        offset += 1
        if len(data) < offset + domain_len + 2:
            raise Socks5Error("域名数据不完整")
        domain = data[offset:offset+domain_len]
        target_addr = domain.decode('utf-8')
        offset += domain_len
    elif atyp == 0x04:  # IPv6
        if len(data) < offset + 18:
            raise Socks5Error("IPv6地址数据不完整")
        addr_bytes = data[offset:offset+16]
        target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        offset += 16
    else:
        raise Socks5Error(f"不支持的地址类型: {atyp}")
    
    if len(data) < offset + 2:
        raise Socks5Error("端口数据不完整")
    
    port_bytes = data[offset:offset+2]
    target_port = struct.unpack('!H', port_bytes)[0]
    
    return target_addr, target_port, cmd


def create_socks5_response(status: int, addr: str = '0.0.0.0', port: int = 0) -> bytes:
    """
    创建SOCKS5响应数据包
    
    Args:
        status: 状态码
        addr: 绑定地址
        port: 绑定端口
        
    Returns:
        bytes: SOCKS5响应数据包
    """
    response = struct.pack('!BBBB', 0x05, status, 0x00, 0x01)  # IPv4
    response += socket.inet_aton(addr)
    response += struct.pack('!H', port)
    return response 
