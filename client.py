#!/usr/bin/env python3
"""
SSocksProxy 客户端
监听本地1080端口，接受SOCKS5请求，加密后转发到远程服务器
"""
import asyncio
import logging
import signal
import sys
import struct
from typing import Optional

from crypto import init_crypto, encrypt, decrypt
from config import get_config, print_config
from socks5 import Socks5Handler, Socks5Error


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SSocksClient')


class SSocksClient:
    """SSocks客户端"""
    
    def __init__(self):
        self.config = get_config()
        self.server = None
        self.running = False
        
        # 初始化加密
        init_crypto(password=self.config.password, key=self.config.key)
        logger.info("加密模块初始化完成")
    
    async def handle_local_connection(self, local_reader: asyncio.StreamReader, 
                                    local_writer: asyncio.StreamWriter):
        """
        处理本地SOCKS5连接
        
        Args:
            local_reader: 本地连接读取器
            local_writer: 本地连接写入器
        """
        client_addr = local_writer.get_extra_info('peername')
        logger.info(f"新的本地连接: {client_addr}")
        
        try:
            # 处理SOCKS5握手
            socks_handler = Socks5Handler(local_reader, local_writer)
            if not await socks_handler.handle_handshake():
                logger.warning(f"SOCKS5握手失败: {client_addr}")
                return
            
            # 处理SOCKS5请求
            target_addr, target_port, cmd = await socks_handler.handle_request()
            logger.info(f"目标连接: {target_addr}:{target_port}")
            
            # 连接远程服务器
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.server_host, self.config.server_port),
                    timeout=self.config.connection_timeout
                )
            except asyncio.TimeoutError:
                logger.error(f"连接远程服务器超时: {self.config.server_host}:{self.config.server_port}")
                await socks_handler.send_error_response(socks_handler.STATUS_NETWORK_UNREACHABLE)
                return
            except Exception as e:
                logger.error(f"连接远程服务器失败: {e}")
                await socks_handler.send_error_response(socks_handler.STATUS_NETWORK_UNREACHABLE)
                return
            
            # 发送目标地址信息到远程服务器
            target_info = f"{target_addr}:{target_port}".encode()
            encrypted_info = encrypt(target_info)
            length_bytes = len(encrypted_info).to_bytes(4, 'big')
            remote_writer.write(length_bytes + encrypted_info)
            await remote_writer.drain()
            
            # 发送成功响应给本地客户端
            await socks_handler.send_success_response()
            
            # 开始数据转发
            await self._forward_data(local_reader, local_writer, remote_reader, remote_writer, client_addr)
            
        except Socks5Error as e:
            logger.error(f"SOCKS5协议错误: {e}")
        except Exception as e:
            logger.error(f"处理连接时发生错误: {e}")
        finally:
            local_writer.close()
            try:
                await local_writer.wait_closed()
            except:
                pass
            logger.info(f"本地连接关闭: {client_addr}")
    
    async def _forward_data(self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter,
                           remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter,
                           client_addr):
        """
        转发数据
        
        Args:
            local_reader: 本地读取器
            local_writer: 本地写入器
            remote_reader: 远程读取器
            remote_writer: 远程写入器
            client_addr: 客户端地址
        """
        try:
            # 本地到远程的数据转发
            async def local_to_remote():
                try:
                    while True:
                        data = await local_reader.read(self.config.buffer_size)
                        if not data:
                            break
                        
                        # 加密数据
                        encrypted_data = encrypt(data)
                        length_bytes = len(encrypted_data).to_bytes(4, 'big')
                        remote_writer.write(length_bytes + encrypted_data)
                        await remote_writer.drain()
                        
                        if self.config.enable_debug:
                            logger.debug(f"本地->远程: {len(data)} 字节")
                            
                except Exception as e:
                    logger.error(f"本地到远程转发错误: {e}")
                finally:
                    remote_writer.close()
            
            # 远程到本地的数据转发
            async def remote_to_local():
                try:
                    while True:
                        # 读取数据长度
                        length_bytes = await remote_reader.readexactly(4)
                        length = int.from_bytes(length_bytes, 'big')
                        
                        # 读取加密数据
                        encrypted_data = await remote_reader.readexactly(length)
                        data = decrypt(encrypted_data)
                        
                        local_writer.write(data)
                        await local_writer.drain()
                        
                        if self.config.enable_debug:
                            logger.debug(f"远程->本地: {len(data)} 字节")
                            
                except asyncio.IncompleteReadError:
                    # 连接正常关闭
                    pass
                except Exception as e:
                    logger.error(f"远程到本地转发错误: {e}")
                finally:
                    local_writer.close()
            
            # 并发执行两个方向的转发
            await asyncio.gather(
                local_to_remote(),
                remote_to_local(),
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"数据转发错误: {e}")
        finally:
            # 确保连接关闭
            remote_writer.close()
            local_writer.close()
            try:
                await remote_writer.wait_closed()
                await local_writer.wait_closed()
            except:
                pass
    
    async def start(self):
        """启动客户端"""
        try:
            # Windows兼容性处理
            import platform
            server_kwargs = {
                'reuse_address': True
            }
            # Linux/macOS 支持 reuse_port
            if platform.system() != 'Windows':
                server_kwargs['reuse_port'] = True
            
            self.server = await asyncio.start_server(
                self.handle_local_connection,
                self.config.client_host,
                self.config.client_port,
                **server_kwargs
            )
            
            self.running = True
            logger.info(f"SSocks客户端启动成功，监听 {self.config.client_host}:{self.config.client_port}")
            logger.info(f"远程服务器: {self.config.server_host}:{self.config.server_port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"启动客户端失败: {e}")
            sys.exit(1)
    
    async def stop(self):
        """停止客户端"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("SSocks客户端已停止")


async def main():
    """主函数"""
    print_config()
    
    client = SSocksClient()
    
    # 设置信号处理（Windows兼容）
    def signal_handler():
        logger.info("收到停止信号，正在关闭...")
        asyncio.create_task(client.stop())
    
    # 注册信号处理器（仅在非Windows系统）
    import platform
    if platform.system() != 'Windows':
        for sig in (signal.SIGINT, signal.SIGTERM):
            asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    try:
        await client.start()
    except KeyboardInterrupt:
        logger.info("收到键盘中断信号")
    finally:
        await client.stop()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程序已退出")
    except Exception as e:
        import traceback
        logger.error(f"程序异常退出: {e}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        sys.exit(1) 
