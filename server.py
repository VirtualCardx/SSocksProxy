#!/usr/bin/env python3
"""
SSocksProxy 服务端
监听指定端口，接收客户端加密数据包，解密后转发到目标服务器
"""
import asyncio
import logging
import signal
import sys
import socket
from typing import Optional

from crypto import init_crypto, encrypt, decrypt
from config import get_config, print_config


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SSocksServer')


class SSocksServer:
    """SSocks服务端"""
    
    def __init__(self):
        self.config = get_config()
        self.server = None
        self.running = False
        
        # 初始化加密
        init_crypto(password=self.config.password, key=self.config.key)
        logger.info("加密模块初始化完成")
    
    async def handle_client_connection(self, client_reader: asyncio.StreamReader, 
                                     client_writer: asyncio.StreamWriter):
        """
        处理客户端连接
        
        Args:
            client_reader: 客户端读取器
            client_writer: 客户端写入器
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"新的客户端连接: {client_addr}")
        
        try:
            # 读取目标地址信息
            length_bytes = await client_reader.readexactly(4)
            length = int.from_bytes(length_bytes, 'big')
            encrypted_info = await client_reader.readexactly(length)
            target_info = decrypt(encrypted_info).decode()
            
            # 解析目标地址和端口
            target_addr, target_port_str = target_info.rsplit(':', 1)
            target_port = int(target_port_str)
            
            logger.info(f"目标连接: {target_addr}:{target_port}")
            
            # 连接目标服务器
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_addr, target_port),
                    timeout=self.config.connection_timeout
                )
                logger.info(f"成功连接到目标服务器: {target_addr}:{target_port}")
            except asyncio.TimeoutError:
                logger.error(f"连接目标服务器超时: {target_addr}:{target_port}")
                return
            except Exception as e:
                logger.error(f"连接目标服务器失败: {target_addr}:{target_port} - {e}")
                return
            
            # 开始数据转发
            await self._forward_data(client_reader, client_writer, target_reader, target_writer, client_addr)
            
        except asyncio.IncompleteReadError:
            logger.warning(f"客户端连接异常关闭: {client_addr}")
        except Exception as e:
            logger.error(f"处理客户端连接时发生错误: {e}")
        finally:
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except:
                pass
            logger.info(f"客户端连接关闭: {client_addr}")
    
    async def _forward_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                           target_reader: asyncio.StreamReader, target_writer: asyncio.StreamWriter,
                           client_addr):
        """
        转发数据
        
        Args:
            client_reader: 客户端读取器
            client_writer: 客户端写入器
            target_reader: 目标读取器
            target_writer: 目标写入器
            client_addr: 客户端地址
        """
        try:
            # 客户端到目标服务器的数据转发
            async def client_to_target():
                try:
                    while True:
                        # 读取数据长度
                        length_bytes = await client_reader.readexactly(4)
                        length = int.from_bytes(length_bytes, 'big')
                        
                        # 读取加密数据
                        encrypted_data = await client_reader.readexactly(length)
                        data = decrypt(encrypted_data)
                        
                        target_writer.write(data)
                        await target_writer.drain()
                        
                        if self.config.enable_debug:
                            logger.debug(f"客户端->目标: {len(data)} 字节")
                            
                except asyncio.IncompleteReadError:
                    # 连接正常关闭
                    pass
                except Exception as e:
                    logger.error(f"客户端到目标转发错误: {e}")
                finally:
                    target_writer.close()
            
            # 目标服务器到客户端的数据转发
            async def target_to_client():
                try:
                    while True:
                        data = await target_reader.read(self.config.buffer_size)
                        if not data:
                            break
                        
                        # 加密数据
                        encrypted_data = encrypt(data)
                        length_bytes = len(encrypted_data).to_bytes(4, 'big')
                        client_writer.write(length_bytes + encrypted_data)
                        await client_writer.drain()
                        
                        if self.config.enable_debug:
                            logger.debug(f"目标->客户端: {len(data)} 字节")
                            
                except Exception as e:
                    logger.error(f"目标到客户端转发错误: {e}")
                finally:
                    client_writer.close()
            
            # 并发执行两个方向的转发
            await asyncio.gather(
                client_to_target(),
                target_to_client(),
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"数据转发错误: {e}")
        finally:
            # 确保连接关闭
            target_writer.close()
            client_writer.close()
            try:
                await target_writer.wait_closed()
                await client_writer.wait_closed()
            except:
                pass
    
    async def start(self):
        """启动服务端"""
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
                self.handle_client_connection,
                self.config.server_listen_host,
                self.config.server_listen_port,
                **server_kwargs
            )
            
            self.running = True
            logger.info(f"SSocks服务端启动成功，监听 {self.config.server_listen_host}:{self.config.server_listen_port}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"启动服务端失败: {e}")
            sys.exit(1)
    
    async def stop(self):
        """停止服务端"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("SSocks服务端已停止")


async def main():
    """主函数"""
    print_config()
    
    server = SSocksServer()
    
    # 设置信号处理（Windows兼容）
    def signal_handler():
        logger.info("收到停止信号，正在关闭...")
        asyncio.create_task(server.stop())
    
    # 注册信号处理器（仅在非Windows系统）
    import platform
    if platform.system() != 'Windows':
        for sig in (signal.SIGINT, signal.SIGTERM):
            asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("收到键盘中断信号")
    finally:
        await server.stop()


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
