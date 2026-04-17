import ctypes
import logging
import logging.handlers
import json
import sys
import asyncio
import argparse
import os
import winreg
from datetime import datetime, timezone
from typing import Tuple, Optional

if sys.platform == "win32":
    os.system("")

COLOR_REQUEST = "\033[92m"
COLOR_ERROR = "\033[91m"
COLOR_CONNECT = "\033[94m"
COLOR_RESET = "\033[0m"


class JsonFormatter(logging.Formatter):

    def format(self, record):
        if isinstance(record.msg, dict):
            record.msg['timestamp'] = datetime.now(timezone.utc).isoformat()
            return json.dumps(record.msg, ensure_ascii=False)
        return super().format(record)


class ProxyLogger:
    def __init__(self, log_file: str, verbose: bool):
        self.verbose = verbose

        self.console_logger = logging.getLogger("ProxyConsole")
        self.console_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.console_logger.propagate = False

        if not self.console_logger.handlers:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
            self.console_logger.addHandler(console_handler)

        self.file_logger = logging.getLogger("ProxyConnections")
        self.file_logger.setLevel(logging.INFO)
        self.file_logger.propagate = False

        if not self.file_logger.handlers:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8'
            )
            file_handler.setFormatter(JsonFormatter())
            self.file_logger.addHandler(file_handler)

    def log_connection(self, client_ip: str, method: str, host: str, port: int, status: str, error: str = ""):
        self.error_ = {
            "client_ip": client_ip,
            "method": method,
            "target_host": host,
            "target_port": port,
            "status": status,
            "error": error
        }
        log_data = self.error_
        self.file_logger.info(log_data)

    def info(self, msg: str):
        self.console_logger.info(msg)

    def error(self, msg: str):
        self.console_logger.error(f"{COLOR_ERROR}{msg}{COLOR_RESET}")

    def print_request(self, color: str, msg: str, addr: Tuple[str, int]):
        self.console_logger.info(f"{addr[0]}:{addr[1]} {color}{msg}{COLOR_RESET}")


class ProxyServer:
    def __init__(self, host: str, port: int, logger: ProxyLogger, timeout: int = 10):
        self.host = host
        self.port = port
        self.logger = logger
        self.timeout = timeout
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        self.logger.info(f"Асинхронный прокси запущен на {addrs}")

        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        client_addr = client_writer.get_extra_info('peername')
        if not client_addr:
            client_writer.close()
            return

        client_ip = client_addr[0]
        method, target_host, target_port = "UNKNOWN", "UNKNOWN", 0

        try:
            data = await asyncio.wait_for(client_reader.read(8192), timeout=self.timeout)
            if not data:
                return

            first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore').strip()
            if not first_line:
                first_line = data.split(b'\n')[0].decode('utf-8', errors='ignore').strip()

            parts = first_line.split()
            if len(parts) < 2:
                raise ValueError("Неверный формат HTTP запроса")

            method = parts[0]
            target_host, target_port = self.parse_host_port(parts[1])

            if method == 'CONNECT':
                self.logger.print_request(COLOR_CONNECT, first_line, client_addr)
                await self.handle_https_tunnel(client_reader, client_writer, target_host, target_port)
            else:
                self.logger.print_request(COLOR_REQUEST, first_line, client_addr)
                await self.handle_http(client_reader, client_writer, data, target_host, target_port)

            self.logger.log_connection(client_ip, method, target_host, target_port, "SUCCESS")

        except asyncio.TimeoutError:
            self.logger.error(f"[{client_ip}] Таймаут ожидания данных от клиента")
            self.logger.log_connection(client_ip, method, target_host, target_port, "TIMEOUT")
        except Exception as e:
            self.logger.error(f"[{client_ip}] Ошибка обработки клиента: {e}")
            self.logger.log_connection(client_ip, method, target_host, target_port, "ERROR", str(e))
        finally:
            if not client_writer.is_closing():
                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass

    def parse_host_port(self, url: str) -> Tuple[str, int]:
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]

        if ':' in url:
            host, rest = url.split(':', 1)
            port_str = rest.split('/')[0]
            port = int(port_str) if port_str.isdigit() else 80
        else:
            host = url.split('/')[0]
            port = 80
        return host, port

    async def handle_http(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                          initial_data: bytes, host: str, port: int):
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            remote_writer.write(initial_data)
            await remote_writer.drain()

            await self.relay_data(client_reader, client_writer, remote_reader, remote_writer)
        except Exception as e:
            raise ConnectionError(f"HTTP подключение к {host}:{port} провалилось: {e}")

    async def handle_https_tunnel(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                                  host: str, port: int):
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            await self.relay_data(client_reader, client_writer, remote_reader, remote_writer)
        except Exception as e:
            raise ConnectionError(f"HTTPS туннель к {host}:{port} провалился: {e}")

    async def relay_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                         remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter):

        async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                while True:
                    data = await reader.read(8192 * 4)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                if not writer.is_closing():
                    writer.close()

        task1 = asyncio.create_task(pipe(client_reader, remote_writer))
        task2 = asyncio.create_task(pipe(remote_reader, client_writer))

        await asyncio.gather(task1, task2, return_exceptions=True)


class SystemProxyManager:
    INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'

    @staticmethod
    def set_state(enable: bool, host: str = "127.0.0.1", port: int = 8080):
        if sys.platform != "win32":
            print(f"[*] Авто-настройка пока реализована только для Windows. На {sys.platform} настройте вручную.")
            return

        try:
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SystemProxyManager.INTERNET_SETTINGS, 0,
                                          winreg.KEY_WRITE)

            if enable:
                winreg.SetValueEx(registry_key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(registry_key, 'ProxyServer', 0, winreg.REG_SZ, f"{host}:{port}")
                winreg.SetValueEx(registry_key, 'ProxyOverride', 0, winreg.REG_SZ, "<local>")
            else:
                winreg.SetValueEx(registry_key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(registry_key)

            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception as e:
            print(f"[!] Ошибка при изменении настроек системы: {e}")

async def main():
    parser = argparse.ArgumentParser(description="Асинхронный прокси с авто-настройкой системы.")
    parser.add_argument("-H", "--host", default="127.0.0.1")
    parser.add_argument("-p", "--port", default=8080, type=int, help="Порт")
    parser.add_argument("-l", "--log-file", default="proxy.jsonl")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-auto", action="store_true")

    args = parser.parse_args()
    logger = ProxyLogger(args.log_file, args.verbose)
    proxy = ProxyServer(args.host, args.port, logger)

    if not args.no_auto:
        logger.info(f"Включаю системный прокси: {args.host}:{args.port}...")
        SystemProxyManager.set_state(True, args.host, args.port)

    try:
        await proxy.start()
    except KeyboardInterrupt:
        pass
    finally:
        if not args.no_auto:
            logger.info("Выключаю системный прокси и восстанавливаю настройки...")
            SystemProxyManager.set_state(False)
        logger.info("Прокси остановлен.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
