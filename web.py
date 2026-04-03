import logging
import os
import socket
import sys
import threading
import time
from typing import Optional, Tuple
import select
if sys.platform == "win32":
    os.system("")
HOST = '0.0.0.0'
PORT = 8080
BACKLOG = 100
BUFFER_SIZE = 8192 * 4
TIMEOUT = 10

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

logger = logging.getLogger(__name__)

COLOR_REQUEST = "\033[92m"
COLOR_ERROR = "\033[91m"
COLOR_CONNECT = "\033[94m"
COLOR_RESET = "\033[0m"


def print_log(color: str, msg: str, addr: Optional[Tuple] = None):
    prefix = f"{addr[0]}:{addr[1]}" if addr else ""
    logger.info(f"{prefix}{color}{msg}{COLOR_RESET}")


class ProxyServer:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.running = True
        self.server_socket: Optional[socket.socket] = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(BACKLOG)
        self.server_socket.settimeout(1)

        logger.info(f"Прокси запущен на {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    client_sock.settimeout(TIMEOUT)
                    threading.Thread(target=self.handle_client,
                                     args=(client_sock, client_addr,),
                                     daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Ошибка accept: {e}")
        except KeyboardInterrupt:
            logger.info("Остановка прокси...")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

    def handle_client(self, client_sock: socket.socket, client_addr: Tuple):
        try:
            data = client_sock.recv(BUFFER_SIZE)
            if not data:
                return

            first_line = data.split(b'\n')[0].decode('utf-8', errors='ignore').strip()
            method = first_line.split()[0] if first_line else ""

            print_log(COLOR_REQUEST, f"{first_line}", client_addr)

            if method == 'CONNECT':
                self.handle_https_tunel(client_sock, first_line, client_addr)
            else:
                self.handle_http(client_sock, data, first_line, client_addr)
        except Exception as e:
            print_log(COLOR_ERROR, f"{e}", client_addr)
        finally:
            client_sock.close()

    def handle_http(self, client_sock: socket.socket, request: bytes, first_line: str, client_addr: Tuple):
        try:
            host, port = self.parse_host_port(first_line)
            logger.debug(f"HTTP запрос к {host}:{port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((host, port))
                s.sendall(request)

                self.relay_data(client_sock, s, is_https=False)

        except Exception as e:
            print_log(COLOR_ERROR, f"{e}", client_addr)

    def handle_https_tunel(self, client_sock: socket.socket, connect_line: str, client_addr: Tuple):
        try:
            parts = connect_line.split()
            host_port = parts[1]
            if ':' in host_port:
                host, host_port = host_port.split(':', 1)
                port = int(host_port)
            else:
                host, port = host_port, 443

            print_log(COLOR_CONNECT, f"CONNECT {host}:{port}", client_addr)

            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((host, port))
                s.settimeout(None)
                client_sock.settimeout(None)
                self.relay_data(client_sock, s, is_https=True)
        except Exception as e:
            print_log(COLOR_ERROR, f"HTTPS туннель ошибка: {e}", client_addr)

    def parse_host_port(self, first_line: str) -> Tuple[str, int]:
        parts = first_line.split()
        if len(parts) < 2:
            raise ValueError("Неверный запрос")

        url = parts[1]
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]

        if ':' in url and '/' in url.split(':', 1)[1]:
            host, rest = url.split(':', 1)
            port = int(rest.split('/')[0])
        elif ':' in url:
            host, port_str = url.split(':', 1)
            port = int(port_str.split('/')[0]) if '/' in port_str else int(port_str)
        else:
            host = url.split('/')[0]
            port = 80
        return host, port
    def relay_data(self, client_sock: socket.socket, s: socket.socket,is_https: bool=False):
        sockets = [client_sock, s]
        timeout = TIMEOUT *2


        last_activity = time.time()
        while time.time() - last_activity < timeout:
            try:
                readable, _, _ = select.select(sockets, [], [], 1.0)
                for sock in readable:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        return

                    last_activity = time.time()

                    other = s if sock is client_sock else client_sock
                    other.sendall(data)
            except Exception:
                break

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
        except ValueError:
            pass

    proxy = ProxyServer(port=PORT)
    proxy.start()