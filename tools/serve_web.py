import http.server
import socket
from pathlib import Path


def _local_ip() -> str:
    hostname = socket.gethostname()
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return "127.0.0.1"


def main() -> None:
    web_root = Path(__file__).resolve().parent.parent / "web"
    host = "0.0.0.0"
    port = 8000
    url = f"http://{_local_ip()}:{port}/index.html"
    print(f"Serving {web_root} on {host}:{port}")
    print(f"Open on your phone: {url}")
    handler = http.server.SimpleHTTPRequestHandler
    http.server.test(HandlerClass=handler, port=port, bind=host)


if __name__ == "__main__":
    main()
