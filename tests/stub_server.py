"""
Simple HTTP stub server for integration testing.
Logs all requests (URL and body) to a file.
"""
import json

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
import sys


class StubHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs requests to a file."""

    def do_POST(self):
        """Handle POST requests."""
        print(f"handle post {self.server.log_file}")
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        # Log the request
        log_entry = {
            'url': self.path,
            'body': body
        }

        log_file = Path(self.server.log_file)
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        # Send a successful response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class StubServer:
    """Wrapper for the HTTP stub server."""

    def __init__(self, port: int, log_file: str):
        self.port = port
        self.log_file = log_file
        self.server = None

        # Ensure log file directory exists
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        # Clear any existing log file
        Path(log_file).unlink(missing_ok=True)

    def start(self):
        """Start the stub server in a background thread."""
        self.server = HTTPServer(('localhost', self.port), StubHandler)
        self.server.log_file = self.log_file

        print(f"starting server on {self.port}")
        self.server.serve_forever()


def run_server(argv: list[str]) -> None:
    port = int(argv[1])
    log_file = argv[2]
    server = StubServer(port, log_file)
    server.start()


if __name__ == "__main__":
    print("Starting server", sys.argv)
    run_server(sys.argv)
