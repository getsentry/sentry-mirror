"""
Simple HTTP stub server for integration testing.
Logs all requests (URL and body) to a file.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread


class StubHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs requests to a file."""

    def do_POST(self):
        """Handle POST requests."""
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
        self.thread = None

        # Ensure log file directory exists
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        # Clear any existing log file
        Path(log_file).unlink(missing_ok=True)

    def start(self):
        """Start the stub server in a background thread."""
        self.server = HTTPServer(('localhost', self.port), StubHandler)
        self.server.log_file = self.log_file

        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the stub server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def get_requests(self) -> list:
        """Read and parse all logged requests."""
        log_file = Path(self.log_file)
        if not log_file.exists():
            return []

        requests = []
        with open(log_file, 'r') as f:
            for line in f:
                if line.strip():
                    requests.append(json.loads(line))
        return requests
