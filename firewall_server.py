

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# Define the filtering conditions
BLOCKED_PATHS = ["/tomcatwar.jsp"]
BLOCKED_PAYLOAD = "class.module.classLoader.resources.context.parent.pipeline.firstPattern"
BLOCKED_USER_AGENTS = ["curl", "python-requests", "wget", "malicious-bot"]

class FirewallHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handles incoming POST requests and applies firewall rules."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length else ""

        # Check if the request path is malicious
        if self.path in BLOCKED_PATHS:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Malicious path detected")
            return

        # Check if the request body contains malicious payload
        if BLOCKED_PAYLOAD in post_data:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Malicious payload detected")
            return

        # Check if the User-Agent header is from a known malicious source
        user_agent = self.headers.get("User-Agent", "").lower()
        if any(bot in user_agent for bot in BLOCKED_USER_AGENTS):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Suspicious User-Agent detected")
            return

        # If no malicious activity is detected, allow the request
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request Allowed")

def run_firewall_server(server_class=HTTPServer, handler_class=FirewallHTTPRequestHandler, port=8080):
    """Starts the HTTP firewall server."""
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Firewall running on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run_firewall_server()
