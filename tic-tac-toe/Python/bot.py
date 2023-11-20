"""
'Tic tac toe' game bot for 'IT Contest' web site. Python 3 only.

This is sample bot: he is stupid and will choose absolutely random turn.
"""
import cgi
import http.server
import json
import random
import socket
import sys
from urllib.parse import parse_qs, urlparse


VERSION = '0.0.1'
SECRET = 'd07e785dfab5278e8ef582be8f3f0d62'


class Bot(http.server.BaseHTTPRequestHandler):

    """Bot class."""

    def get_response_message(self, code):
        """Get HTTP response name by code."""
        try:
            return self.responses[code][0]
        except KeyError:
            return '???'

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer, log response code."""
        self.log_request(code)
        self.send_response_only(code, message)

    def send_empty_response(self):
        """Send empty '200 OK' response."""
        self.send_response(200, self.responses[200][0])
        self.send_header('Connection', "close")
        self.send_header('Content-Length', 0)
        self.end_headers()

    def send_json_response(self, data, code=200, message=None):
        """Send JSON response."""
        if message is None:
            message = self.get_response_message(code)

        body = json.dumps(data).encode('UTF-8', 'replace')
        self.send_response(code, message)
        self.send_header('Content-Type', "application/json")
        self.send_header('Connection', "close")
        self.send_header('Content-Length', int(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        """Send and log an error reply."""
        if message is None:
            message = self.get_response_message(code)

        self.log_error("Error {0}: {1}".format(code, message))
        response = {'error': explain or message}
        self.send_json_response(response, code, message)

    def get_status(self, data):
        """Process 'status' command.

        http://itcontest.ru/docs/games/tic-tac-toe/api/status/
        """
        self.send_json_response({
            'status': "OK",
            'game': "tic-tac-toe",
            'version': VERSION,
            'secret': SECRET,
            'message': "Hi, there!",
        })

    def post_start(self, data):
        """Process 'start' command.

        http://itcontest.ru/docs/games/tic-tac-toe/api/start/
        """
        self.send_json_response({
            'status': "accept",
            'secret': SECRET,
            'message': "Let's go!",
        })

    def post_turn(self, data):
        """Process 'turn' command.

        http://itcontest.ru/docs/games/tic-tac-toe/api/turn/
        """
        if 'game_field' not in data:
            self.send_error(400, explain="No 'game_field' found in data")
            return

        moves_allowed = []
        for coord_x in range(0, 3):
            for coord_y in range(0, 3):
                if data['game_field'][coord_x][coord_y] is None:
                    moves_allowed.append([coord_x, coord_y])

        if not len(moves_allowed):
            self.send_error(400, explain="No allowed moves found")
            return

        self.send_json_response({
            'secret': SECRET,
            'move': random.choice(moves_allowed),
        })

    def post_finish(self, data):
        """Process 'finish' command.

        http://itcontest.ru/docs/games/tic-tac-toe/api/finish/
        """
        self.send_empty_response()

    def post_error(self, data):
        """Process 'error' command.

        http://itcontest.ru/docs/games/tic-tac-toe/api/error/
        """
        self.send_empty_response()

    def handle_one_request(self):
        """Handle a single HTTP request."""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return

            if self.command not in ('GET', 'POST'):
                error_text = "Only 'GET' and 'POST' HTTP methods are allowed"
                self.send_error(400, explain=error_text)
                return

            get_params = parse_qs(urlparse(self.path).query)
            if 'method' not in get_params:
                self.send_error(400, explain="No API method defined")
                return

            api_method = get_params['method'][0]
            method_name = self.command.lower() + '_' + api_method
            if hasattr(self, method_name):
                cmd_method = getattr(self, method_name)
            else:
                error_text = "Unsupported API method {0} '{1}'".format(
                    self.command, api_method
                )
                self.send_error(400, explain=error_text)
                return

            request_data = None
            if self.command == 'POST':
                content_length = self.headers.get('content-length')
                if content_length:
                    try:
                        content_length = int(content_length)
                    except (ValueError, TypeError):
                        error_text = "'Content-Length' header is wrong"
                        self.send_error(400, explain=error_text)
                        return
                else:
                    error_text = "'Content-Length' header is not defined"
                    self.send_error(400, explain=error_text)
                    return

                content_type_header = self.headers.get('content-type')
                if not content_type_header:
                    error_text = "'Content-Type' header is not defined"
                    self.send_error(400, explain=error_text)
                    return

                try:
                    content_type, __ = cgi.parse_header(content_type_header)
                except TypeError:
                    error_text = "'Content-Type' header is wrong"
                    self.send_error(400, explain=error_text)
                    return

                if content_type != 'application/json':
                    error_text = "Only 'JSON' requests are supported"
                    self.send_error(400, explain=error_text)
                    return

                try:
                    request_data = json.loads(
                        str(self.rfile.read(content_length), 'utf-8')
                    )
                except ValueError:
                    self.send_error(400, explain="Can't parse JSON data")
                    return

            cmd_method(request_data)
            self.wfile.flush()
        except socket.timeout as e:
            # a read or a write timed out, discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return


if __name__ == '__main__':
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except (ValueError, TypeError):
            print("Usage: python {0} [port_number]".format(sys.argv[0]))
            sys.exit(1)

    if not 1024 <= port <= 65535:
        print("Error: port number must be in range 1024-65535")
        sys.exit(1)

    try:
        server = http.server.HTTPServer(('localhost', port), Bot)
    except OSError as exc:
        print("Error: {0}".format(exc))
        sys.exit(1)

    print("Starting 'Tic tac toe' bot server at port {0}.".format(port))
    print("Quit the server with CONTROL-C.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('CONTROL-C received, shutting down server')
        server.socket.close()
