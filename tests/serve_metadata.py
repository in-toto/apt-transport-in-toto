#!/usr/bin/python3
"""
<Program Name>
  serve_metadata.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  December 10, 2018.

<Purpose
  Super simple mock metadata server for rebuilder interface testing purposes.

  Starts a localhost SimpleHTTPServer on the passed PORT to serve a metadata
  file from the passed METADATA_PATH on an incoming METADATA_REQUEST. Any other
  request is handled as usual by SimpleHTTPServer. Shuts down on SIGINT.

  Example Usage:

  python serve_metadata.py 8000 /sources/final-product/0.0.0.0-0/metadata \
      /absolute/path/to/rebuild.5863835e.link

"""
import sys
import socketserver
import http.server as SimpleHTTPServer

PORT = sys.argv[1]
METADATA_REQUEST = sys.argv[2]
METADATA_PATH = sys.argv[3]


class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        """Intercept file requests to path in METADATA_REQUEST and serve file
         from METADATA_PATH.
        """
        if path == METADATA_REQUEST:
            return METADATA_PATH
        return SimpleHTTPServer.SimpleHTTPRequestHandler.translate_path(
            self, path)


socketserver.TCPServer.allow_reuse_address = True
server = socketserver.TCPServer(("", int(PORT)), CustomHandler)
try:
    # Serve until KeyboardInterrupt (SIGTERM)
    server.serve_forever()
except KeyboardInterrupt:
    server.server_close()
