#!/usr/bin/env python
"""
<Program Name>
  test_intoto.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  December 06, 2018.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Mock basic apt <--> intoto <--> http message flow. The main TestCase below
  mocks (apt), which calls the intoto transport in a subprocess, reading and
  writing messages according to the basic message flow. The intoto transport
  starts the mock http transport (implemented in mock_http) also in a
  subprocess,  which reads relayed messages and replies accordingly.

<Usage>
  python -m unittest tests.test_intoto

"""
import os
import sys
import unittest
import subprocess32 as subprocess
import signal
import intoto



TEST_DATA_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "test_data")

LAYOUT_PATH = os.path.join(TEST_DATA_PATH, "root.layout")
GPG_KEYRING = os.path.join(TEST_DATA_PATH, "gpg_keyring")
LAYOUT_KEY_ID = "88876A89E3D4698F83D3DB0E72E33CA3E0E04E46"

FINAL_PRODUCT_PATH = os.path.join(TEST_DATA_PATH,
    "final-product_0.0.0.0-0_all.deb")

# Messages are stripped to contain only the required fields for this test
_MSG_CAPABILITIES = \
"""100 Capabilities

"""
_MSG_CONFIG = \
"""601 Configuration
Config-Item: APT::Intoto::Rebuilders::=127.0.0.1:8081/
Config-Item: APT::Intoto::Rebuilders::=127.0.0.1:8082/
Config-Item: APT::Intoto::Layout::={}
Config-Item: APT::Intoto::Keyid::={}
Config-Item: APT::Intoto::GPGHomedir::={}

""".format(LAYOUT_PATH, LAYOUT_KEY_ID, GPG_KEYRING)

_MSG_ACQUIRE = \
"""600 URI Acquire
Filename: {}

""".format(FINAL_PRODUCT_PATH)

_MSG_URI_DONE = \
"""201 URI Done
Filename: {}

""".format(FINAL_PRODUCT_PATH)

def _send(msg, stream):
  """Use intoto `write_one` to send a message to the passed stream. """
  intoto.write_one(msg, stream)

def _recv(stream):
  """Use intoto `read_one` from passed stream to block until one message is
  received. """
  intoto.read_one(stream)

def mock_http():
  """Mock basic http transport, reading and writing messages relayed by intoto
  transport.

  """
  try:
    # Send capabilities
    _send(_MSG_CAPABILITIES, sys.stdout)
    # Wait for CONFIGURATION
    _recv(sys.stdin)
    # Wait for URI Acquire
    _recv(sys.stdin)
    # send URI Done
    _send(_MSG_URI_DONE, sys.stdout)

  except KeyboardInterrupt:
    return


class InTotoTransportTestCase(unittest.TestCase):
  def test_basic_message_flow(self):
    """Mock basic apt process that starts and communicates with the intoto
    transport. """
    # Build absolute path to intoto transport. It will use this path (argv[0])
    # to find the http transport.
    intoto_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "intoto.py")

    # Run intoto.py transport as subprocess with stdin, stdout pipe
    intoto_proc = subprocess.Popen(["python", intoto_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)


    """
    Create subprocesses that each serve a filefrom
    localhost:8081 "sources/final-product/0.0.0.0-0/metadata" --> rebuild.5863835e.link
    localhost:8082 "sources/final-product/0.0.0.0-0/metadata" --> rebuild.e946fc60.link
    """

    # Wait for Capabilities
    _recv(intoto_proc.stdout)
    # Send Config
    _send(_MSG_CONFIG, intoto_proc.stdin)
    # Send URI Acquire
    _send(_MSG_ACQUIRE, intoto_proc.stdin)
    # Wait for URI Done
    _recv(intoto_proc.stdout)
    # Send EOF and SIGINT
    intoto_proc.stdin.close()
    intoto_proc.send_signal(signal.SIGINT)


if __name__ == "__main__":
  unittest.main()