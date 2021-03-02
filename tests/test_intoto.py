#!/usr/bin/python3
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
  subprocess, which reads relayed messages and replies accordingly.

<Usage>
  python -m unittest tests.test_intoto

"""
import os
import sys
import unittest
import signal
import intoto
import logging

if sys.version_info[0] == 2:
    import subprocess32 as subprocess
else:
    import subprocess

LOG_LEVEL = logging.INFO
TEST_PATH = os.path.dirname(os.path.realpath(__file__))
TEST_DATA_PATH = os.path.join(TEST_PATH, "data")

# Paths to two versions of the final product, one with a hash that matches
# the product of the rebuild step (as per link metadata) and one that does not.
FINAL_PRODUCT_PATH_GOOD = os.path.join(
    TEST_DATA_PATH, "good", "final-product_0.0.0.0-0_all.deb")
FINAL_PRODUCT_PATH_BAD = os.path.join(
    TEST_DATA_PATH, "bad", "final-product_0.0.0.0-0_all.deb")

# Absolute path to intoto transport. It will use this path (argv[0])
# to find the http transport.
INTOTO_EXEC = os.path.join(TEST_PATH, "..", "intoto.py")

# The mock apt routine of this test does not call the intoto transport directly
# but instead calls a shim that enables subprocess test code coverage
MEASURE_COVERAGE = os.path.join(TEST_PATH, "measure_coverage.py")
# The subprocess test code coverage requires below envvar
os.environ['COVERAGE_PROCESS_START'] = os.path.join(
    TEST_PATH, "..", ".coveragerc")

# Path to mock rebuilder server executable
MOCK_REBUILDER_EXEC = os.path.join(TEST_PATH, "serve_metadata.py")

# Default values for the `601 Configuration` and `600 URI Acquire` message
# used in tests below. May be overridden in a test.
_CONFIG_DEFAULTS = {
    "log_level": LOG_LEVEL,
    "rebuilder1": "http://127.0.0.1:8081",
    "rebuilder2": "http://127.0.0.1:8082",
    "layout_path": os.path.join(TEST_DATA_PATH, "test.layout"),
    "layout_keyid": "88876A89E3D4698F83D3DB0E72E33CA3E0E04E46",
    "gpg_home": os.path.join(TEST_DATA_PATH, "gpg_keyring"),
    "no_fail": "false"
}
_ACQUIRE_DEFAULTS = {
    "filename": FINAL_PRODUCT_PATH_GOOD
}

# Message scaffoldings used in tests below. `_MSG_CAPABILITIES` and
# `_MSG_URI_DONE` are sent by the mock http transport and `_MSG_CONFIG` and
# `_MSG_ACQUIRE` by the mock apt.
_MSG_CAPABILITIES = \
    """100 Capabilities

    """
_MSG_CONFIG = \
    """601 Configuration
    Config-Item: APT::Intoto::Rebuilders::={rebuilder1}
    Config-Item: APT::Intoto::Rebuilders::={rebuilder2}
    Config-Item: APT::Intoto::LogLevel::={log_level}
    Config-Item: APT::Intoto::Layout::={layout_path}
    Config-Item: APT::Intoto::Keyids::={layout_keyid}
    Config-Item: APT::Intoto::GPGHomedir::={gpg_home}
    Config-Item: APT::Intoto::NoFail::={no_fail}

    """
_MSG_ACQUIRE = \
    """600 URI Acquire
    Filename: {filename}

    """
_MSG_URI_DONE = \
    """201 URI Done
    Filename: {filename}

    """


def mock_http():
    """Mock basic http transport series of message writes and reads. """
    try:
        # Send capabilities
        intoto.write_one(_MSG_CAPABILITIES, sys.stdout)
        # Wait for CONFIGURATION and ignore
        intoto.read_one(sys.stdin)
        # Wait for URI Acquire
        acquire_msg = intoto.deserialize_one(intoto.read_one(sys.stdin))
        # send URI Done
        intoto.write_one(_MSG_URI_DONE.format(
            filename=dict(acquire_msg["fields"]).get("Filename", "")),
            sys.stdout)

    except KeyboardInterrupt:
        return


def mock_apt(intoto_proc, config_args=None, acquire_args=None):
    """Mock basic apt series of message reads and writes.

    Messages scaffoldings and message parameters are defined above but may be
    overridden using arguments config_args and acquire_args.

    """
    if not config_args:
        config_args = {}
    if not acquire_args:
        acquire_args = {}

    # Wait for Capabilities,
    intoto.read_one(intoto_proc.stdout)
    # Send Config
    intoto.write_one(_MSG_CONFIG.format(
        **dict(_CONFIG_DEFAULTS, **config_args)), intoto_proc.stdin)
    # Send URI Acquire
    intoto.write_one(_MSG_ACQUIRE.format(
        **dict(_ACQUIRE_DEFAULTS, **acquire_args)), intoto_proc.stdin)
    # Wait for URI Done
    return intoto.deserialize_one(intoto.read_one(intoto_proc.stdout))


class InTotoTransportTestCase(unittest.TestCase):
    """Test class to mock routines as would be triggered by `apt-get install`.
    Each test mocks an installation with different parameters, asserting for
    passing or failing in-toto verification.

    """

    @classmethod
    def setUpClass(self):
        """Start two mock rebuilder servers on localhost, each of which serving a
        rebuild link metadata as required by the layout and the final product used
        in below tests. These rebuilders may be re-used for all tests of this
        class.

        """
        # The request both servers listen for to serve metadata_file defined below
        self.metadata_request = "/sources/final-product/0.0.0.0-0/metadata"
        self.rebuilder_procs = []
        for port, metadata_file in [
            ("8081", "rebuild.5863835e.link"),
            ("8082", "rebuild.e946fc60.link")]:
            metadata_path = os.path.join(TEST_DATA_PATH, metadata_file)
            self.rebuilder_procs.append(subprocess.Popen(
                ["python3", MOCK_REBUILDER_EXEC, port, self.metadata_request,
                 metadata_path], stderr=subprocess.DEVNULL))

    @classmethod
    def tearDownClass(self):
        """Tell mock rebuilder servers to shutdown and wait until they did. """
        for rebuilder_proc in self.rebuilder_procs:
            rebuilder_proc.send_signal(signal.SIGINT)
        for rebuilder_proc in self.rebuilder_procs:
            rebuilder_proc.wait()

    def setUp(self):
        """Start intoto transport anew for each test. """
        self.intoto_proc = subprocess.Popen(
            ["python3", MEASURE_COVERAGE, INTOTO_EXEC],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            # stderr=subprocess.DEVNULL, # NOTE: Unomment for less verbose test log
            universal_newlines=True)

    def tearDown(self):
        """Tell intoto transport to shutdown and wait until it did. We also
        have to close the opened subprocess pipes.
        """
        self.intoto_proc.stdin.close()
        self.intoto_proc.stdout.close()
        self.intoto_proc.send_signal(signal.SIGINT)
        self.intoto_proc.wait()

    def test_pass(self):
        """Verification passes. """
        result = mock_apt(self.intoto_proc)
        self.assertEqual(result["code"], intoto.URI_DONE)

    def test_bad_target(self):
        """Verification fails due to final product with bad hash. """
        result = mock_apt(self.intoto_proc,
                          acquire_args={"filename": FINAL_PRODUCT_PATH_BAD})
        self.assertEqual(result["code"], intoto.URI_FAILURE)

    def test_bad_target_nofail(self):
        """Verification fails due to final product with bad hash despite nofail
        option. NOTE: Nofail is only used if the fail reason is missing links.
        """
        result = mock_apt(self.intoto_proc,
                          config_args={"no_fail": "true"},
                          acquire_args={"filename": FINAL_PRODUCT_PATH_BAD})
        self.assertEqual(result["code"], intoto.URI_FAILURE)

    def test_missing_links(self):
        """Verification fails due to missing links. """
        # Override address of one rebuilder (there is no rebuilder on port 8083)
        result = mock_apt(self.intoto_proc,
                          config_args={"rebuilder1": "http://127.0.0.1:8083"})
        self.assertEqual(result["code"], intoto.URI_FAILURE)

    def test_missing_links_nofail(self):
        """Verification passes despite missing links because of nofail
        option.
        """
        result = mock_apt(self.intoto_proc,
                          config_args={"rebuilder1": "http://127.0.0.1:8083",
                                       "no_fail": "true"})
        self.assertEqual(result["code"], intoto.URI_DONE)

    def test_missing_links_404(self):
        """Verification fails due to missing links (rebuilder 404). """
        # Start another mock rebuilder that 404s on the expected request
        # To be sure, let's first assert that it will indeed not find anything
        self.assertFalse(
            os.path.exists(os.path.abspath(self.metadata_request.lstrip("/"))))
        rebuilder_proc = subprocess.Popen(
            ["python3", MOCK_REBUILDER_EXEC, "8083", "/", "/"],
            stderr=subprocess.DEVNULL)

        result = mock_apt(self.intoto_proc,
                          config_args={"rebuilder1": "http://127.0.0.1:8083"})
        self.assertEqual(result["code"], intoto.URI_FAILURE)

        rebuilder_proc.send_signal(signal.SIGINT)
        rebuilder_proc.wait()


if __name__ == "__main__":
    unittest.main()
