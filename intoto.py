#!/usr/bin/python3
"""
<Program Name>
  intoto.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  November 22, 2018.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide an in-toto transport method for apt to perform in-toto
  verification using in-toto link metadata fetched from a rebuilder.

  - This program must be installed as executable in
      `/usr/lib/apt/methods/intoto`.
  - It is executed for package sources in `/etc/apt/sources.list` or
    `/etc/apt/sources.list.d/*`, that have an `intoto` method prefix, e.g.
      `deb intoto://ftp.us.debian.org/debian/ jessie main contrib`
  - The in-toto transport uses the http transport to download the target debian
    packages.
  - Verification is performed on `apt-get install`, i.e. after the http
    transport has downloaded the package requested by apt and signals apt to
    install it, by sending the `201 URI Done` message.
  - Further messages may be intercepted from apt, e.g.
      `601 Configuration` to parse `Config-Item`s, or
      `600 URI Acquire` to check if a requested URI is an index file
      (`Index-File: true`), issued, e.g. on `apt-get update`.

  - An in-toto root layout must be present on the client system, the
    path may be specified in the method's config file, i.e.
      `/etc/apt/apt.conf.d/intoto`.
  - Corresponding layout root keys must be present in the client gpg chain
  - The base path of the remote rebuilder that hosts in-toto link metadata may
    be specified in the client method config file.
  - The full path of the in-toto link metadata for a given package is inferred
    from the configured base path and the package URI in `600 URI Acquire`.
  - That information may also be used for in-toto layout parameter
    substitution.

<Workflow>
  From the APT method interface definition::
  "The flow of messages starts with the method sending out a 100 Capabilities
  and APT sending out a 601 Configuration. After that APT begins sending 600
  URI Acquire and the method sends out 200 URI Start, 201 URI Done or 400 URI
  Failure. No synchronization is performed, it is expected that APT will send
  600 URI Acquire messages at -any- time and that the method should queue the
  messages. This allows methods like http to pipeline requests to the remote
  server. It should be noted however that APT will buffer messages so it is not
  necessary for the method to be constantly ready to receive them."

  NOTE: From what I've seen in the message flow between apt and the http
  transport, apt always starts the http transport subprocess twice. When apt
  receives the 100 Capabilities message from the http transport it starts the
  transport again, and sends a 601 Configuration message. The restart prompts
  the http transport to resend 100 Capabilities, which probably gets ignored.
  After that the normal message flow continues.

  Below diagram depicts the message flow between apt, intoto and http (process
  hierarchy left to right) to successfully download a debian package and
  perform in-toto verification. Note that intoto or http may send 10x logging
  or status messages or 40x failure messages, depending on the status/results
  of their work.


                APT
                 +                   intoto
                 |                     +                    http
                 |                     |                     +
                 |         ...         |  100 Capabilities   |
                 | <-----------------+ | <-----------------+ |
                 |   601 Configuration |         ...         |
                 | +-----------------> | +-----------------> |
                 |   600 URI Acquire   |         ...         |
                 | +-----------------> | +-----------------> |
                 |         ...         |     200 URI Start   |
                 | <-----------------+ | <-----------------+ |
                 |                     |                  Download package
                 |                     |                  from archive
                 |                     |    201 URI Done     |
                 |                     + <-----------------+ |
                 |             Download in-toto links        |
                 |             and verify package            |
                 |    201 URI Done     |                     |
                 + <-----------------+ +                     +


<Resources>
  APT method interface
  http://www.fifi.org/doc/libapt-pkg-doc/method.html/ch2.html

  Apt Configuration
  https://manpages.debian.org/stretch/apt/apt.conf.5.en.html

  Apt sources list syntax
  https://wiki.debian.org/SourcesList

"""
import os
import sys
import signal
import select
import threading
import logging
import logging.handlers
import requests
import tempfile
import shutil
import queue as Queue  # pylint: disable=import-error
import subprocess
import securesystemslib.gpg.functions

import in_toto.exceptions
import in_toto.verifylib
import in_toto.models.link
import in_toto.models.metadata

# Configure base logger with lowest log level (i.e. log all messages) and
# finetune the actual log levels on handlers
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# A file handler for debugging purposes
# NOTE: bandit security linter flags the use of /tmp because an attacker might
# hijack that file. This should not be a problem for logging since we don't
# read from the file nor expose sensitive data, hence we exclude with #nosec
# TODO: Maybe there is a better location for the log
LOG_FILE = "/tmp/intoto.log"  # nosec
LOG_HANDLER_FILE = logging.handlers.RotatingFileHandler(LOG_FILE)
LOG_HANDLER_FILE.setLevel(logging.DEBUG)
logger.addHandler(LOG_HANDLER_FILE)

# A stream handler (stderr), which can be configured in apt configuration file,
# e.g.: APT::Intoto::LogLevel::=10
# NOTE: Use file handler above to debug events prior to apt's `601
# CONFIGURATION` message which may set the SteamHandler's loglevel
LOG_HANDLER_STDERR = logging.StreamHandler()
LOG_HANDLER_STDERR.setLevel(logging.INFO)
logger.addHandler(LOG_HANDLER_STDERR)

APT_METHOD_HTTP = os.path.join(os.path.dirname(sys.argv[0]), "http")

# Global interrupted boolean. Apt may send SIGINT if it is done with its work.
# Upon reception we set INTERRUPTED to true, which may be used to gracefully
# terminate.
INTERRUPTED = False


# TODO: Maybe we can replace the signal handler with a KeyboardInterrupt
# try/except block in the main loop, for better readability.
def signal_handler(*junk):
    # Set global INTERRUPTED flag telling worker threads to terminate
    logger.debug("Received SIGINT, setting global INTERRUPTED true")
    global INTERRUPTED
    INTERRUPTED = True


# Global BROKENPIPE flag should be set to true, if a `write` or `flush` on a
# stream raises a BrokenPipeError, to gracefully terminate reader threads.
BROKENPIPE = False

# APT Method Interface Message definition
# The first line of each message is called the message header. The first 3
# digits (called the Status Code) have the usual meaning found in the http
# protocol. 1xx is informational, 2xx is successful and 4xx is failure. The 6xx
# series is used to specify things sent to the method. After the status code is
# an informational string provided for visual debugging
# Only the 6xx series of status codes is sent TO the method. Furthermore the
# method may not emit status codes in the 6xx range. The Codes 402 and 403
# require that the method continue reading all other 6xx codes until the proper
# 602/603 code is received. This means the method must be capable of handling
# an unlimited number of 600 messages.

# Message types by their status code. Each message type has an "info" and
# and the a list of allowed fields. MESSAGE_TYPE may be used to verify
# the format of the received messages.
CAPABILITES = 100
LOG = 101
STATUS = 102
URI_START = 200
URI_DONE = 201
URI_FAILURE = 400
GENERAL_FAILURE = 401
AUTH_REQUIRED = 402
MEDIA_FAILURE = 403
URI_ACQUIRE = 600
CONFIGURATION = 601
AUTH_CREDENTIALS = 602
MEDIA_CHANGED = 603

MESSAGE_TYPE = {
    # Method capabilities
    CAPABILITES: {
        "info": "Capabilities",
        "fields": [
            "Version", "Single-Instance", "Pre-Scan", "Pipeline",
            "Send-Config", "Needs-Cleanup"
        ]
    },
    # General Logging
    LOG: {
        "info": "Log",
        "fields": ["Message"]
    },
    # Inter-URI status reporting (logging progress)
    STATUS: {
        "info": "Status",
        "fields": ["Message"]
    },
    # URI is starting acquire
    URI_START: {
        "info": "URI Start",
        "fields": ["URI", "Size", "Last-Modified", "Resume-Point"]
    },
    # URI is finished acquire
    URI_DONE: {
        "info": "URI Done",
        "fields": [
            "URI", "Size", "Last-Modified", "Filename", "MD5-Hash",
            # NOTE: Although not documented we need to include all these hash algos
            # https://www.lucidchart.com/techblog/2016/06/13/apt-transport-for-s3/
            "MD5Sum-Hash", "SHA1-Hash", "SHA256-Hash", "SHA512-Hash"
        ]
    },
    # URI has failed to acquire
    URI_FAILURE: {
        "info": "URI Failure",
        "fields": ["URI", "Message"]
    },
    # Method did not like something sent to it
    GENERAL_FAILURE: {
        "info": "General Failure",
        "fields": ["Message"]
    },
    # Method requires authorization to access the URI.
    # Authorization is User/Pass
    AUTH_REQUIRED: {
        "info": "Authorization Required",
        "fields": ["Site"]
    },
    # Method requires a media change
    MEDIA_FAILURE: {
        "info": "Media Failure",
        "fields": ["Media", "Drive"]
    },
    # Request a URI be acquired
    URI_ACQUIRE: {
        "info": "URI Acquire",
        "fields": ["URI", "Filename", "Last-Modified"]
    },
    # Sends the configuration space
    CONFIGURATION: {
        "info": "Configuration",
        "fields": ["Config-Item"]
    },
    # Response to the 402 message
    AUTH_CREDENTIALS: {
        "info": "Authorization Credentials",
        "fields": ["Site", "User", "Password"]
    },
    # Response to the 403 message
    MEDIA_CHANGED: {
        "info": "Media Changed",
        "fields": ["Media", "Fail"]
    }
}


def deserialize_one(message_str):
    """Parse raw message string as it may be read from stdin and return a
    dictionary that contains message header status code and info and an optional
    fields dictionary of additional headers and their values.

    Raise Exception if the message is malformed. See MESSAGE_TYPE for
    details about formats.
    NOTE: We are pretty strict about the format of messages that we receive.
    Given the vagueness of the specification, we might be too strict.

    {
      "code": <status code>,
      "info": "<status info>",
      "fields": [
        ("<header field name>", "<value>"),
      ]
    }

    NOTE: Message field values are NOT deserialized here, e.g. the Last-Modified
    time stamp remains a string and Config-Item remains a string of item=value
    pairs.

    """
    lines = message_str.splitlines()
    if not lines:
        raise Exception("Invalid empty message:\n{}".format(message_str))

    # Deserialize message header
    message_header = lines.pop(0)
    message_header_parts = message_header.split()

    # TODO: Are we too strict about the format (should we not care about info?)
    if len(message_header_parts) < 2:
        raise Exception("Invalid message header: {}, message was:\n{}"
                        .format(message_header, message_str))

    code = None
    try:
        code = int(message_header_parts.pop(0))
    except ValueError:
        pass

    if not code or code not in list(MESSAGE_TYPE.keys()):
        raise Exception(
            "Invalid message header status code: {}, message was:\n{}"
            .format(code, message_str))

    # TODO: Are we too strict about the format (should we not care about info?)
    info = " ".join(message_header_parts).strip()
    if info != MESSAGE_TYPE[code]["info"]:
        raise Exception("Invalid message header info for status code {}:\n{},"
                        " message was: {}".format(code, info, message_str))

    # TODO: Should we assert that the last line is a blank line?
    if lines and not lines[-1]:
        lines.pop()

    # Deserialize header fields
    header_fields = []
    for line in lines:

        header_field_parts = line.split(":")

        if len(header_field_parts) < 2:
            raise Exception("Invalid header field: {}, message was:\n{}"
                            .format(line, message_str))

        field_name = header_field_parts.pop(0).strip()

        if field_name not in MESSAGE_TYPE[code]["fields"]:  # pragma: no cover
            logger.debug("Undefined header field for message code {}: {},"
                         .format(code, field_name))

        field_value = ":".join(header_field_parts).strip()
        header_fields.append((field_name, field_value))

    # Construct message data
    message_data = {
        "code": code,
        "info": info
    }
    if header_fields:
        message_data["fields"] = header_fields

    return message_data


def serialize_one(message_data):
    """Create a message string that may be written to stdout. Message data
    is expected to have the following format:
    {
      "code": <status code>,
      "info": "<status info>",
      "fields": [
        ("<header field name>", "<value>"),
      ]
    }

    """
    message_str = ""

    # Code must be present
    code = message_data["code"]
    # Convenience (if info not present, info for code is used )
    info = message_data.get("info") or MESSAGE_TYPE[code]["info"]

    # Add message header
    message_str += "{} {}\n".format(code, info)

    # Add message header fields and values (must be list of tuples)
    for field_name, field_value in message_data.get("fields", []):
        message_str += "{}: {}\n".format(field_name, field_value)

    # Blank line to mark end of message
    message_str += "\n"

    return message_str


def read_one(stream):
    """Read one apt related message from the passed stream, e.g. sys.stdin for
    messages from apt, or subprocess.stdout for messages from a transport that we
    open in a subprocess. The end of a message (EOM) is denoted by a blank line
    ("\n") and end of file (EOF) is denoted by an empty line. Returns either a
    message including a trailing blank line or None on EOF.

    """
    message_str = ""
    # Read from stream until we get a SIGINT/BROKENPIPE, or reach EOF (see below)
    # TODO: Do we need exception handling for the case where we select/read from
    # a stream that was closed? If so, we should do it in the main loop for
    # better readability.
    while not (INTERRUPTED or BROKENPIPE):  # pragma: no branch
        # Only read if there is data on the stream (non-blocking)
        if not select.select([stream], [], [], 0)[0]:
            continue

        # Read one byte from the stream
        one = os.read(stream.fileno(), 1).decode()

        # Break on EOF
        if not one:
            break

        # If we read something append it to the message string
        message_str += one

        # Break on EOM (and return message below)
        if len(message_str) >= 2 and message_str[-2:] == "\n\n":
            break

    # Return a message if there is one, otherwise return None
    if message_str:
        return message_str

    return None


def write_one(message_str, stream):
    """Write the passed message to the passed stream.

    """
    try:
        stream.write(message_str)
        stream.flush()

    except BrokenPipeError:
        # TODO: Move exception handling to main loop for better readability
        global BROKENPIPE
        BROKENPIPE = True
        logger.debug("BrokenPipeError while writing '{}' to '{}'.".format(
            message_str, stream))
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown
        # See https://docs.python.org/3/library/signal.html#note-on-sigpipe
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


def notify_apt(code, message_text, uri):
    # Escape LF and CR characters in message bodies to not break the protocol
    message_text = message_text.replace("\n", "\\n").replace("\r", "\\r")
    # NOTE: The apt method interface spec references RFC822, which doesn't allow
    # LF or CR in the message body, except if followed by a LWSP-char (i.e. SPACE
    # or HTAB, for "folding" of long lines). But apt does not seem to support
    # folding, and splits lines only at LF. To be safe we escape LF and CR.
    # See 2.1 Overview in www.fifi.org/doc/libapt-pkg-doc/method.html/ch2.html
    # See "3.1.1. LONG HEADER FIELDS" and  "3.1.2. STRUCTURE OF HEADER FIELDS" in
    # www.ietf.org/rfc/rfc822.txt

    write_one(serialize_one({
        "code": code,
        "info": MESSAGE_TYPE[code]["info"],
        "fields": [
            ("Message", message_text),
            ("URI", uri)
        ]
    }), sys.stdout)


def read_to_queue(stream, queue):
    """Loop to read messages one at a time from the passed stream until EOF,
     i.e. the returned message is None, and write to the passed queue.

    """
    while True:
        msg = read_one(stream)
        if not msg:
            return None

        queue.put(msg)


# Dict to keep some global state, i.e. we need information from earlier
# messages (e.g. CONFIGURATION) when doing in-toto verification upon URI_DONE.
global_info = {
    "config": {
        "Rebuilders": [],
        "GPGHomedir": "",
        "Layout": "",
        "Keyids": [],
        "NoFail": False
    }
}


def _intoto_parse_config(message_data):
    """Upon apt `601 Configuration` parse intoto config items and assign to
    global config store. Example message data:
    {
      'code': 601,
      'info': 'Configuration'
      'fields': [
        ('Config-Item', 'APT::Intoto::Rebuilders::=http://158.39.77.214/'),
        ('Config-Item', 'APT::Intoto::Rebuilders::=https://reproducible-builds.engineering.nyu.edu/'),
        ('Config-Item', 'APT::Intoto::GPGHomedir::=/path/to/gpg/keyring'),
        ('Config-Item', 'APT::Intoto::Layout::=/path/to/root.layout'),
        ('Config-Item', 'APT::Intoto::Keyids::=88876A89E3D4698F83D3DB0E72E33CA3E0E04E46'),
        ('Config-Item', 'APT::Intoto::LogLevel::=10'),
        ('Config-Item', 'APT::Intoto::NoFail::=true'),
         ...
      ],
    }

    """
    for field_name, field_value in message_data["fields"]:
        if field_name == "Config-Item" and field_value.startswith(
                "APT::Intoto"):
            # Dissect config item
            logger.debug(field_value)
            _, _, config_name, config_value = field_value.split("::")
            # Strip leading "=", courtesy of apt config
            config_value = config_value.lstrip("=")

            # Assign exhaustive intoto configs
            if config_name in ["Rebuilders", "Keyids"]:
                global_info["config"][config_name].append(config_value)

            elif config_name in ["GPGHomedir", "Layout"]:
                global_info["config"][config_name] = config_value

            elif config_name == "LogLevel":
                try:
                    LOG_HANDLER_STDERR.setLevel(int(config_value))
                    logger.debug(
                        "Set stderr LogLevel to '{}'".format(config_value))

                except Exception:
                    logger.warning(
                        "Ignoring unknown LogLevel '{}'".format(config_value))

            elif config_name == "NoFail" and config_value == "true":
                global_info["config"][config_name] = True

            else:
                logger.warning(
                    "Skipping unknown config item '{}'".format(field_value))

    logger.debug(
        "Configured intoto session: '{}'".format(global_info["config"]))


def _intoto_verify(message_data):
    """Upon http `201 URI Done` check if the downloaded package is in the global
    package store (see `_intoto_parse_package`), to filter out index files and
    perform in-toto verification using the session config (see
    `_intoto_parse_config`). Example message data:

    {
      'code': 201,
      'info': 'URI Done'
      'fields': [
        ('URI', 'intoto://www.example.com/~foo/debian/pool/main/cowsay_3.03+dfsg1-10_all.deb'),
        ('Filename', '/var/cache/apt/archives/partial/cowsay_3.03+dfsg1-10_all.deb'),
        ('Size', '20020'),
        ('Last-Modified', 'Mon, 26 Nov 2018 14:39:07 GMT'),
        ('MD5-Hash', '071b...'),
        ('MD5Sum-Hash', '071b...'),
        ('SHA1-Hash', '3794...'),
        ('SHA256-Hash', 'fd04...'),
        ('SHA512-Hash','95bc...'),
        ...
      ],
    }

    """
    # Get location of file that was downloaded
    filename = dict(message_data["fields"]).get("Filename", "")
    uri = dict(message_data["fields"]).get("URI", "")

    # Parse package name and version-release according to naming convention:
    #    packagename_version-release_architecture.deb
    # If we can parse packagename and version-release we will try in-toto
    # verification
    pkg_name = pkg_version_release = None
    if filename.endswith(".deb"):
        pkg_name_parts = os.path.basename(filename).split("_")
        if len(pkg_name_parts) == 3:
            pkg_name = pkg_name_parts[0]
            pkg_version_release = pkg_name_parts[1]

    if not (pkg_name and pkg_version_release):
        logger.info("Skipping in-toto verification for '{}'".format(filename))
        return True

    logger.info("Prepare in-toto verification for '{}'".format(filename))

    # Create temp dir
    verification_dir = tempfile.mkdtemp()
    logger.info("Create verification directory '{}'"
                .format(verification_dir))

    logger.info("Request in-toto metadata from {} rebuilder(s) (apt config)"
                .format(len(global_info["config"]["Rebuilders"])))
    # Download link files to verification directory
    for rebuilder in global_info["config"]["Rebuilders"]:
        # Accept rebuilders with and without trailing slash
        endpoint = "{rebuilder}/sources/{name}/{version}/metadata".format(
            rebuilder=rebuilder.rstrip("/"), name=pkg_name,
            version=pkg_version_release)

        logger.info("Request in-toto metadata from {}".format(endpoint))

        try:
            # Fetch metadata
            response = requests.get(endpoint)
            if not response.status_code == 200:
                raise Exception(
                    "server response: {}".format(response.status_code))

            # Decode json
            link_json = response.json()

            # Load as in-toto metadata
            link_metablock = in_toto.models.metadata.Metablock(
                signatures=link_json["signatures"],
                signed=in_toto.models.link.Link.read(link_json["signed"]))

            # Construct link name as required by in-toto verification
            link_name = in_toto.models.link.FILENAME_FORMAT.format(
                keyid=link_metablock.signatures[0]["keyid"],
                step_name=link_metablock.signed.name)

            # Write link metadata to temporary verification directory
            link_metablock.dump(os.path.join(verification_dir, link_name))

        except Exception as e:
            # We don't fail just yet if metadata cannot be downloaded or stored
            # successfully. Instead we let in-toto verification further below
            # fail if there is not enought metadata
            logger.warning(
                "Could not retrieve in-toto metadata from rebuilder '{}',"
                " reason was: {}".format(rebuilder, e))
            continue

        else:
            logger.info("Successfully downloaded in-toto metadata '{}'"
                        " from rebuilder '{}'".format(link_name, rebuilder))

    # Copy final product downloaded by http to verification directory
    logger.info("Copy final product to verification directory")
    shutil.copy(filename, verification_dir)

    # Temporarily change to verification, changing back afterwards
    cached_cwd = os.getcwd()
    os.chdir(verification_dir)

    try:
        logger.info("Load in-toto layout '{}' (apt config)"
                    .format(global_info["config"]["Layout"]))

        layout = in_toto.models.metadata.Metablock.load(
            global_info["config"]["Layout"])

        keyids = global_info["config"]["Keyids"]
        gpg_home = global_info["config"]["GPGHomedir"]

        logger.info("Load in-toto layout key(s) '{}' (apt config)".format(
            global_info["config"]["Keyids"]))
        if gpg_home:
            logger.info("Use gpg keyring '{}' (apt config)".format(gpg_home))
            layout_keys = securesystemslib.gpg.functions.export_pubkeys(
                keyids, homedir=gpg_home)
        else:  # pragma: no cover
            logger.info("Use default gpg keyring")
            layout_keys = securesystemslib.gpg.functions.export_pubkeys(keyids)

        logger.info("Run in-toto verification")

        # Run verification
        in_toto.verifylib.in_toto_verify(layout, layout_keys)

    except Exception as e:
        error_msg = ("In-toto verification for '{}' failed, reason was: {}"
                     .format(filename, str(e)))
        logger.error(error_msg)

        if (isinstance(e, in_toto.exceptions.LinkNotFoundError) and
                global_info["config"].get("NoFail")):
            logger.warning("The 'NoFail' setting was configured,"
                           " installation continues.")

        else:
            # Notify apt about the failure ...
            notify_apt(URI_FAILURE, error_msg, uri)
            # ... and do not relay http's URI Done
            # (so that apt does not install it)
            return False

    else:
        logger.info("In-toto verification for '{}' passed! :)".format(filename))

    finally:
        os.chdir(cached_cwd)
        shutil.rmtree(verification_dir)

    # If we got here verification was either skipped (non *.deb file) or passed,
    # we can relay the message.
    return True


def handle(message_data):
    """Handle passed message to parse configuration and perform in-toto
    verification. The format of message_data is:
    {
      "code": <status code>,
      "info": "<status info>",
      "fields": [
        ("<header field name>", "<value>"),
      ]
    }
    Return a boolean value that can be used to decide, whether the message
    should be relayed or not.

    """
    logger.debug("Handling message: {}".format(message_data["code"]))
    # Parse out configuration data required for in-toto verification below
    if message_data["code"] == CONFIGURATION:
        _intoto_parse_config(message_data)

    # Perform in-toto verification for non-index files
    # The return value decides if the message should be relayed or not
    elif message_data["code"] == URI_DONE:
        return _intoto_verify(message_data)

    # All good, we can relay the message
    return True


def loop():
    """Main in-toto http transport method loop to relay messages between apt and
    the apt http transport method and inject in-toto verification upon reception
    of a particular message.

    """
    # Start http transport in a subprocess
    # Messages from the parent process received on sys.stdin are relayed to the
    # subprocess' stdin and vice versa, messages written to the subprocess'
    # stdout are relayed to the parent via sys.stdout.
    http_proc = subprocess.Popen([APT_METHOD_HTTP], stdin=subprocess.PIPE,
                                 # nosec
                                 stdout=subprocess.PIPE,
                                 universal_newlines=True)

    # HTTP transport message reader thread to add messages from the http
    # transport (subprocess) to a corresponding queue.
    http_queue = Queue.Queue()
    http_thread = threading.Thread(target=read_to_queue,
                                   args=(http_proc.stdout, http_queue))

    # APT message reader thread to add messages from apt (parent process)
    # to a corresponding queue.
    apt_queue = Queue.Queue()
    apt_thread = threading.Thread(target=read_to_queue,
                                  args=(sys.stdin, apt_queue))

    # Start reader threads.
    # They will run until they see an EOF on their stream, or the global
    # INTERRUPTED or BROKENPIPE flags are set to true.
    http_thread.start()
    apt_thread.start()

    # Main loop to get messages from queues, i.e. apt queue and http transport
    # queue, and relay them to the corresponding streams, injecting in-toto
    # verification upon reception of a particular message.
    while True:
        for name, queue, out in [
            ("apt", apt_queue, http_proc.stdin),
            ("http", http_queue, sys.stdout)
        ]:

            should_relay = True
            try:
                message = queue.get_nowait()
                logger.debug("{} sent message:\n{}".format(name, message))
                message_data = deserialize_one(message)

            except Queue.Empty:
                continue

            # De-serialization error: Skip message handling, but do relay.
            except Exception as e:
                logger.debug("Cannot handle message, reason is {}".format(e))

            else:
                # Read config, perform in-toto verification in there we also
                # decide whether we should relay the message or not.
                logger.debug("Handle message")
                should_relay = handle(message_data)

            if should_relay:
                logger.debug("Relay message")
                write_one(message, out)

        # Exit when both threads have terminated (EOF, INTERRUPTED or BROKENPIPE)
        # NOTE: We do not check if there are still messages on the streams or
        # in the queue, assuming that there aren't or we can ignore them if both
        # threads have terminated.
        if (not apt_thread.is_alive() and not http_thread.is_alive()):
            logger.debug(
                "The worker threads are dead. Long live the worker threads!"
                "Terminating.")

            # If INTERRUPTED or BROKENPIPE are true it (likely?) means that apt
            # sent a SIGINT or closed the pipe we were writing to. This means we
            # should exit and tell the http child process to exit too.
            # TODO: Could it be that the http child closed a pipe or sent a SITERM?
            # TODO: Should we behave differently for the two signals?
            if INTERRUPTED or BROKENPIPE:  # pragma: no branch
                logger.debug("Relay SIGINT to http subprocess")
                http_proc.send_signal(signal.SIGINT)

            return


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    loop()
