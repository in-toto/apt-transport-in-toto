#!/usr/bin/env python
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
import time
import signal
import select
import threading
import Queue
import logging
import logging.handlers
import subprocess32 as subprocess

# TODO: Should we setup a SysLogHandler and write to /var/log/apt/intoto ?
LOG_FILE = "/tmp/intoto.log"
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.handlers.RotatingFileHandler(LOG_FILE))

APT_METHOD_HTTP = os.path.join(os.path.dirname(sys.argv[0]), "http")

# Global interrupted boolean. Apt may send SIGINT if it is done with its work.
# Upon reception we set INTERRUPTED to true, which may be used to gracefully
# terminate.
INTERRUPTED = False
def signal_handler(signal, frame):
  # Set global INTERRUPTED flag telling worker threads to terminate
  global INTERRUPTED
  INTERRUPTED = True

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
    "fields": ["Version", "Single-Instance", "Pre-Scan", "Pipeline",
        "Send-Config", "Needs-Cleanup"]
  },
  # General Logging
  LOG: {
    "info": "Log",
    "fields": ["Message"]
  },
  # Inter-URI status reporting (login progress)
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
    "fields": ["URI", "Size", "Last-Modified", "Filename", "MD5-Hash",
      # NOTE: Although not documented we need to include all these hash algos
      # https://www.lucidchart.com/techblog/2016/06/13/apt-transport-for-s3/
      "MD5Sum-Hash", "SHA1-Hash", "SHA256-Hash", "SHA512-Hash"]
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
  # Method requires authorization to access the URI. Authorization is User/Pass
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

  code = int(message_header_parts.pop(0))
  if code not in MESSAGE_TYPE.keys():
    raise Exception("Invalid message header status code: {}, message was:\n{}"
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

    if field_name not in MESSAGE_TYPE[code]["fields"]:
      logger.warning("Unsupported header field for message code {}: {},"
          " message was:\n{}".format(code, field_name, message_str))

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
    for val in field_value:
      message_str += "{}: {}\n".format(field_name, val)

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
  # Read from passed stream until apt sends us a SIGINT or EOF (see below)
  while not INTERRUPTED:
    # Only read if there is data on the stream (non-blocking)
    if not select.select([stream], [], [], 0)[0]:
      continue

    # Read one byte from the stream
    one = os.read(stream.fileno(), 1)

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
  stream.write(message_str)
  stream.flush()


def read_to_queue(stream, queue):
  """Loop to read messages one at a time from the passed stream until EOF, i.e.
  the returned message is None, and write to the passed queue.

  """
  while True:
    msg = read_one(stream)
    if not msg:
      return None

    queue.put(msg)


# Dict to keep some global state, i.e. we need information from earlier
# messages (e.g. CONFIGURATION) when doing in-toto verification upon URI_DONE.
global_info = {
  "config": {},
}

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
  Return a boolean value that can be used to decide, whether the message should
  be relayed or not.

  """
  # Parse out configuration data
  if message_data["code"] == CONFIGURATION:
    # TODO: Call function to parse in-toto related config items
    # (reproducer URL, layout path, gpg keyid(s) or pem file path(s)), and
    # add them to our `global_info` dict, the function could look something
    # like:
    # for name, value in message_data["fields"].iteritems():
    #   if name == "Config-Item" and value.startswith("APT::intoto::"):
    #     global_info["config"][value_parts[0]] = value_parts[1]
    pass

  elif message_data["code"] == URI_ACQUIRE:
    # TODO: Should cache URIs that apt wants us to download? We could take
    # a look at the `Index-File` header field to later decide if we try
    # to fetch link metadata for this file.
    pass

  elif message_data["code"] == URI_DONE:
    # The http transport has downloaded the package requested by apt and
    # sends an URI_DONE to signal that the package can be installed. Here's
    # an example deserialized URI_DONE message:

    # {
    #   'code': 201,
    #   'info': 'URI Done'
    #   'fields': [
    #     ('URI', 'intoto://www.example.com/~foo/debian/pool/main/cowsay_3.03+dfsg1-10_all.deb'),
    #     ('Filename', '/var/cache/apt/archives/partial/cowsay_3.03+dfsg1-10_all.deb'),
    #     ('Size', '20020'),
    #     ('Last-Modified', 'Mon, 26 Nov 2018 14:39:07 GMT'),
    #     ('MD5-Hash', '071b...'),
    #     ('MD5Sum-Hash', '071b...'),
    #     ('SHA1-Hash', '3794...'),
    #     ('SHA256-Hash', 'fd04...'),
    #     ('SHA512-Hash','95bc...')
    #   ],
    # }

    # TODO:
    # Optionally check global_info if this the corresponding URI_ACQUIRE told
    # us that this is an Index-File and skip in-toto verification if yes
    # 1. Create temp dir
    # 2. download link metadata from reproducer (see config in global_info)
    # 3. move final product, i.e. debian package to temp dir
    # 4. run in-toto verification using the specified layout and keys (see
    # config in global_info)
    # 5.a. Return True on successful verification, i.e. URI_DONE is relayed
    # to apt, which will install the package
    # 5.b. Send URI_FAILURE or GENERAL_FAILURE to apt if verification
    # fails and return False, i.e. URI_DONE is not relayed.
    #
    # Optionally send STATUS or LOG messages to apt, while doing all of above
    # To send these messages to apt use
    # `write_one(serialize_message(<msg dict in above format>), sys.stdout)`
    pass

  # All good, we can relay the message
  return True


def loop():
  """Main in-toto http transport method loop to relay messages between apt and
  the apt http transport method and inject in-toto verification upon reception
  of a particular message.

  """
  # Start http transport in a subprocess
  # Messages from the parent process received on sys.stdin are relayed to the
  # subprocesses stdin and vice versa, messages written to the subprocess's
  # stdout are relayed to the parent via sys.stdout.
  http_proc = subprocess.Popen([APT_METHOD_HTTP], stdin=subprocess.PIPE,
      stdout=subprocess.PIPE)

  # HTTP transport message reader thread to add messages from the http
  # transport (subprocess) to a corresponding queue.
  http_queue = Queue.Queue()
  http_thread = threading.Thread(target=read_to_queue, args=(http_proc.stdout,
      http_queue))

  # APT message reader thread to add messages from apt (parent process)
  # to a corresponding queue.
  apt_queue = Queue.Queue()
  apt_thread = threading.Thread(target=read_to_queue, args=(sys.stdin,
      apt_queue))

  # Start reader threads. They will run until they see an EOF on their stream
  # or the global INTERRUPTED flag is set to true (on SIGINT from apt).
  http_thread.start()
  apt_thread.start()

  # Main loop to get messages from queues, i.e. apt queue and http transport
  # queue, and relay them to the corresponding streams, injecting in-toto
  # verification upon reception of a particular message.
  while True:
    for queue, out in [
        (apt_queue, http_proc.stdin),
        (http_queue, sys.stdout)]:

      try:
        message = queue.get_nowait()
        message_data = deserialize_one(message)

      except Queue.Empty:
        continue

      # De-serialization error: Skip message handling, but do relay.
      except Exception as e:
        logger.warning(e)

      else:
        # Read config, perform in-toto verification in there we also
        # decide whether we should relay the message or not.
        should_relay = handle(message_data)

      if should_relay:
        write_one(message, out)

    # Exit when both threads have terminated (on EOF or INTERRUPTED)
    # NOTE: We do not check if there are still messages on the streams or
    # in the queue, assuming that there aren't or we can ignore them if both
    # threads have terminated.
    if (not apt_thread.is_alive() and not http_thread.is_alive()):
      # If apt has sent us a SIGINT we relay it to the subprocess
      if INTERRUPTED:
        http_proc.send_signal(signal.SIGINT)
      return


if __name__ == "__main__":
  signal.signal(signal.SIGINT, signal_handler)
  loop()
