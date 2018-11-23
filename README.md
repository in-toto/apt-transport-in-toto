# apt-transport-in-toto

Provide an in-toto transport method for APT to perform in-toto verification
using in-toto link metadata fetched from a rebuilder. Take a look at
[`intoto.py`](intoto.py) document header, docstrings and comments for details.

## Installation (quick and dirty)
```bash
cd /usr/lib/apt/methods
curl https://raw.githubusercontent.com/lukpueh/apt-transport-in-toto/basic-transport-wip/intoto.py\
    -o intoto
chmod 755 intoto
```

## Usage
Use the `intoto` protocol prefix in URIs in `/etc/apt/sources.list` or
`/etc/apt/sources.list.d/*`, e.g.:
`deb intoto://ftp.us.debian.org/debian/ stretch main contrib`


## Troubleshooting
APT and APT transports exchange messages over `stdin` and `stdout`. You can use
the following snippet to proxy and log the message flow.
```bash
cd /usr/lib/apt/methods
cp intoto intoto-real
cat > intoto <<EOL
#!/bin/sh
tee -a /tmp/intoto.std.log | /usr/lib/apt/methods/intoto-real "$@" | tee -a /tmp/intoto.std.log
EOL

# Use `tail -f /tmp/intoto.std.log` while e.g. `apt-get install <package>`
```


## Todo
- Currently this program just relays messages between APT and and the builtin
  APT HTTP transport. It provides a stub to easily intercept and deserialize
  messages and perform in-toto verification. See the
  [`handle(message_data)`](intoto.py#L388-459) function for more details.
- Add Debian metadata for proper installation.
