# Get slim debian base image
FROM debian:sid-slim

# Install required packages using apt (w/o in-toto) python, pip and gpg
RUN apt-get update && apt-get install -y python-pip gpg

# Install intoto and intoto apt transport (and requirements)
# TODO: These should be available as apt packages
RUN pip install in-toto requests subprocess32
COPY intoto.py /usr/lib/apt/methods/intoto
RUN chmod +x /usr/lib/apt/methods/intoto

# Copy apt configuration file, root layout and root layout key
# FIXME: These should be added when installing the intoto transport
COPY tests/data/intoto.conf.docker /etc/apt/apt.conf.d/intoto
COPY tests/data/root.layout.docker /etc/intoto/root.layout
COPY tests/data/alice.asc /etc/intoto/alice.asc
RUN gpg --import /etc/intoto/alice.asc

# Enable intoto apt transport
# FIXME: This will be done by the user eventually (according to documentation)
RUN sed -i 's/http:\/\//intoto:\/\//g' /etc/apt/sources.list

# Example: apt-get install with intoto (check output!!)
# NOTE: Although in-toto verification for canlock will pass, the overall
# installation will fail because of the dependency libcanlock for which
# we don't have rebuilder metadata
ENTRYPOINT apt-get update && apt-get install canlock
