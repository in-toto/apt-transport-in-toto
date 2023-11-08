# Build apt-transport-in-toto for Debian on any host
#
# Release workflow (with example commands)
# ----------------
#
#
# 1. Update debian/* files, most notably add new entry to debian/changelog
#
# 2. Build (requires upstream VERSION and path to *.deb dependencies as args)
#
#    - Installs dev tools and build dependencies
#      NOTE: Extra in-toto and securesystemslib *.deb files expected to be
#      passed via `--build-context extras=/path/to/extra/depebndences/`
#    - Configures gpg + dput to upload to mentors
#    - Fetches source dist from GitHub
#    - Builds Debian package
#
#        docker build --build-context extras=/path/to/dependency/*.deb \
#             --build-arg VERSION=0.1.1 \
#             -t deb-build .
#
#    HINT: If the build fails, update debian/* files on host and rebuild.
#    This might include downstream patching with `quilt`, which is also
#    available outside of Debian (e.g. via brew on macOS).
#
# 3. Run to sign and upload (requires signing key as argument)
#
#        docker run --rm -it --name deb-build --entrypoint bash \
#             --env GPG_KEY="$(gpg --armor --export-secret-key lukas.puehringer@nyu.edu)" \
#             deb-build
#
# 4. (on container) Import signing key, sign and upload to mentors
#
#        echo "$GPG_KEY" | gpg --import
#        (cd apt-transport-in-toto-0.1.1 && debsign -k lukas.puehringer@nyu.edu)
#        dput mentors apt-transport-in-toto_0.1.1-4_arm64.changes
#
FROM debian:sid

# Install developer tools and build dependencies
RUN apt-get update \
  && apt-get install --no-install-recommends -yV \
    build-essential \
    devscripts \
    debhelper \
    equivs \
    wget \
    lintian \
    dput

# Copy and install extra dependencies (see --build-context arg)
# HACK: Comment out if not needed
COPY --from=extras . /tmp/extras
RUN apt-get install /tmp/extras/*.deb -yV

# Copy debian files
COPY . /tmp/debian

RUN mk-build-deps \
    --install \
    --remove \
    --tool 'apt-get --no-install-recommends -yV' /tmp/debian/control

# Create user (some build tests related to permission fail as root)
RUN useradd build --create-home
USER build
WORKDIR /home/build

# Configure GPG
COPY --chown=build:build <<-"EOT" .gnupg/gpg.conf
use-agent
pinentry-mode loopback
EOT

COPY --chown=build:build <<-"EOT" .gnupg/gpg-agent.conf
allow-loopback-pinentry
EOT

# Configure DPUT
COPY --chown=build:build <<-"EOT" .dput.cf
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
# Allow uploads for UNRELEASED packages
allowed_distributions = .*
EOT

# Grab source dist and sig for VERSION from GitHub and prepare for building
ARG VERSION
RUN wget https://github.com/in-toto/apt-transport-in-toto/archive/refs/tags/v${VERSION}.tar.gz \
    -O apt-transport-in-toto_${VERSION}.orig.tar.gz
RUN wget https://github.com/in-toto/apt-transport-in-toto/releases/download/v${VERSION}/v${VERSION}.tar.gz.asc\
    -O apt-transport-in-toto_${VERSION}.orig.tar.gz.asc
RUN tar xf apt-transport-in-toto_${VERSION}.orig.tar.gz
RUN cp -r /tmp/debian apt-transport-in-toto-${VERSION}

# Build
RUN cd apt-transport-in-toto-${VERSION} && debuild \
  --unsigned-source \
  --unsigned-changes \
  --lintian-opts --display-level ">=pedantic" --display-experimental --tag-display-limit 0
