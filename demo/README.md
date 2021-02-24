# in-toto apt transport demo

The commands in this document may be used to demonstrate two scenarios of
installing a Debian package with the in-toto apt transport, using a generic
[*rebuild layout*](root.layout), which requires a treshold of two trusted
rebuilders to agree on the package to be installed.

In the first scenario the rebuilder results and the served package align and
the installation succeeds. In the second scenario, the mirror servers a package
with a hash that does not correspond to the rebuild results and thus in-toto
aborts installation.

All components used for this demo are defined as docker compose services in
[`docker-compose.yml`](docker-compose.yml):

- *mirror.ok* and *mirror.bad* each set up a basic Debian archive that serves
  a single `demo-package`. *mirror.ok* serves a package, whose hash
  corresponds to the rebuilder results. *mirror.bad* does not.
- *rebuilder.a* and *rebuilder.b* each statically serve in-toto link metadata,
  to provide the signed rebuild evidence for `demo-package`.
- *client* is a pre-configured Debian host, which is set up to demonstrate the
  installation.


## Create and run services
Use the following command to start all services in the same virtual network

```bash
# In project root
docker-compose -f demo/docker-compose.yml up

```

## Attach to client
Use the following command to connect to client service started above
```bash
# In a new terminal
docker exec -it $(docker ps -qf "name=client") bash
```

## Scenario 1: Successfully install verified package
```bash
# In client bash

# Optional: Browse config file, root layout and root key
vi /etc/apt/apt.conf.d/intoto
vi /etc/intoto/root.layout
gpg --list-keys

# Enable in-toto transport in sources.list
vi -c :s/http/intoto/g /etc/apt/sources.list

# Update apt and install demo package
apt-get update && apt-get install demo-package

# Check apt output...

# Optional: Take a look at the used rebuilder link metadata
wget -q -O - rebuilder.a/sources/demo-package/1.0.0/metadata | vi -
wget -q -O - rebuilder.b/sources/demo-package/1.0.0/metadata | vi -

```

## Scenario 2: Abort installation of package served from malicious mirror

```bash
# In client bash

# Remove demo package if installed above
apt-get remove demo-package

# Change mirror in sources.list
vi -c :s/ok/bad/g /etc/apt/sources.list

# Update apt and install demo package (will fail)
apt-get update && apt-get install demo-package

# Check apt output...

```