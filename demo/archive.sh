#!/bin/sh

# Create a small public archive
# https://www.debian.org/doc/manuals/debian-reference/ch02.en.html#_small_public_package_archive
cd /var/www/html/debian
mkdir -p dists/unstable/main/binary-amd64
mkdir -p dists/unstable/main/source
cat > dists/unstable/main/binary-amd64/Release << EOF
Archive: unstable
Version: 4.0
Component: main
Origin: Foo
Label: Foo
Architecture: amd64
EOF

cat > dists/unstable/main/source/Release << EOF
Archive: unstable
Version: 4.0
Component: main
Origin: Foo
Label: Foo
Architecture: source
EOF

cat >aptftp.conf <<EOF
APT::FTPArchive::Release {
  Origin "Foo";
  Label "Foo";
  Suite "unstable";
  Codename "sid";
  Architectures "amd64";
  Components "main";
  Description "Public archive for Foo";
};
EOF

cat >aptgenerate.conf <<EOF
Dir::ArchiveDir ".";
Dir::CacheDir ".";
TreeDefault::Directory "pool/";
TreeDefault::SrcDirectory "pool/";
Default::Packages::Extensions ".deb";
Default::Packages::Compress ". gzip bzip2";
Default::Sources::Compress "gzip bzip2";
Default::Contents::Compress "gzip bzip2";

BinDirectory "dists/unstable/main/binary-amd64" {
  Packages "dists/unstable/main/binary-amd64/Packages";
  Contents "dists/unstable/Contents-amd64";
  SrcPackages "dists/unstable/main/source/Sources";
};

Tree "dists/unstable" {
  Sections "main";
  Architectures "amd64 source";
};
EOF

apt-ftparchive generate -c=aptftp.conf aptgenerate.conf
apt-ftparchive release -c=aptftp.conf dists/unstable > dists/unstable/Release

gpg --homedir /tmp/keyring -u 88876A89E3D4698F83D3DB0E72E33CA3E0E04E46 \
    -bao dists/unstable/Release.gpg dists/unstable/Release
