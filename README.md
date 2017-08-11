# node-red-contrib-testssl
This is a node-red node for running the testssl.sh script within node-red

## Installation
```
npm install node-red-contrib-testssl
```
it will download the latest version of the testssl.sh script from github automatically (https://github.com/drwetter/testssl.sh)

## Features
- scan a host and get the report as text and HTML output.
- if an FQDN is provided as host, every IP gets scanned from the DNS result separately. Every IP will get a single report.
- use your own OpenSSL version for the scan (simply provide the path to the executable).
- provide a path to your CA certificates file(s) to allow the verification of the chain of trust with the remote host.

## Build OpenSSL for testing purposes
```
git clone https://github.com/PeterMosmans/openssl.git
./config --prefix=/OPENSSLTEST
make depend && make && make install
```

## Thanks to
* [Dirk Wetter](https://github.com/drwetter)
* [Peter Mosman](https://github.com/PeterMosmans)
