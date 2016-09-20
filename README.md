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

## Build OpenSSL for testing with testssl.sh (working for OpenSSL 1.0.1)
```
sed -i.bak -r 's/"(ssl2|rc5|md2|zlib|weak-ssl-ciphers)"[[:space:]]+=>/#&/g' Configure
sed -i.bak -r 's/^(#[[:space:]]define[[:space:]]TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES[[:space:]]+)0/\11/' ssl/tls1.h
```
