# node-red-contrib-testssl
This is a node-red node for running the testssl.sh script within node-red

## Installation
run `npm -g install node-red-contrib-testssl`
it will download the latest version of the testssl.sh script from github automatically (https://github.com/drwetter/testssl.sh)

## Features
- scan a host and get the report as text and HTML output
- if an FQDN is provided as host, every IP gets scanned from the DNS result. Every IP will get a single report
- use your own OpenSSL version for the scan (simply provide the path to the executable)