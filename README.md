# node-red-contrib-testssl
This is a node-red node for running testssl.sh script within node-red

## Installation
run `npm -g install node-red-contrib-testssl`
it will download the latest version of the testssl.sh script from github for you

## Features
- scan a host and get the report as text and HTML output
- use your own OpenSSL version for the scan by providing the path to it
- multiple IPs for single FQDN will result in seperate reports