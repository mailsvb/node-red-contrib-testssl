const https = require('https')
const fs = require('fs')
const branch = '3.1dev'

const downloadFile = (filename, target, permissions) => {
    let OPTIONS = {
        hostname: 'raw.githubusercontent.com',
        port: 443,
        path: '/drwetter/testssl.sh/' + branch + '/' + filename,
        method: 'GET',
        rejectUnauthorized: false
    }
    let REQ = https.request(OPTIONS, (res) => {
        if (res.statusCode != 200)
        {
            console.error('unable to download ' + filename + '. Please copy it manually to here: ' + __dirname)
        }
        let data = ""
        res.on('data', (d) => data += d.toString())
        res.on('end', () => {
            fs.writeFileSync(__dirname + '/' + target, data, {flag: 'w+'})
            fs.chmodSync(__dirname + '/' + target, permissions)
            console.log('A copy of ' + filename + ' has been downloaded')
        })
    })
    REQ.on('error', (e) => console.error('unable to download ' + filename + ' script. Please copy it manually to here: ' + __dirname))
    REQ.end()
}

if (!fs.existsSync(__dirname + '/etc')){
    fs.mkdirSync(__dirname + '/etc')
}
if (!fs.existsSync(__dirname + '/bin')){
    fs.mkdirSync(__dirname + '/bin')
}

downloadFile('testssl.sh', 'testssl.sh', '755');
downloadFile('LICENSE', 'LICENSE-testssl', '644');

downloadFile('etc/Apple.pem', 'etc/Apple.pem', '644');
downloadFile('etc/Java.pem', 'etc/Java.pem', '644');
downloadFile('etc/Linux.pem', 'etc/Linux.pem', '644');
downloadFile('etc/Microsoft.pem', 'etc/Microsoft.pem', '644');
downloadFile('etc/Mozilla.pem', 'etc/Mozilla.pem', '644');
downloadFile('etc/ca_hashes.txt', 'etc/ca_hashes.txt', '644');
downloadFile('etc/cipher-mapping.txt', 'etc/cipher-mapping.txt', '644');
downloadFile('etc/client-simulation.txt', 'etc/client-simulation.txt', '644');
downloadFile('etc/client-simulation.wiresharked.md', 'etc/client-simulation.wiresharked.md', '644');
downloadFile('etc/client-simulation.wiresharked.txt', 'etc/client-simulation.wiresharked.txt', '644');
downloadFile('etc/common-primes.txt', 'etc/common-primes.txt', '644');
downloadFile('etc/curves.txt', 'etc/curves.txt', '644');
downloadFile('etc/tls_data.txt', 'etc/tls_data.txt', '644');

downloadFile('bin/krb5-ciphers.txt', 'bin/krb5-ciphers.txt', '644');
downloadFile('bin/new-ciphers.diffed2vanilla.txt', 'bin/new-ciphers.diffed2vanilla.txt', '644');
downloadFile('bin/new-ciphers.std_distro.txt', 'bin/new-ciphers.std_distro.txt', '644');
downloadFile('bin/openssl-Vall.krb.txt', 'bin/openssl-Vall.krb.txt', '644');
downloadFile('bin/openssl-Vall.txt', 'bin/openssl-Vall.txt', '644');
downloadFile('bin/openssl.Darwin.x86_64', 'bin/openssl.Darwin.x86_64', '644');
downloadFile('bin/openssl.FreeBSD.amd64', 'bin/openssl.FreeBSD.amd64', '644');
downloadFile('bin/openssl.Linux.i686', 'bin/openssl.Linux.i686', '644');
downloadFile('bin/openssl.Linux.x86_64', 'bin/openssl.Linux.x86_64', '644');
downloadFile('bin/openssl.Linux.x86_64.krb', 'bin/openssl.Linux.x86_64.krb', '644');
