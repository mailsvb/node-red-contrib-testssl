const https = require('https');
const fs = require('fs');

const downloadFile = (filename, target, permissions) => {
    let OPTIONS = {
        hostname: 'raw.githubusercontent.com',
        port: 443,
        path: '/drwetter/testssl.sh/2.9dev/' + filename,
        method: 'GET',
        rejectUnauthorized: false
    };
    
    let REQ = https.request(OPTIONS, (res) => {
        if (res.statusCode != 200)
        {
            console.error('unable to download ' + filename + '. Please copy it manually to here: ' + __dirname);
        }
        
        let data = "";
        
        res.on('data', (d) => data += d.toString());
        
        res.on('end', () => {
            fs.writeFileSync(__dirname + '/' + target, data, {flag: 'w+'});
            fs.chmodSync(__dirname + '/' + target, permissions);
            console.log('A copy of ' + filename + ' has been downloaded');
        });
    });

    REQ.on('error', (e) => console.error('unable to download ' + filename + ' script. Please copy it manually to here: ' + __dirname));
    REQ.end();
};

if (!fs.existsSync(__dirname + '/etc')){
    fs.mkdirSync(__dirname + '/etc');
}

downloadFile('testssl.sh', 'testssl.sh', '755');
downloadFile('LICENSE', 'LICENSE-testssl', '644');

downloadFile('etc/tls_data.txt', 'etc/tls_data.txt', '644');
downloadFile('etc/cipher-mapping.txt', 'etc/cipher-mapping.txt', '644');
downloadFile('etc/common-primes.txt', 'etc/common-primes.txt', '644');
