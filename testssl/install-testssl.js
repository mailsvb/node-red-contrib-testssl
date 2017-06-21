const https = require('https');
const fs = require('fs');

let testsslOPTIONS = {
    hostname: 'raw.githubusercontent.com',
    port: 443,
    path: '/drwetter/testssl.sh/2.9dev/testssl.sh',
    method: 'GET',
    rejectUnauthorized: false
};

let testsslREQ = https.request(testsslOPTIONS, (res) => {
    if (res.statusCode != 200)
    {
        console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname);
    }
    
    let data = "";
    
    res.on('data', (d) => data += d.toString());
    
    res.on('end', () => {
        fs.writeFileSync(__dirname + '/testssl.sh', data, {flag: 'w+'});
        fs.chmodSync(__dirname + '/testssl.sh', '755');
        console.log('A copy of testssl.sh has been placed here: ' + __dirname);
    });
});

testsslREQ.on('error', (e) => console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname));
testsslREQ.end();

let testsslLicOPTIONS = {
    hostname: 'raw.githubusercontent.com',
    port: 443,
    path: '/drwetter/testssl.sh/2.9dev/LICENSE',
    method: 'GET',
    rejectUnauthorized: false
};

let testsslLicREQ = https.request(testsslLicOPTIONS, (res) => {
    if (res.statusCode != 200)
    {
        console.error('unable to download testssl.sh License. Please copy it manually to here: ' + __dirname);
    }
    
    let data = "";
    
    res.on('data', (d) => data += d.toString());
    
    res.on('end', () => {
        fs.writeFileSync(__dirname + '/LICENSE-testssl', data, {flag: 'w+'});
        fs.chmodSync(__dirname + '/LICENSE-testssl', '644');
        console.log('By using this node-red node, you agree to the license of testssl.sh. A copy of the license is available here: ' + __dirname);
    });
});


testsslLicREQ.on('error', (e) => console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname));
testsslLicREQ.end();
