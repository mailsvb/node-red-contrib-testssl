var https = require('https');
var fs = require('fs');

var testsslOPTIONS = {
    hostname: 'raw.githubusercontent.com',
    port: 443,
    path: '/mailsvb/testssl.sh/CA_BUNDLES_PATH/testssl.sh',
    method: 'GET',
    rejectUnauthorized: false
};

var testsslREQ = https.request(testsslOPTIONS, function(res) {
    if (res.statusCode != 200)
    {
        console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname);
    }
    
    var data = ""
    
    res.on('data', function(d){
        data += d.toString();
    });
    
    res.on('end', function(){
        fs.writeFileSync(__dirname + '/testssl.sh', data);
        fs.chmodSync(__dirname + '/testssl.sh', '755');
        console.log('A copy of testssl.sh has been placed here: ' + __dirname);
    });
});


testsslREQ.on('error', function(e) {
    console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname);
});

testsslREQ.end();

var testsslLicOPTIONS = {
    hostname: 'raw.githubusercontent.com',
    port: 443,
    path: '/drwetter/testssl.sh/master/LICENSE',
    method: 'GET',
    rejectUnauthorized: false
};

var testsslLicREQ = https.request(testsslLicOPTIONS, function(res) {
    if (res.statusCode != 200)
    {
        console.error('unable to download testssl.sh License. Please copy it manually to here: ' + __dirname);
    }
    
    var data = ""
    
    res.on('data', function(d){
        data += d.toString();
    });
    
    res.on('end', function(){
        fs.writeFileSync(__dirname + '/LICENSE-testssl', data);
        fs.chmodSync(__dirname + '/LICENSE-testssl', '644');
        console.log('By using this node-red node, you agree to the license of testssl.sh. A copy of the license is available here: ' + __dirname);
    });
});


testsslLicREQ.on('error', function(e) {
    console.error('unable to download testssl.sh script. Please copy it manually to here: ' + __dirname);
});

testsslLicREQ.end();
