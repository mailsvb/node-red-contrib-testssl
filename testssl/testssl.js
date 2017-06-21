module.exports = function(RED) {
    "use strict";
    const util = require('util');
    const fs = require('fs');
    const aha = require('aha');
    const crypto = require('crypto');
    const moment = require('moment');
    const validator = require("validator");
    const dns = require('dns');
    const spawn = require('child_process').spawn;

    function TestSSLScan(n) {
        RED.nodes.createNode(this,n);
        let scantarget      = n.host;
        let opensslpath     = n.opensslpath || '/usr/bin/openssl';
        let cabundlespath   = n.cabundlespath || '/etc/ssl';

        let node = this;

        this.on("input",function(msg) {
            let host            = scantarget || msg.host;
            let openssl         = opensslpath || msg.opensslpath;
            let capath          = cabundlespath || msg.cabundlespath;
            let scanID          = msg._msgid;
            let env             = Object.create( process.env );
            
            // setting openssl path
            if (openssl != undefined && openssl != "") {
                node.log(`[testssl][${scanID}] - using openssl executable: ${openssl}`);
                openssl = '--openssl=' + openssl;
            }
            
            // setting ca-bundles path
            if (capath != undefined && capath != "") {
                node.log(`[testssl][${scanID}] - using ca bundles path: ${capath}`);
                env.CA_BUNDLES_PATH = capath;
            }
            
            // checking host and port data provided
            if (host === undefined || host === "") {
                node.status({fill:"red",shape:"dot",text:'address missing'});
                return;
            }
            let tmpHost = '';
            let tmpPort = 443;
            let tmp1 = host.match(/^[A-Za-z0-9\x2E\x2D]*$/);        // check for host only
            let tmp2 = host.match(/^([^\x3A]*)\x3A([0-9]{1,5})$/);  // check for host + port
            if (tmp1 instanceof Array && tmp1.length === 1)
            {
                tmpHost = tmp1[0];
            }
            else if (tmp2 instanceof Array && tmp2.length === 3)
            {
                tmpHost = tmp2[1];
                tmpPort = parseInt(tmp2[2]);
            }
            else
            {
                node.status({fill:"red",shape:"dot",text:"invalid data given"});
                msg.payload = "you provided invalid data";
                node.send(msg);
                return;
            }
            
            // checking port
            if (tmpPort < 1 || tmpPort > 65535)
            {
                node.status({fill:"red",shape:"dot",text:"not a valid port"});
                msg.payload = "this is not a valid port";
                node.send(msg);
                return;
            }
            
            GetMyTarget(tmpHost, function(IPsToScan){
                if (typeof IPsToScan === "string") {
                    node.status({fill:"red",shape:"dot",text:IPsToScan});
                    msg.payload = IPsToScan;
                    node.send(msg);
                    return;
                }
                
                node.status({fill:"green",shape:"dot",text:"scanning " + tmpHost + " on port " + tmpPort});
                msg.payload = "scanning... " + IPsToScan.join() + ' on port ' + tmpPort;
                node.send(msg);
                node.log(`[testssl][${scanID}] - scanning ${tmpHost} via ${IPsToScan.join()} on port ${tmpPort}`);
                
                let timeBefore = moment();
                
                IPsToScan.forEach((singleAddrToScan, index, arr) => {
                
                    let output = "";
                    let HTML = "";
                    let error = "";
                    let timeout = false;
                    let hash = crypto.createHash('sha256').update(`${scanID}${tmpHost}${tmpPort}`);
                    let jsonfile = '/tmp/' + hash.digest('hex');
                    
                    let run = spawn('./testssl.sh',
                      [
                        openssl,
                        '--protocols',
                        '--server-defaults',
                        '--server-preference',
                        '--headers',
                        '--vulnerable',
                        '--cipher-per-proto',
                        '--pfs',
                        '--rc4',
                        '--ip',
                        '--nodns',
                        '--jsonfile',
                        jsonfile,
                        singleAddrToScan,
                        tmpHost + ':' + tmpPort
                      ],
                      {
                          cwd: __dirname,
                          env: env
                      }
                    );
                    
                    // timeout for scan of 10 minutes
                    let timeout = setTimeout(function(){
                        if (run != null) {
                            node.log(`[testssl][${scanID}][${index}] - timeout of scan`);
                            node.status({fill:"red",shape:"dot",text:"timeout during scan"});
                            timeout = true;
                            run.kill();
                            return;
                        }
                    }, 600000);
                    
                    // interval to inform user of ongoing activity
                    let interval = setInterval(() => {
                        if (run != null) {
                            msg.payload = "scan is still running (" + moment().diff(timeBefore, 'seconds') + " seconds) for " + singleAddrToScan + ":" + tmpPort;
                            node.send(msg);
                        }
                    }, 60000);
                    
                    run.stdout.on('data', (data) => {
                        HTML+=data.toString('hex');
                        output+=data.toString();
                    });

                    run.stderr.on('data', (data) => {
                        error+=data.toString();
                    });

                    run.on('close', () => {
                        node.log(`[testssl][${scanID}][${index}] - scan finished for ${singleAddrToScan}:${tmpPort}`);
                        run = null;
                        clearTimeout(timeout);
                        clearInterval(interval);
                        if (error != "") {
                            node.status({fill:"red",shape:"dot",text:"error during scan"});
                            msg.payload = error.toString().trim().replace(/\[[^m]*m/g,'');
                            node.send(msg);
                        }
                        else {
                            let timeAfter = moment();
                            let outputHTML = aha(new Buffer(HTML, 'hex'));
                            try {
                                jsonfile = fs.readFileSync(jsonfile).toString();
                            }
                            catch (e) {
                                node.error(`[testssl][${scanID}][${index}] - ${e}`);
                            }
                            let payload = {
                                text: output,
                                html: outputHTML,
                                json: jsonfile,
                                timeout: timeout,
                                host: singleAddrToScan,
                                duration: timeAfter.diff(timeBefore, 'seconds'),
                                start: timeBefore.utc().format(),
                                end: timeAfter.utc().format()
                            }
                            msg.payload = payload;
                            node.status({});
                            node.send(msg);
                        }
                    });
                });
            });
        });
    }

    RED.nodes.registerType("testssl-node",TestSSLScan);
    
    const GetMyTarget = (tmpHost, cb) => {
        let IPsToScan    = [];
        if (validator.isIP(tmpHost, '4') === true)
        {
            IPsToScan.push(tmpHost);
            cb(IPsToScan);
        }
        else if (validator.isFQDN(tmpHost) === true)
        {
            dns.resolve(tmpHost, (err, addresses) => {
                if (err) {
                    cb("Error resolving host: " + err.message);
                    return;
                }
                for (var i=0; i < addresses.length; i++) {
                    IPsToScan.push(addresses[i]);
                }
                cb(IPsToScan);
            });
        }
        else
        {
            cb("this is not a valid host");
        }
    }
}
