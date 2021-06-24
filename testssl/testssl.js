module.exports = function(RED) {
    "use strict";
    const util = require('util');
    const fs = require('fs');
    const crypto = require('crypto');
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
                
                const timeBefore = new Date();
                
                IPsToScan.forEach((singleAddrToScan, index, arr) => {
                
                    let output = "";
                    let error = "";
                    let timeout = false;
                    const hash = crypto.createHash('sha256').update(`${scanID}${tmpHost}${tmpPort}${index}`).digest('hex');
                    const jsonfile = `/tmp/json${hash}`;
                    const htmlfile = `/tmp/html${hash}`;
                    const csvfile  = `/tmp/csv${hash}`;
                    
                    let run = spawn('./testssl.sh',
                      [
                        openssl,
                        '--protocols',
                        '--grease',
                        '--headers',
                        '--vulnerable',
                        '--cipher-per-proto',
                        '--fs',
                        '--rc4',
                        '--nodns=none',
                        '--phone-out',
                        '--mapping=rfc',
                        '--jsonfile',
                        jsonfile,
                        '--htmlfile',
                        htmlfile,
                        '--csvfile',
                        csvfile,
                        '--warnings=off',
                        '--ip',
                        singleAddrToScan,
                        tmpHost + ':' + tmpPort
                      ],
                      {
                          cwd: __dirname,
                          env: env
                      }
                    );
                    
                    // timeout for scan of 5 minutes
                    timeout = setTimeout(function(){
                        if (run != null) {
                            node.log(`[testssl][${scanID}][${index}] - timeout of scan`);
                            node.status({
                                fill:"red",
                                shape:"dot",
                                text:"timeout during scan"
                            });
                            timeout = true;
                            run.kill();
                            return;
                        }
                    }, 300000);
                    
                    // interval to inform user of ongoing activity
                    let interval = setInterval(() => {
                        if (run != null) {
                            msg.payload = `scan is still running (${getSecondsBetweenDates(timeBefore)} seconds) for ${singleAddrToScan}:${tmpPort}`;
                            node.send(msg);
                        }
                    }, 60000);
                    
                    run.stdout.on('data', (data) => {
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
                            const timeAfter = new Date();
                            const fileContent = {};
                            try {
                                fileContent.jsonfile = fs.readFileSync(jsonfile).toString();
                                fs.unlinkSync(jsonfile);
                                fileContent.htmlfile = fs.readFileSync(htmlfile).toString();
                                fs.unlinkSync(htmlfile);
                                fileContent.csvfile = fs.readFileSync(csvfile).toString();
                                fs.unlinkSync(csvfile);
                            }
                            catch (e) {
                                node.error(`[testssl][${scanID}][${index}] - ${e && e.message}`);
                            }
                            let payload = {
                                text: output,
                                html: fileContent.htmlfile,
                                json: fileContent.jsonfile,
                                csv: fileContent.csvfile,
                                timeout: timeout,
                                host: singleAddrToScan,
                                duration: getSecondsBetweenDates(timeBefore, timeAfter),
                                start: formatDate(timeBefore),
                                end: formatDate(timeAfter)
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

    const getSecondsBetweenDates = (startDate, endDate) => {
        return Math.round( ( (endDate || new Date()) - startDate) / 1000);
    }

    const formatDate = (date) => {
        const now = date || (new Date());
        let MM = (now.getMonth() + 1);
            if (MM < 10) { MM = '0' + MM; }
        let DD = now.getDate();
            if (DD < 10) { DD = '0' + DD; }
        let H = now.getHours();
            if (H < 10) { H = '0' + H; }
        let M = now.getMinutes();
            if (M < 10) { M = '0' + M; }
        let S = now.getSeconds();
            if (S < 10) { S = '0' + S; }
        return `${now.getFullYear()}/${MM}/${DD} - ${H}:${M}:${S}`
    }
}
