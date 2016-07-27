module.exports = function(RED) {
    "use strict";
    const util = require('util');
    const fs = require('fs');
    const aha = require('aha');
    const moment = require('moment');
    const validator = require("validator");
    const dns = require('dns');
    const spawn = require('child_process').spawn;

    function TestSSLScan(n) {
        RED.nodes.createNode(this,n);
        var scantarget = n.host;
        var opensslpath = n.opensslpath || '/usr/bin/openssl';

        var node = this;

        this.on("input",function(msg) {
            var host    = scantarget || msg.host;
            var openssl = opensslpath || msg.opensslpath;
            var scanID  = msg._msgid;
            
            // setting openssl path
            if (openssl != undefined && openssl != "") {
                console.log("[testssl][" + scanID + "] - using openssl executable: " + openssl);
                openssl = '--openssl=' + openssl;
            }
            
            // checking host and port data provided
            if (host === undefined || host === "") {
                node.status({fill:"red",shape:"dot",text:'address missing'});
                return;
            }
            var tmpHost = '';
            var tmpPort = 443;
            var tmp1 = host.match(/^[A-Za-z0-9\x2E\x2D]*$/);        // check for host only
            var tmp2 = host.match(/^([^\x3A]*)\x3A([0-9]{1,5})$/);  // check for host + port
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
                node.status({fill:"red",shape:"dot",text:'invalid data given'});
                msg.payload = "you provided invalid data";
                node.send(msg);
                return;
            }
            
            // checking port
            if (tmpPort < 1 || tmpPort > 65535)
            {
                node.status({fill:"red",shape:"dot",text:'not a valid port'});
                msg.payload = "this is not a valid port";
                node.send(msg);
                return;
            }
            
            GetMyTarget(tmpHost, tmpPort, function(hostsToScan){
                if (typeof hostsToScan === "string") {
                    node.status({fill:"red",shape:"dot",text:hostsToScan});
                    msg.payload = hostsToScan;
                    node.send(msg);
                    return;
                }
                
                node.status({fill:"green",shape:"dot",text:"scanning " + host});
                msg.payload = "scanning... " + hostsToScan.join();
                node.send(msg);
                console.log("[testssl][" + scanID + "] - scanning " + host + ": " + hostsToScan.join());
                
                var timeBefore = moment();
                
                hostsToScan.forEach(function(singleAddrToScan, index, arr){
                
                    var output = "";
                    var HTML = "";
                    var error = "";
                    var timeout = false;
                    
                    var run = spawn('./testssl.sh',
                      [
                        openssl,
                        '-f',
                        '-p',
                        '-S',
                        '-P',
                        '-U',
                        '-E',
                        '-s',
                        singleAddrToScan
                      ],
                      {
                          cwd: __dirname
                      }
                    );
                    
                    // timeout for scan of 10 minutes
                    var timeout = setTimeout(function(){
                        if (run != null) {
                            console.log("[testssl][" + scanID + "][" + index + "] - timeout of scan");
                            node.status({fill:"red",shape:"dot",text:"timeout during scan"});
                            timeout = true;
                            run.kill();
                            return;
                        }
                    }, 600000);
                    
                    // interval to inform user of ongoing activity
                    var interval = setInterval(function(){
                        if (run != null) {
                            msg.payload = "scan is still running (" + moment().diff(timeBefore, 'seconds') + " seconds) for " + singleAddrToScan;
                            node.send(msg);
                        }
                    }, 60000);
                    
                    run.stdout.on('data', function (data) {
                        HTML+=data.toString('hex');
                        output+=data.toString();
                    });

                    run.stderr.on('data', function (data) {
                        error+=data.toString();
                    });

                    run.on('close', function(){
                        console.log("[testssl][" + scanID + "][" + index + "] - scan finished for " + singleAddrToScan);
                        run = null;
                        clearTimeout(timeout);
                        clearInterval(interval);
                        if (error != "") {
                            node.status({fill:"red",shape:"dot",text:'error during scan'});
                            msg.payload = error.toString().trim().replace(/\[[^m]*m/g,'');
                            node.send(msg);
                        }
                        else {
                            var timeAfter = moment();
                            var outputHTML = aha(new Buffer(HTML, 'hex'));
                            var payload = {
                                text: output,
                                html: outputHTML,
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
    
    const GetMyTarget = function(tmpHost, tmpPort, cb)
    {
        var hostsToScan = [];
        if (validator.isIP(tmpHost, '4') === true)
        {
            hostsToScan.push(tmpHost + ':' + tmpPort);
            cb(hostsToScan);
        }
        else if (validator.isFQDN(tmpHost) === true)
        {
            dns.resolve(tmpHost, function(err, addresses){
                if (err) {
                    cb("Error resolving host: " + err.message);
                    return;
                }
                for (var i=0; i < addresses.length; i++) {
                    hostsToScan.push(addresses[i] + ':' + tmpPort);
                }
                cb(hostsToScan);
            });
        }
        else
        {
            cb("this is not a valid host");
        }
    }
}
