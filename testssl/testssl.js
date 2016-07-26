/**
 **
 **/

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
            var path    = opensslpath || msg.opensslpath;
            var scanID  = msg._msgid;
            
            // setting path
            if (path != undefined && path != "") {
                console.log("[testssl][" + scanID + "] - using openssl executable: " + path);
                path = '--openssl=' + path;
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
            
            GetMyTarget(tmpHost, tmpPort, function(hostToScan){
                if (typeof hostToScan === "string") {
                    node.status({fill:"red",shape:"dot",text:hostToScan});
                    msg.payload = hostToScan;
                    node.send(msg);
                    return;
                }
                
                node.status({fill:"green",shape:"dot",text:"scanning " + host});
                msg.payload = "scanning... " + hostToScan.join();
                node.send(msg);
                console.log("[testssl][" + scanID + "] - scanning " + host + ": " + hostToScan.join());
                
                var timeBefore = moment();
                
                hostToScan.forEach(function(curVal, index, arr){
                
                    var output = "";
                    var HTML = "";
                    var error = "";
                    var timeout = false;
                    
                    var run = spawn('./testssl.sh',
                      [
                        path,
                        '-f',
                        '-p',
                        '-S',
                        '-P',
                        '-U',
                        '-E',
                        '-s',
                        curVal
                      ],
                      {
                          cwd: __dirname
                      }
                    );
                    
                    // timeout for scan of 20 minutes
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
                            msg.payload = "scan is still running (" + moment().diff(timeBefore, 'seconds') + " seconds) for " + curVal;
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
                        console.log("[testssl][" + scanID + "][" + index + "] - scan finished for " + curVal);
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
                                host: curVal,
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
        var hostToScan = [];
        if (validator.isIP(tmpHost, '4') === true)
        {
            hostToScan.push(tmpHost + ':' + tmpPort);
            cb(hostToScan);
        }
        else if (validator.isFQDN(tmpHost) === true)
        {
            dns.resolve(tmpHost, function(err, addresses){
                if (err) {
                    cb("Error resolving host: " + err.message);
                    return;
                }
                for (var i=0; i < addresses.length; i++) {
                    hostToScan.push(addresses[i] + ':' + tmpPort);
                }
                cb(hostToScan);
            });
        }
        else
        {
            cb("this is not a valid host");
        }
    }
}
