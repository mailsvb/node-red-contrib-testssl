/**
 **
 **/

module.exports = function(RED) {
    "use strict";
    var util = require('util');
    var fs = require('fs');
    var aha = require('aha');
    var moment = require('moment');
    var validator = require("validator");
    var spawn = require('child_process').spawn;

    function TestSSLScan(n) {
        RED.nodes.createNode(this,n);
        var scantarget = n.host;
        var opensslpath = n.opensslpath || '/usr/bin/openssl';

        var node = this;

        this.on("input",function(msg) {
            var host    = scantarget || msg.host;
            var path    = opensslpath || msg.opensslpath;
            var scanID  = msg._msgid;
            if (host === undefined || host === "") {
                node.status({fill:"red",shape:"dot",text:'address missing'});
                return;
            }
            
            // checking host and port provided
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
            
            if (validator.isFQDN(tmpHost) === false && validator.isIP(tmpHost, '4') === false)
            {
                node.status({fill:"red",shape:"dot",text:'not a valid host'});
                msg.payload = "this is not a valid host";
                node.send(msg);
                return;
            }
            if (tmpPort < 1 || tmpPort > 65535)
            {
                node.status({fill:"red",shape:"dot",text:'not a valid port'});
                msg.payload = "this is not a valid port";
                node.send(msg);
                return;
            }
            
            msg.payload = "scan has been started...";
            node.send(msg);
            console.log("[testssl][" + scanID + "] - start scan for host: " + host);
            var timeBefore = moment();
            
            if (path != undefined && path != "") {
                console.log("[testssl][" + scanID + "] - using openssl executable: " + path);
                path = '--openssl=' + path;
            }
            
            var output = "";
            var HTML = "";
            var error = "";
            var timeout = false;
            
            node.status({fill:"green",shape:"dot",text:"scanning " + host});
            
            var run = spawn('./testssl.sh',
              [
                path,
                '-f',
                '-p',
                '-S',
                '-P',
                '-U',
                '-E',
                host
              ],
              {
                  cwd: __dirname
              }
            );
            
            // global timeout for scan of 20 minutes
            var timeout = setTimeout(function(){
                if (run != null) {
                    console.log("[testssl][" + scanID + "] - timeout of scan");
                    node.status({fill:"red",shape:"dot",text:"timeout during scan"});
                    timeout = true;
                    run.kill();
                    return;
                }
            }, 1200000);
            
            // interval to inform user of ongoing activity
            var interval = setInterval(function(){
                if (run != null) {
                    msg.payload = "scan is still running (" + moment().diff(timeBefore, 'seconds') + " seconds)";
                    node.send(msg);
                }
            }, 45000);
            
            run.stdout.on('data', function (data) {
                HTML+=data.toString('hex');
                output+=data.toString();
            });

            run.stderr.on('data', function (data) {
                error+=data.toString();
            });

            run.on('close', function(){
                console.log("[testssl][" + scanID + "] - scan finished of host: " + host);
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
                        host: host,
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
    }

    RED.nodes.registerType("testssl-node",TestSSLScan);
}
