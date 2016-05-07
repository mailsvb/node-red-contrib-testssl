/**
 **
 **/

module.exports = function(RED) {
    "use strict";
    var util = require('util');
    var fs = require('fs');
    var aha = require('aha');
    var moment = require('moment');
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
            
            var timeout = setTimeout(function(){
                if (run != null) {
                    console.log("[testssl][" + scanID + "] - timeout of scan");
                    node.status({fill:"red",shape:"dot",text:"timeout during scan"});
                    timeout = true;
                    run.kill();
                    return;
                }
            }, 1200000);
            
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
                if (error != "") {
                    node.status({fill:"red",shape:"dot",text:'error during scan'});
                    var msg = {
                        payload: error
                    }
                    console.error(error);
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
                    var msg = {
                        payload: payload
                    }
                    node.status({});
                    node.send(msg);
                }
            });
        });
    }

    RED.nodes.registerType("testssl-node",TestSSLScan);
}
