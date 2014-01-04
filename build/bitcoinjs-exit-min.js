/**
 * BitcoinJS-lib v0.1.3-default
 * Copyright (c) 2011 BitcoinJS Project
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license.
 */

!function(exports,Bitcoin,io,$){function ExitNode(host,port,secure){this.setUri(host,port,secure),this.unique=1,this.connected=!1,this.callbacks=[]}exports.ExitNode=ExitNode,Bitcoin.EventEmitter.augment(ExitNode),ExitNode.prototype.setUri=function(host,port,secure){this.uri=(secure?"https://":"http://")+host+":"+port},ExitNode.prototype.connect=function(wallet){this.wallet=wallet,delete io.sockets[this.uri],io.j=[],this.socket=io.connect(this.uri),this.socket.on("connect",$.proxy(this.handleConnect,this)),this.socket.on("error",function(){console.log("error, test")}),this.socket.on("message",$.proxy(this.handleMessage,this)),this.socket.on("disconnect",$.proxy(this.handleDisconnect,this))},ExitNode.prototype.disconnect=function(){this.socket&&(this.socket.disconnect(),this.socket=null,this.connected=!1),this.trigger("connectStatus",{status:"unknown"})},ExitNode.prototype.call=function(method,argObj,callback){this.socket.send($.toJSON({method:method,params:[argObj],id:this.unique})),callback&&(this.callbacks[this.unique]=callback),this.unique++},ExitNode.prototype.handleConnect=function(){this.connected=!0},ExitNode.prototype.listen=function(addrs){self.call("pubkeysRegister",{keys:addrs.join(",")},function(err,result){return err?(console.error("Could not register public keys"),void 0):(self.call("pubkeysListen",{handle:result.handle},function(err,result){self.trigger("blockInit",{height:result.height}),self.trigger("txData",{confirmed:!0,txs:result.txs}),self.trigger("connectStatus",{status:"ok"})}),self.call("pubkeysUnconfirmed",{handle:result.handle},function(err,result){self.trigger("txData",{confirmed:!1,txs:result.txs})}),void 0)})},ExitNode.prototype.handleMessage=function(data){"undefined"!=typeof data.result&&"function"==typeof this.callbacks[data.id]?this.callbacks[data.id](data.error,data.result):"undefined"!=typeof data.method&&this.trigger(data.method,data.params[0])},ExitNode.prototype.handleDisconnect=function(){},ExitNode.prototype.query=function(api,params,jsonp,callback){"function"==typeof jsonp&&(callback=jsonp,jsonp=!1),params=params||{},callback="function"==typeof callback?callback:function(){};var url=this.uri+"/"+api;jsonp&&(url+="?callback=?"),$.getJSON(url,params,callback)}}("undefined"!=typeof Bitcoin?Bitcoin:module.exports,"undefined"!=typeof Bitcoin?Bitcoin:require("bitcoinjs-lib"),"undefined"!=typeof io?io:require("io"),jQuery,this);