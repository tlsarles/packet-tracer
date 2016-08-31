var objs = require('./readObjGroup.js');
// HOST
function host(ip) {
	re = /host\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
	if(re.test(ip)) {
		ip = ip.split(" ")[1];
	}
	this.ip = ip.trim();
}
host.prototype.toString = function() {
	return "host "+this.ip;
}
host.prototype.length = function() {
	var len = "host "+this.ip;
	return len.length;
}
host.prototype.contains = function(input) {
	if(input instanceof target) {
		//console.log('Host - Self Call - ' + input.tgt);
		return this.contains(input.tgt);
	}
	if(input instanceof host) {
		console.log('Compare Host ' + this.ip + ' to Host ' + input.ip);
		if(this.ip == input.ip) return true;
	}
	return false;
}
// Any
function any() {
}
any.prototype.toString = function() {
	return "any";
}
any.prototype.length = function() {
	return 3;
}
any.prototype.contains = function(input) {
	return true;
}
// Network
function network(nw) {
	nw = nw.split(" ");
	this.network = nw[0];
	this.wildCard = nw[1];
}
network.prototype.toString = function() {
	return this.network+" "+this.wildCard;
}
network.prototype.length = function() {
	var len = this.network+" "+this.wildCard;
	return len.length;
}
network.prototype.bitMask = function(input) {
	var thisSplit = input.split(".");
	var thisMask = null;
	var output = "";
	for(i=0;i<4;i++) {
		thisMask = Number(thisSplit[i]).toString(2);
		output += "00000000".substr(thisMask.length)+thisMask;
	}
	return parseInt(output, 2);
}
network.prototype.contains = function(input) {
	var net = this.bitMask(this.network);
	var mask = this.bitMask(this.wildCard);
	var thisMask = net & mask;
	var inputMask = null;
	if(input instanceof target) {
		input = input.tgt;
	}
	if(input instanceof host) {
		net = this.bitMask(input.ip);
		inputMask = net & mask;
	}
	console.log(input +" in Network "+ this.network);
	if(thisMask == inputMask) return true;
	return false;
}
// Ports
function port(port) {
	this.port = port;
}
port.prototype.toString = function() {
	return "eq "+this.port;
}
port.prototype.length = function() {
	return this.port.toString().length;
}
port.prototype.contains = function(input) {
	if(input instanceof port) {
		if(input.port == this.port) { 
			console.log("Port " + input.port + " Matches " + this.port);
			return true;
		}
	}
	if(input instanceof target) {
		return this.contains(input.port);
	}
	console.log("Port " + input.port + " != " + this.port);
	return false;
}

// Ports for Object Groups
function ogPort(input) {
	var protocol = "";
	var port = "";
	re = /(tcp|udp|icmp)/;
	if(re.test(input)) {
		protocol = re.exec(input)[0];
		input = input.substr(re.exec(input)['index'] + protocol.length);
		port = subTypeReader(input)[0];
		if(port == " FAIL ") port = "";
	}
	this.protocol = protocol;
	this.port = port;
}
ogPort.prototype.toString = function() {
	if(this.protocol == icmp)
		return this.protocol+" "+this.port;
	return this.protocol+" "+this.port;
}
ogPort.prototype.length = function() {
	if(this.protocol != icmp)
		var len = this.protocol+" "+this.port;
	else
		var len = this.protocol+" eq "+this.port;
	return len.trim().length;
}

// Range
function range(input) {
	input = input.split(" ");
	this.start = input[1];
	this.end = input[2];
}
range.prototype.toString = function() {
	return "range "+this.start+" "+this.end;
}
range.prototype.length = function() {
	var len = "range "+this.start+" "+this.end;
	return len.length;
}
// ICMP
function icmp(type) {
	this.type = type
}
icmp.prototype.toString = function() {
	return this.type;
}
icmp.prototype.length = function() {
	return this.type.length;
}
icmp.prototype.contains = function() {
	return false;
}
// A target can be a source or destination
function target(tgt, port) {
	this.tgt = tgt;
	this.port = port;
}
target.prototype.toString = function() {
	if(this.port == "") return this.tgt.toString();
	return this.tgt+" "+this.port;
}
target.prototype.contains = function(input) {
	if(this.tgt.contains(input)) {
		console.log("Target Host/NW Match");
		console.log(this.port);
		if(this.port.contains(input)) {
			console.log("Target Port Match");
			return true;
		}
	}
	return false;
}

// SubType Reader
function subTypeReader(thisRule, OGs) {
	var end = function(re, thisRule, thisObject) {
		thisRule = thisRule.substr(re.exec(thisRule)['index'] + thisObject.length());
		return Array(thisObject, thisRule);
	}
	
	// ARG NEED TO REINSTATE A PRECHECK OF ALL CONDITIONS
	// SO THAT IT ONLY FINDS THE FIRST OCCURANCE OF ONE OF THESE
	re = /(host\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|object-group\s\S+|any\s|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\seq\s\S+|range\s\S+\s\S+|echo-reply|echo|traceroute|unreachable|time-exceeded|established|\stcp\s|\sudp\s|\sicmp\s|\sicmp$)/;
	if(re.test(thisRule))
		retVal = re.exec(thisRule)[0];
	else
		return Array(" FAIL ", thisRule);
	//if(re.test(thisRule) === false) return Array(false,thisRule);
	var re = null;
	// Host
	re = /host\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
	if(re.test(retVal)) {
		return end(re, thisRule, new host(re.exec(thisRule)[0].trim()));
	}
	// Object Group
	re = /object-group\s\S+/;
	if(re.test(retVal)) {
		if(OGs) {
			var grpName = re.exec(thisRule)[0].trim().substring(13);
			return end(re, thisRule, OGs.get(grpName));
		} else {
			return end(re, thisRule, new objs.objGroup(re.exec(thisRule)[0].trim(), "reference"));
		}
	}
	// Any
	re = /any\s/;
	if(re.test(retVal)) {
		return end(re, thisRule, new any());
	}
	// Network
	re = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
	if(re.test(retVal)) {
		return end(re, thisRule, new network(re.exec(thisRule)[0].trim()));
	}
	// EQ
	re = /\seq\s\S+/;
	if(re.test(retVal)) {
		return end(re, thisRule, new port(re.exec(thisRule)[0].substr(4)));
	}
	// Range
	re = /range\s\S+\s\S+/;
	if(re.test(retVal)) {
		return end(re, thisRule, new range(re.exec(thisRule)[0]));
	}
	// ICMP
	re = /(echo-reply|echo|traceroute|unreachable|time-exceeded|established)/;
	if(re.test(retVal)) {
		return end(re, thisRule, new icmp(re.exec(thisRule)[0]));
	}
	// Object Group Protocols
	re = /(\stcp\s|\sudp\s|\sicmp\s|\sicmp$)/;
	if(re.test(retVal)) {
		return end(re, thisRule, new ogPort(thisRule));
	}
	return Array(" FAIL ", thisRule);
}
function subTypeLooper(thisRule) {
	var output = Array();
	var keepGoing = true;
	while(keepGoing == true) {
		var temp = subs.subTypeReader(thisRule);
		thisRule = temp[1];
		temp = temp[0];
		if(temp == " FAIL ") {
			keepGoing = false;
		} else {
			output.push(temp);
		}
	}
	return output;
}


module.exports.host = host;
module.exports.any = any;
module.exports.network = network;
module.exports.port = port;
module.exports.range = range;
module.exports.icmp = icmp;
module.exports.target = target;
module.exports.subTypeReader = subTypeReader;
module.exports.subTypeLooper = subTypeLooper;