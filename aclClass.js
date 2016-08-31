// Import SubClasses
var subs = require('./subClasses.js');
var objs = require('./readObjGroup.js');
// Define aclRule
var aclRule = function(Line, Permit, Protocol, Src, Dst) {
	this.line = Line;
	this.permit = Permit;
	this.protocol = Protocol;
	this.src = Src;
	this.dst = Dst;
}
aclRule.prototype.toString = function() {
	return this.line+" "+this.permit+" "+this.protocol+" "+this.src+" "+this.dst;
}
// Protocol
function protocol(protocol) {
	this.protocol = protocol;
}
protocol.prototype.length = function() {
	return this.protocol.length;
}
protocol.prototype.toString = function() {
	return this.protocol;
}
// ####################### Object Group Reference ###################
// objGroupRef is a reference to a group from within an ACL rule

function objGroupRef(name) {
	name = name.split(" ");
	this.name = name[1];
}
objGroupRef.prototype.toString = function() {
	return "object-group "+this.name;
}
objGroupRef.prototype.length = function() {
	var len = "object-group "+this.name;
	return len.length;
}
// ####################### ACL CLASS #################################
// An ACL is a collection of aclRules. Raw CLI output is fed into the
// add method, which parses each line into an aclRule
function acl() {
	this.size = 0;
	this.rules = Array();
}
acl.prototype.toString = function() {
	var output = "";
	for(i=0;i<this.size;i++) {
		output += this.rules[i].toString()+"\n";
	}
	return output;
}
acl.prototype.add = function(rule) {
	// Parse Line #
	var re = /\d+\s/;
	var line = re.exec(rule)[0].trim();
	// Parse Permit or Deny
	re = /(permit|deny)/;
	var permit = re.exec(rule)[0].trim();
	// Parse Protocol
	re = /(tcp|udp|ip|icmp|object-group)/;
	var Protocol = re.exec(rule)[0].trim();
	re = /object-group\s\S+/;
	if(Protocol == "object-group") {
		if(this.objectGroups) {
			var grpName = re.exec(rule)[0].trim().substring(13);
			Protocol = this.objectGroups.get(grpName);
		} else {
			console.log("Groups MISSING");
			Protocol = new objs.objGroup(re.exec(rule)[0].trim(), "reference");
		}
	} else {
		re = /(tcp|udp|ip|icmp)/;
		Protocol = new protocol(Protocol);
	}
	rule = rule.substr(re.exec(rule)['index'] + Protocol.length());
	var output = Array();
	var keepGoing = true;
	while(keepGoing == true) {
		var temp = subs.subTypeReader(rule, this.objectGroups);
		rule = temp[1];
		temp = temp[0];
		if(temp == " FAIL ") {
			keepGoing = false;
		} else {
			output.push(temp);
		}
	}
	var i = 1;
	var source = output[0];
	if(output[i] instanceof subs.port || output[i] instanceof subs.range || output[i] instanceof subs.icmp) {
		source = new subs.target(source, output[i]);
		i++;
	}
	var dest = output[i];
	i++;
	if(output[i] instanceof subs.port || output[i] instanceof subs.range || output[i] instanceof subs.icmp) {
		dest = new subs.target(dest, output[i]);
	}
	this.rules.push(new aclRule(line, permit, Protocol, source, dest));
	this.size++;
	return line+" "+permit+" "+Protocol+" "+source+""+dest;
}
acl.prototype.sizeFn = function() {
	return this.size;
}
acl.prototype.readFile = function(fileName, callback) {
	// Read File
	var lineReader = require('readline').createInterface({
		input: require('fs').createReadStream(fileName)
	});
	// Line By Line
	lineReader.on('line', (line) => {
		this.add(line);
	}).on('close', () => {
		callback();
		//console.log(this.toString());
		//require('fs').writeFile("output.txt", ACL.toString());
	});
}
acl.prototype.setObjGroups = function(fileName) {
	this.objectGroups = new objs.objGroups();
	this.objectGroups.readFile(fileName);
}
acl.prototype.checkFlow = function(flow) {
	console.log("\x1b[36m### New Flow ###\x1b[37m");
	//console.log(flow);
	//for(flowLoopi=0;flowLoopi<this.rules.length;flowLoopi++) {
	for(flowLoopi=0;flowLoopi<11;flowLoopi++) {
		var thisRule = this.rules[flowLoopi];
		console.log("\x1b[36m### Next : Line "+ thisRule.line +" ###\x1b[37m");
		//console.log(thisRule);
		console.log(" ");
		console.log("\x1b[33mSTEP 1. Source :\x1b[37m");
		//console.log("Rule:"+thisRule.src+" Flow:"+flow.src);
		var goOn = thisRule.src.contains(flow.src);
		if(!goOn) {
			console.log("\x1b[31mNo Match\n\x1b[37m");
		} else {
			console.log("\x1b[32mHit!\x1b[37m");
			console.log(" ");
			console.log("\x1b[33mSTEP 2. Destination :\x1b[37m");
			//console.log("Rule:"+thisRule.dst+" Flow:"+flow.dst);
			//console.log(thisRule.dst);
			goOn = thisRule.dst.contains(flow.dst);
			if(!goOn) {
				console.log("\x1b[31mNo Match\n\x1b[37m");
			} else {
				console.log("\x1b[32mHit!\x1b[37m");
				console.log(" ");
				console.log("\x1b[33mSTEP 3. Protocol :\x1b[37m");
				//console.log("Rule:"+thisRule.protocol+" Flow:"+flow.protocol);
				if( thisRule.protocol == flow.protocol || (thisRule.protocol == 'ip' && (flow.protocol == 'tcp' || flow.protocol == 'udp')) ) {
					console.log("\x1b[32mFlow Permited\x1b[37m");
					break;
				} else {
					console.log("\x1b[31mNo Match\n\x1b[37m");
				}
			}
		}
	}
}

module.exports = acl;