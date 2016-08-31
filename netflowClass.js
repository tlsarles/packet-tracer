var subs = require('./subClasses.js');

//Netflow Class
function netflow(source,destination,protocol) {
	this.src = source;
	this.dst = destination;
	this.protocol = protocol;
}
netflow.prototype.toString = function() {
	return this.source+","+this.destination+","+this.protocol;
}
function netflows() {
	this.netflows = Array();
	this.position = 0;
}
netflows.prototype.toString = function() {
	var output = "";
	for(i=0;i<this.netflows.length;i++) {
		output += this.netflows[i].toString()+"\n";
	}
	return output;
}
netflows.prototype.first = function() {
	this.position = 0;
	return this.netflows[0];
}
netflows.prototype.next = function() {
	this.position++;
	return this.netflows[this.position];
}
netflows.prototype.readFile = function(fileName, callback) {
	// Read File
	var lineReader = require('readline').createInterface({
	  input: require('fs').createReadStream(fileName)
	});
	// Line By Line
	lineReader.on('line', (line) => {
	  line = line.split(",");
	  var source = new subs.target(new subs.host(line[0]), "");
	  var dest = new subs.target(new subs.host(line[1]), new subs.port(line[3]));
	  var nf = new netflow(source,dest,line[2].toLowerCase());
	  this.netflows.push(nf);
	}).on('close', () => {
		callback();
	});
}

module.exports.netflows = netflows;