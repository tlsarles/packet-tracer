// Import SubClasses
var subs = require('./subClasses.js');

// Type is either Network or Service
function objGroup(name, type) {
	if(type == "reference") {
		name = name.split(" ")[1];
	}
	this.groupItems = Array();
	this.name = name;
	this.type = type;
}
objGroup.prototype.toString = function() {
	if(this.type == "reference") {
		var output = "object-group "+this.name;
	} else {
		var output = this.type+" object group "+this.name+"\n";
		for(i=0;i < this.groupItems.length;i++) {
			output += " "+this.groupItems[i]+"\n";
		}
	}
	return output;
}
objGroup.prototype.length = function() {
	var len = "object group "+this.name;
	return len.length;
}
objGroup.prototype.add = function(item) {
	this.groupItems.push(item);
}
objGroup.prototype.contains = function(input) {
	for(i=0;i<this.groupItems.length;i++) {
		console.log(this.groupItems[i]);
		if(this.groupItems[i].contains(input)) return true;
	}
	return false;
}
// objGroups is a container holding all objGroup objects
function objGroups() {
	this.allGroups = {};
}
objGroups.prototype.toString = function() {
	var output = "";
	for(var item in this.allGroups){
		output += this.allGroups[item].toString();
	}
	return output;
}
objGroups.prototype.add = function(group) {
	this.allGroups[group.name] = group;
}
objGroups.prototype.get = function(input) {
	return this.allGroups[input];
}
objGroups.prototype.readFile = function(fileName) {
	var newGroup = null;
	// Read File
	var lineReader = require('readline').createInterface({
	  input: require('fs').createReadStream(fileName)
	});
	// Line By Line
	lineReader.on('line', (line) => {
		// Catch new Object Group Declarations
		var re = /^(Network|Service) object group \S+/;
		if(re.test(line)) {
			re = /^(Network|Service)/;
			var groupType = re.exec(line)[0].trim();
			re = /\s\S+$/;
			var groupName = re.exec(line)[0].trim();
			newGroup = new objGroup(groupName, groupType);
			this.add(newGroup);
		}
		// Otherwise, parse out the line items within an object group
		else {
			var ret = subs.subTypeReader(line)[0];
			if(ret != " FAIL ") {
				newGroup.add(ret);
			}
		}
	}).on('close', () => {
		//console.log(this.toString());
		console.log("\x1b[33m### Groups Loaded ###\x1b[37m");
	});	
}

//var objectGroups = new objGroups();
//objectGroups.readFile();

module.exports.objGroup = objGroup;
module.exports.objGroups = objGroups;