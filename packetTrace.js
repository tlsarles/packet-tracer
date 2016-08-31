// Imports
var acl = require('./aclClass.js');
var subs = require('./subClasses.js');
var net = require('./netflowClass.js');

var ACL = new acl();
ACL.setObjGroups('objGroups.txt');
ACL.readFile('aws_acl_in.txt', function() {
	console.log("################### START ########################");
	var nf = new net.netflows();
	nf.readFile('AWSTraffic.csv', function() {
		var thisnf = nf.first();
		ACL.checkFlow(thisnf);
		
		/*
		while(thisnf = nf.next()) {
			ACL.checkFlow(thisnf);
		}
		*/
	});

});



