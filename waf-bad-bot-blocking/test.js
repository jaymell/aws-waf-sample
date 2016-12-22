var AWS = require('aws-sdk-mock');
var func = require('./function.js');

AWS.mock('WAF', 'getChangeToken', function(params, callback) {
  callback(null, {ChangeToken: "abcd12f2-46da-4fdb-b8d5-fbd4c466928f"});
});

AWS.mock('WAF', 'updateIPSet', function(params, callback) {
  callback(null, {ChangeToken: "abcd12f2-46da-4fdb-b8d5-fbd4c466928f"});
});

AWS.mock('SNS', 'publish', function(params, callback) {
  callback(null, {MessageId: '0'});
});

exports.handler = func.handler;
