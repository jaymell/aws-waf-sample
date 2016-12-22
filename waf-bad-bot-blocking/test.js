var AWS = require('aws-sdk-mock');

AWS.mock('WAF', 'getChangeToken', function(params, callback) {
  callback(null, {ChangeToken: "abcd12f2-46da-4fdb-b8d5-fbd4c466928f"});
});

var config = {
  region: process.env.REGION,
  wafIpSetId: process.env.WAFIPSETID,
  snsTopicArn: process.env.SNSTOPICARN
};

var WAF = new AWS.WAF();
console.log('success');
