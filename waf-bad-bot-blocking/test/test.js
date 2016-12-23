var AWS = require('aws-sdk-mock');
var myFunc = require('../function.js');
var lambdaLocal = require('lambda-local');
var myEvent = require('./event.js');
var assert = require('assert');

function testLambda(e) {
  return function(cb) {
 
    AWS.mock('WAF', 'getChangeToken', function(params, callback) {
      callback(null, {ChangeToken: "abcd12f2-46da-4fdb-b8d5-fbd4c466928f"});
    });
    
    AWS.mock('WAF', 'updateIPSet', function(params, callback) {
      callback(null, {ChangeToken: "abcd12f2-46da-4fdb-b8d5-fbd4c466928f"});
    });
    
    AWS.mock('SNS', 'publish', function(params, callback) {
      callback(null, {MessageId: '0'});
    });
  
    lambdaLocal.execute({
        event: e,
        lambdaFunc: myFunc,
        timeoutMs: 10000,
        callback: function(_err, _done) {
          err = _err;
          done = _done;
          cb();
        }
    });
  }
}

var done, err;
describe("successful event tests", function() {
  var mySuccessfulEvent = {
      "forwardedIps": "127.0.0.1, 172.91.235.252, 54.19.34.96",
      "viewerCountry": "US",
      "isDesktop": "true"
  };
  before(testLambda(mySuccessfulEvent));
  
  describe('Test Lambda blockedIp return', function() {
    it('ip should match first ip in mock event', function() {
      assert.equal(done.blockedIp, "172.91.235.252");
    });
  });
  
  describe('Test Lambda changeToken return', function() {
    it('changeToken should match that in event', function() {
      assert.equal(done.changeToken, "abcd12f2-46da-4fdb-b8d5-fbd4c466928f");
    });
  });
});

describe("bad event tests", function() {
  var myFailEvent = {
      "forwardedIps": "127.0.0.1",
      "viewerCountry": "US",
      "isDesktop": "true"
  };
  before(testLambda(myFailEvent));
  describe('Test Lambda return on invalid IP', function() {
    it('ip should match first ip in mock event', function() {
      assert.equal(err, "No valid IP addresses found");
    });
  });
});
