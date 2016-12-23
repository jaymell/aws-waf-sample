/*
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

// init modules
var AWS = require('aws-sdk');
var ASYNC = require('async');
var VALIDATOR = require('validator');
var Promise = require('bluebird');

// get environment variables
var config = {
  region: process.env.REGION,
  wafIpSetId: process.env.WAFIPSETID,
  snsTopicArn: process.env.SNSTOPICARN
};

var wafClient = null;
var snsClient = null;
var lambdaClient = null;
var event = null;


function parseConfig() {
  return new Promise(function(resolve, reject) {
    // validate config:
    if (config.wafIpSetId === undefined || config.snsTopicArn === undefined || config.region === undefined ) {
      // error out
      reject('Missing required environment variables, perhaps function is misconfigured?');
    } else {
      // export configuration object & go to next stpe
      resolve({ config: { wafIpSetId: config.wafIpSetId, snsTopicArn: config.snsTopicArn }});
    }
  }); 
}



// extract and validate the source IP address
function extractAndValidate(context) {
  return new Promise(function(resolve, reject) {
    // make sure the input event is valid
    if (event.forwardedIps !== undefined && event.forwardedIps.length !== undefined && event.forwardedIps.length > 0) {
      // working with forwarded IPs only, API Gateway acts as a proxy and adds the source IP to the x-forwarded-for header
      var forwardedIps = event.forwardedIps.split(',');
      var foundValidIp = false;
      var sourceIp = '';

      // find the first valid IP address in the array (normally each proxy appends IPs to the header, so the first in the list is the source IP)
      forwardedIps.forEach(function(ip) {
        // trim whitespace
        ip = ip.trim();

        // skip if we already found the valid IP
        if (!foundValidIp) {
          // validate the IP address as a proper IPV4 address
          if (VALIDATOR.isIP(ip, 4)) {
            // exclude private IP ranges
            if (!(/(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)/.test(ip))) {
              // found the valid IP
              foundValidIp = true;
              sourceIp = ip;
            }
          }
        }
      });

      // did we find a valid IP
      if (foundValidIp) {
        // export the source IP, config & next step
        resolve({ config: context.config, sourceIp: sourceIp});
      } else {
        // error out
        reject('No valid IP addresses found');
      }
    } else {
      // error out
      reject('No valid list of IP addresses received');
    }
  });
}


// get a AWS WAF change token
function getWAFChangeToken(context) {
  return new Promise(function(resolve, reject) {
    // implementing separate retry mechanism to control interval
    ASYNC.retry({ times: 3, interval: 1002 }, function(tokenCallback, prevResult) {
      // call the AWS WAF API
      wafClient.getChangeToken({}, function(err, result) {
        if (err) {
          // log the error
          console.log(err, err.stack);

          // error out
          tokenCallback('Cannot provision an AWS WAF Change Token');
        } else {
          // make sure the output is valid
          if (result.ChangeToken !== undefined) {
            // export the source IP, config, token & next step
            tokenCallback(null, result.ChangeToken);
          } else {
            // error out
            tokenCallback('Received an unexpected response from the server while provisioning a WAF ChangeToken');
          }
        }
      });
    }, function(err, result) {
      if (err) {
        // error out
        reject(err);
      } else {
        // export the source IP, config, token & next step
        resolve({ config: context.config, sourceIp: context.sourceIp, changeToken: result});
      }
    });
  });
}


// update the AWS WAF IPSet using the token
function updateIPSet(context) {
  return new Promise(function(resolve, reject) {
    // implementing separate retry mechanism to control interval
    ASYNC.retry({ times: 3, interval: 1002 }, function(updateCallback, prevResult) {
      // call the AWS WAF API
      wafClient.updateIPSet({
        ChangeToken: context.changeToken,
        IPSetId: context.config.wafIpSetId,
        Updates: [ {
          Action: 'INSERT',
          IPSetDescriptor: {
            Type: 'IPV4',
            Value: context.sourceIp + '/32'
          }
        } ]
      }, function(err, result) {
        if (err) {
          // log the error
          console.log(err, err.stack);

          // error out
          updateCallback('Cannot update the specified WAF IPSet');
        } else {
          // make sure the output is valid
          if (result.ChangeToken !== undefined) {
            // export the source IP, config, token & next step
            updateCallback(null, true);
          } else {
            // error out
            updateCallback('Received an unexpected response from the server while updating the WAF IPSet: ' + result);
          }
        }
      });
    }, function(err, result) {
      if (err) {
        // error out
        reject(err);
      } else {
        // export the source IP, config, token & next step
        resolve({config: context.config, sourceIp: context.sourceIp, changeToken: context.changeToken});
      }
    });
  });
}


// issue an SNS notification
function issueSNSNotification(context) {
    return new Promise(function(resolve, reject) {
    // call the AWS SNS API
    snsClient.publish({
      Message: 'Blocked IP: ' + context.sourceIp + '\nChange token: ' + context.changeToken + '\nViewer Country: ' + ((event.viewerCountry !== undefined) ? event.viewerCountry : 'unknown') + '\nDesktop device: ' + ((event.isDesktop !== undefined) ? event.isDesktop : 'unknown') + '\nMobile device: ' + ((event.isMobile !== undefined) ? event.isMobile : 'unknown') + '\nSmartTV device: ' + ((event.isSmartTV !== undefined) ? event.isSmartTV : 'unknown') + '\nTablet device: ' + ((event.isTablet !== undefined) ? event.isTablet : 'unknown') + '\n',
      TopicArn: context.config.snsTopicArn,
      Subject: 'WAF: Bad Bot Blocked: ' + context.sourceIp
    }, function(err, result) {
      if (err) {
        // log the error
        console.log(err, err.stack);
        // error out
        reject('Cannot send a notification to the SNS Topic specified');
      } 
      else {
        // make sure the output is valid
        if (result.MessageId !== undefined) {
          // export the sourceIp, token & next step
          resolve({ blockedIp: context.sourceIp, changeToken: context.changeToken});
        } else {
          // error out
          reject('Received an unexpected response from the server while sending a message via SNS');
        }
      }
    });
  });
}


// export lambda function
exports.handler = function(e, context, callback) {
  event = e;
  wafClient = new AWS.WAF({ region: config.region, maxRetries: 30 });
  snsClient = new AWS.SNS({ maxRetries: 30 });
  lambdaClient = new AWS.Lambda({ maxRetries: 30 });

  parseConfig()
    .then(extractAndValidate)
    .then(getWAFChangeToken)
    .then(updateIPSet)
    .then(issueSNSNotification)
    .then(function(result) {
      console.log('success');
      callback(null, result);
    })
    .catch(function(err) {
      console.log('error: ', err);
      callback(err);
    });
}
