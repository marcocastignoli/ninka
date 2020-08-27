const config = require('../config')
const fetch = require('node-fetch');

module.exports = {
    sendToken: async function (phone, verificationCode, content) {
        var options = {
            'method': 'POST',
            'headers': {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Authorization': config.sms_auth
            },
            body: `{\n\t\"to\":\"${phone}\",\n\t\"content\":\"${content}${verificationCode}\",\n\t\"from\":\"SMSINFO\",\n\t\"dlr\":\"yes\",\n\t\"dlr-method\":\"GET\", \n\t\"dlr-level\":\"2\", \n\t\"dlr-url\":\"http://yourcustompostbackurl.com\"\n}`
          
          };
        return await fetch('https://rest-api.d7networks.com/secure/send', options);
    }
}