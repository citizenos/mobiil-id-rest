# Simple Mobiil-ID rest client for node

## Install
```
npm install mobiil-id-rest
```

## Run tests
```
npm test
```

## Usage

### Configure client
```javascript
const mobiilIdClient = require('mobiil-id-rest')();

mobiilIdClient.init({
    hostname: "{hostname}",
    apiPath: "{apiPath}",
    relyingPartyUUID: "{relyingPartyUUID}",
    replyingPartyName: "{replyingPartyName}",
    issuers: [{
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of EID-SK 2015"
        }...]
});
```

### Authenticate
```javascript
mobiilId
    .authenticate(nationalIdentityNumber, phoneNumber)
    .then(function (result) {
        mobiilId
            .statusAuth(result.sessionId, result.sessionHash)
            .then(function (authResult) {
                /*
                authResult contains response from API, see https://github.com/SK-EID/MID#335-response-structure
                */
                mobiilId
                    .getCertUserData(authResult.cert)
                    .then(function (personalInfo) {
                        /* With structure {
                            firstName: subject.GivenName,
                            lastName: subject.SurName,
                            pid,
                            country: subject.Country
                        }*/
                    });
            });
    });
```

### Sign

This is basic example for signing, if the desired result is to sign a bdoc or asice container, see [undersign](https://github.com/moll/js-undersign). Example usages [citizenos](https://github.com/citizenos/citizenos-api) or [rahvaalgatus](https://github.com/rahvaalgatus/rahvaalgatus)

```javascript
const hash = crypto.createHash('SHA256');
hash.update('Sign this text');
const finalHash = hash.digest('hex');

mobiilId
        .signature(nationalIdentityNumber, phoneNumber, Buffer.from(finalHash, 'hex').toString('base64'))
        .then(function (result) {
            mobiilId.statusSign(result.sessionId)
                .then(function(signResult) {
                    /*
                    signResult contains response from API, see https://github.com/SK-EID/MID#335-response-structure
                    */
                });
        })
```

## Credits

* [CitizenOS](https://citizenos.com) for funding the development
