'use strict'

const testConfig = {
    hostname: "tsp.demo.sk.ee",
    apiPath: "/mid-api",
    relyingPartyUUID: "00000000-0000-0000-0000-000000000000",
    replyingPartyName: "DEMO",
    issuers: [
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of EID-SK 2015"
        },
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "EID-SK 2016"
        },
        {
          "C": "EE",
          "O": "SK ID Solutions AS",
          "OID": "NTREE-10747013",
          "CN": "ESTEID2018"
        },
        {
          "CN": "ESTEID-SK 2011",
          "O": "AS Sertifitseerimiskeskus",
          "C": "EE"
        },
        {
          "CN": "EID-SK 2011",
          "O": "AS Sertifitseerimiskeskus",
          "C": "EE"
        },
        {
          "CN": "ESTEID-SK 2015",
          "OID": "NTREE-10747013",
          "O": "AS Sertifitseerimiskeskus",
          "C": "EE"
        },
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of EID-SK 2015"
        },
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of EID-SK 2016"
        },
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of ESTEID-SK 2015"
        },
        {
          "C": "EE",
          "O": "AS Sertifitseerimiskeskus",
          "OID": "NTREE-10747013",
          "CN": "TEST of ESTEID-SK 2016"
        },
        {
          "C":"EE",
          "O":"AS Sertifitseerimiskeskus",
          "CN":"TEST of EID-SK 2011",
          "E":"pki@sk.ee"
        }
      ]
};

const assert = require('chai').assert;
const crypto = require('crypto');
const mobiilId = require('../index.js')();
mobiilId.init(testConfig);

suite('Certificate', function () {
    test('Success', async function () {
        this.timeout(5000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';

        const result = await mobiilId.getUserCertificate(nationalIdentityNumber, phoneNumber);
        assert.match(result, /[0-9A-B]/);
    });
});
suite('Auth', function () {
    test('Success - Estonian mobile number and PID', async function () {
        this.timeout(10000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37268000769';
        const nationalIdentityNumber = '60001017869';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        const personalInfo = {
            firstName: 'EID2016',
            lastName: 'TESTNUMBER',
            pid: 'PNOEE-60001017869',
            country: 'EE'
        };

        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'OK');
        assert.deepEqual(authResult.personalInfo, personalInfo);
        assert.deepEqual(Object.keys(authResult.signature), ['value', 'algorithm']);
    });

    test('Fail - Invalid phone number', async function () {
        const phoneNumber = '+372519';
        const nationalIdentityNumber = '60001019906';

        try {
            await mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber);
        } catch(e) {
            assert.equal(e.message, 'phoneNumber must contain of + and numbers(8-30)');
        };

    });

    test('Fail - Invalid national identity number', async function () {
        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '510';

        try {
            await mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber);
        } catch(e) {
            assert.equal(e.message, 'nationalIdentityNumber must contain of 11 digits');
        };

    });

    test('Fail - Mobile-ID user has no active certificates', async function () {
        const phoneNumber = '+37200000266';
        const nationalIdentityNumber = '60001019939';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'NOT_MID_CLIENT');
    });

    test('Fail - Sending authentication request to phone failed', async function () {
        const phoneNumber = '+37207110066';
        const nationalIdentityNumber = '60001019947';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'DELIVERY_ERROR');
    });

    test('Fail - User cancelled authentication', async function () {
        const phoneNumber = '+37201100266';
        const nationalIdentityNumber = '60001019950';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'USER_CANCELLED');
    });

    test('Fail - Created signature is not valid', async function () {
        const phoneNumber = '+37200000666';
        const nationalIdentityNumber = '60001019961';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'SIGNATURE_HASH_MISMATCH');
    });

    test('Fail - SIM application error', async function () {
        const phoneNumber = '+37201200266';
        const nationalIdentityNumber = '60001019972';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'SIM_ERROR');
    });

    test('Fail - Phone is not in coverage area', async function () {
        const phoneNumber = '+37213100266';
        const nationalIdentityNumber = '60001019983';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber);
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'PHONE_ABSENT');
    });

    test('Fail - User does not react', async function () {
        const phoneNumber = '+37066000266';
        const nationalIdentityNumber = '50001018908';

        const result = await mobiilId.authenticate(nationalIdentityNumber, phoneNumber, 'LT');
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusAuth(result.sessionId, result.sessionHash);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'TIMEOUT');
    });
});

suite('Sign', function () {
    test('Success - Estonian mobile number and PID', async function () {
        this.timeout(15000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';
        const hash = crypto.createHash('SHA256');
        hash.update('Sign this text');
        const finalHash = hash.digest('hex');

        const result = await mobiilId.signature(nationalIdentityNumber, phoneNumber, Buffer.from(finalHash, 'hex').toString('base64'));
        assert.match(result.challengeID, /[0-9]{4}/);
        const signResult = await mobiilId.statusSign(result.sessionId);
        assert.equal(signResult.state, 'COMPLETE');
        assert.equal(signResult.result, 'OK');
        assert.property(signResult, 'signature');
    });

    test('Fail - Invalid hash', async function () {
        this.timeout(5000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';

        try {
            await mobiilId.signature(nationalIdentityNumber, phoneNumber, '');
        } catch(e) {
            assert.equal(e.message, 'hash must be valid Base64 string with length between 44 and 88');
        };
    });

    test('Fail - User does not react', async function () {
        const phoneNumber = '+37066000266';
        const nationalIdentityNumber = '50001018908';

        const hash = crypto.createHash('SHA256');
        hash.update('Sign this text');
        const finalHash = hash.digest('hex');

        const result = await mobiilId.signature(nationalIdentityNumber, phoneNumber, Buffer.from(finalHash, 'hex').toString('base64'));
        assert.match(result.challengeID, /[0-9]{4}/);

        const authResult = await mobiilId.statusSign(result.sessionId, 10000);
        assert.equal(authResult.state, 'COMPLETE');
        assert.equal(authResult.result, 'TIMEOUT');
    });
});