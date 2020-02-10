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

suite('Auth', function () {
    test('Success - Estonian mobile number and PID', function (done) {
        this.timeout(5000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        const personalInfo = {
                            firstName: 'MARY ÄNN',
                            lastName: 'O’CONNEŽ-ŠUSLIK TESTNUMBER',
                            pid: '60001019906',
                            country: 'EE'
                        };

                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'OK');
                        assert.deepEqual(authResult.personalInfo, personalInfo);
                        assert.deepEqual(Object.keys(authResult.signature), ['value', 'algorithm']);

                        return done();
                    }).catch(done);
            });
    });

    test('Fail - Invalid phone number', function (done) {
        const phoneNumber = '+372519';
        const nationalIdentityNumber = '60001019906';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .catch(function (e) {
                assert.equal(e.message, 'phoneNumber must contain of + and numbers(8-30)');
                done();
            });

    });

    test('Fail - Invalid national identity number', function (done) {
        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '510';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .catch(function (e) {
                assert.equal(e.message, 'nationalIdentityNumber must contain of 11 digits');
                done();
            });

    });

    test('Fail - Mobile-ID user has no active certificates', function (done) {
        const phoneNumber = '+37200000266';
        const nationalIdentityNumber = '60001019939';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId
                    .statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {

                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'NOT_MID_CLIENT');

                        return done();
                    }).catch(done);

            });
    });

    test('Fail - Sending authentication request to phone failed', function (done) {
        const phoneNumber = '+37207110066';
        const nationalIdentityNumber = '60001019947';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'DELIVERY_ERROR');

                        done();
                    }).catch(done);

            });
    });

    test('Fail - User cancelled authentication', function (done) {
        const phoneNumber = '+37201100266';
        const nationalIdentityNumber = '60001019950';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'USER_CANCELLED');

                        done();
                    }).catch(done);

            });
    });

    test('Fail - Created signature is not valid', function (done) {
        const phoneNumber = '+37200000666';
        const nationalIdentityNumber = '60001019961';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'SIGNATURE_HASH_MISMATCH');

                        done();
                    }).catch(done);

            });
    });

    test('Fail - SIM application error', function (done) {
        const phoneNumber = '+37201200266';
        const nationalIdentityNumber = '60001019972';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'SIM_ERROR');

                        done();
                    }).catch(done);

            });
    });

    test('Fail - Phone is not in coverage area', function (done) {
        const phoneNumber = '+37213100266';
        const nationalIdentityNumber = '60001019983';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber)
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'PHONE_ABSENT');

                        done();
                    }).catch(done);

            });
    });

    test('Fail - User does not react', function (done) {
        const phoneNumber = '+37066000266';
        const nationalIdentityNumber = '50001018908';

        mobiilId
            .authenticate(nationalIdentityNumber, phoneNumber, 'LT')
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusAuth(result.sessionId, result.sessionHash)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'TIMEOUT');

                        done();
                    }).catch(done);

            });
    });
});

suite('Sign', function () {
    test('Success - Estonian mobile number and PID', function (done) {
        this.timeout(5000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';
        const hash = crypto.createHash('SHA256');
        hash.update('Sign this text');
        const finalHash = hash.digest('hex');

        mobiilId
                .signature(nationalIdentityNumber, phoneNumber, Buffer.from(finalHash, 'hex').toString('base64'))
                .then(function (result) {
                    assert.match(result.challengeID, /[0-9]{4}/);
                    mobiilId.statusSign(result.sessionId)
                        .then(function(signResult) {
                            assert.equal(signResult.state, 'COMPLETE');
                            assert.equal(signResult.result, 'OK');
                            assert.property(signResult, 'signature');
                            done();
                        });
                })
                .catch(done);
    });

    test('Fail - Invalid hash', function (done) {
        this.timeout(5000); //eslint-disable-line no-invalid-this

        const phoneNumber = '+37200000766';
        const nationalIdentityNumber = '60001019906';

        mobiilId
            .signature(nationalIdentityNumber, phoneNumber, '')
            .catch(function (e) {
                assert.equal(e.message, 'hash must be valid Base64 string with length between 44 and 88');
                done();
            });
    });

    test('Fail - User does not react', function (done) {
        const phoneNumber = '+37066000266';
        const nationalIdentityNumber = '50001018908';

        const hash = crypto.createHash('SHA256');
        hash.update('Sign this text');
        const finalHash = hash.digest('hex');

        mobiilId
            .signature(nationalIdentityNumber, phoneNumber, Buffer.from(finalHash, 'hex').toString('base64'))
            .then(function (result) {
                assert.match(result.challengeID, /[0-9]{4}/);

                mobiilId.statusSign(result.sessionId)
                    .then(function (authResult) {
                        assert.equal(authResult.state, 'COMPLETE');
                        assert.equal(authResult.result, 'TIMEOUT');

                        done();
                    }).catch(done);

            });
    });
});