'use strict';

/**
 * @returns {object} MobileId object
 */
function MobileId () {
    const that = this;
    const crypto = require('crypto');
    const https = require('https');
    const logger = require('log4js').getLogger();
    const Pkijs = require('pkijs');
    const Asn1js = require('asn1js');
    const EC = require('elliptic').ec;
    const forge = require('node-forge');
    const rsautl = require('simple_rsautl');

    let _replyingPartyUUID;
    let _replyingPartyName;
    let _authorizeToken;
    let _issuers;

    let _hostname;
    let _apiPath;
    let _port;
    const LANGUAGES = {
        et: 'EST',
        en: 'ENG',
        ru: 'RUS',
        lt: 'LIT'
    }

    const OID = {
        "2.5.4.3": {
            short: "CN",
            long: "CommonName",
        },
        "2.5.4.6": {
            short: "C",
            long: "Country",
        },
        "2.5.4.5": {
            long: "DeviceSerialNumber",
        },
        "0.9.2342.19200300.100.1.25": {
            short: "DC",
            long: "DomainComponent",
        },
        "1.2.840.113549.1.9.1": {
            short: "E",
            long: "EMail",
        },
        "2.5.4.42": {
            short: "G",
            long: "GivenName",
        },
        "2.5.4.43": {
            short: "I",
            long: "Initials",
        },
        "2.5.4.7": {
            short: "L",
            long: "Locality",
        },
        "2.5.4.10": {
            short: "O",
            long: "Organization",
        },
        "2.5.4.97": {
            short: "OID",
            long: "OrganizationIdentifier"
        },
        "2.5.4.11": {
            short: "OU",
            long: "OrganizationUnit",
        },
        "2.5.4.8": {
            short: "ST",
            long: "State",
        },
        "2.5.4.9": {
            short: "Street",
            long: "StreetAddress",
        },
        "2.5.4.4": {
            short: "SN",
            long: "SurName",
        },
        "2.5.4.12": {
            short: "T",
            long: "Title",
        },
        "1.2.840.113549.1.9.8": {
            long: "UnstructuredAddress",
        },
        "1.2.840.113549.1.9.2": {
            long: "UnstructuredName",
        },
    };

    class ValidationError extends Error {
        constructor(message) {
            super(message);
            this.name = "ValidationError";
        }
    }

    const _createHash = async function (input = '', hashType) {
        input = input.toString() || crypto.randomBytes(20).toString();
        hashType = hashType || 'sha256';

        const hash = crypto.createHash(hashType);
        hash.update(input);

        return hash.digest('hex');
    };

    const _apiRequest = async function (params, options) {
        return new Promise(function (resolve, reject) {
            const request = https.request(options, function (result) {
                let data = '';
                result.setEncoding('utf8');
                result.on('data', function (chunk) {
                    data += chunk;
                });

                result.on('end', function () {
                    try {
                        data = JSON.parse(data);
                        return resolve({
                            status: result.statusCode,
                            data: data
                        });
                    } catch (e) {
                        return reject(e);
                    }
                });
            });

            if (params) {
                request.write(params);  // write data to request body
            }
            request.end();
            request.on('error', function (e) {
                return reject(e);
            });
        });
    };

    const _init = async function (options) {
        _replyingPartyUUID = options.relyingPartyUUID;
        _replyingPartyName = options.replyingPartyName;
        _authorizeToken = options.authorizeToken;
        _issuers = options.issuers;
        logger.level = process.env || options.loggerLevel;

        if (options.hostname) {
            const hostData = options.hostname.split(':');
            _hostname = hostData[0];
            _port = hostData[1] || 443;
        }

        _apiPath = options.apiPath;

        return that;
    };

    const getCertValue = async function (key, cert) {
        let res = {};
        cert[key].typesAndValues.forEach(function (typeAndValue) {
            const type = typeAndValue.type;
            const oid = OID[type.toString()];
            const name2 = oid ? oid.long : null;
            res[`${name2 ? name2 : type}`] = `${typeAndValue.value.valueBlock.value}`;
        });

        return res;
    };

    const _prepareCert = async function (certificateString, format) {
        if (typeof certificateString !== 'string') {
            throw new Error('Expected PEM as string, recieved:' + typeof certificateString);
        }

        // Now that we have decoded the cert it's now in DER-encoding
        const der = Buffer.from(certificateString, format);

        // And massage the cert into a BER encoded one
        const ber = new Uint8Array(der).buffer;

        // And now Asn1js can decode things \o/
        const asn1 = Asn1js.fromBER(ber);
        const cert = new Pkijs.Certificate({schema: asn1.result});

        return cert;
    };

    const _getCertUserData = async function (certificate, format) {
        const cert = await _prepareCert(certificate, format);
        const subject = await getCertValue('subject', cert);
        const pid = subject.CommonName.split(',').filter(function (item) {return item !== subject.GivenName && item !== subject.SurName})[0];

        return {
            firstName: subject.GivenName,
            lastName: subject.SurName,
            pid,
            country: subject.Country
        };
    };

    const _getVerificationCode = async function (sessionHash, format) {
        format = format || 'hex';
        const buf = Buffer.from(sessionHash, format);
        let binary = '';
        for (const value of buf.values()) {
            binary += value.toString(2).padStart(8, '0');
        }
        const finalNumber = binary.slice(0, 6) +''+ binary.slice(-7);

        return parseInt(finalNumber, 2).toString(10).padStart(4, '0');
    };

    const _getUserCertificate = async function (nationalIdentityNumber, phoneNumber) {
            const path = _apiPath + '/certificate';

            let params = {
                relyingPartyUUID: _replyingPartyUUID,
                relyingPartyName: _replyingPartyName,
                phoneNumber,
                nationalIdentityNumber
            };

            params = JSON.stringify(params);

            const options = {
                hostname: _hostname,
                path: path,
                method: 'POST',
                port: _port,
                headers: {
                    'Authorization': 'Bearer ' + _authorizeToken,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(params, 'utf8')
                }
            };

            const result = await _apiRequest(params, options);
            if (result.data && result.data.cert) {
                await _validateCert(await _prepareCert(result.data.cert, 'base64'))
                return result.data.cert;
            } else if (result.data.error) {
                throw new Error(result.data.error);
            }

            return result;
    };

    const _authenticate = async function (nationalIdentityNumber, phoneNumber, language) {
        const sessionHash = await _createHash();
        const path = _apiPath + '/authentication';
        language = LANGUAGES[language] || LANGUAGES.en;
        const hashType = 'sha256';

        let params = {
            relyingPartyUUID: _replyingPartyUUID,
            relyingPartyName: _replyingPartyName,
            phoneNumber,
            nationalIdentityNumber,
            language,
            hash: Buffer.from(sessionHash, 'hex').toString('base64'),
            hashType: hashType.toUpperCase()
        };

        params = JSON.stringify(params);

        const options = {
            hostname: _hostname,
            path: path,
            method: 'POST',
            port: _port,
            headers: {
                'Authorization': 'Bearer ' + _authorizeToken,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(params, 'utf8')
            }
        };

        const result = await _apiRequest(params, options);
        if (result.data.sessionID) {
            return {
                sessionId: result.data.sessionID,
                challengeID: await _getVerificationCode(sessionHash),
                sessionHash
            };
        } else if (result.data.error) {
            let err = new Error(result.data.error);
            logger.error(err);
            err.code = result.status;

            throw err;
        } else {
            return result;
        }
    };

    const _getSessionStatusData = async function (type, sessionId, timeout) {

        let path = _apiPath + '/' + type + '/session/:sessionId'.replace(':sessionId', sessionId);
        if (timeout) {
            path += '?timeoutMs=' + timeout;
        }
        const options = {
            hostname: _hostname,
            path: path,
            method: 'GET',
            port: _port,
            requestCert: true,
            requestOCSP: true,
            headers: {
                'Authorization': 'Bearer ' + _authorizeToken
            }
        };

        return _apiRequest(null, options);
    };

    const _validateEC = async function (cert,hash, signatureString) {
        const ec = new EC('p256');
        const publicKeyData = {
            x: Buffer.from(cert.subjectPublicKeyInfo.parsedKey.x).toString('hex'),
            y: Buffer.from(cert.subjectPublicKeyInfo.parsedKey.y).toString('hex')
        };
        const key = ec.keyFromPublic(publicKeyData, 'hex');

        // Splits to 2 halfs
        const m = Buffer.from(signatureString, 'base64').toString('hex').match(/([a-f\d]{64})/gi);

        const signature = {
            r: m[0],
            s: m[1]
        };

        return key.verify(hash, signature);
    };

    const _validateRSA = async function (cert, hash, signatureString) {
        const publicKey = forge.pki.publicKeyToPem(cert.publicKey);
        const sha256Prefix = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
        const items = [Buffer.from(sha256Prefix), Buffer.from(hash, 'hex')];

        const verified = await rsautl.verify(signatureString, publicKey, {padding: null, encoding: null});
        const verificationResult = Buffer.from(verified).toString('hex');
        const prefixedHash = Buffer.concat(items).toString('hex')

        return (verificationResult === prefixedHash);
    };

    const _isEquivalent = function (a, b) {
        var aProps = Object.getOwnPropertyNames(a);
        var bProps = Object.getOwnPropertyNames(b);

        if (aProps.length != bProps.length) {
            return false;
        }

        for (var i = 0; i < aProps.length; i++) {
            var propName = aProps[i];

            if (a[propName] !== b[propName]) {
                return false;
            }
        }

        return true;
    };

    const _validateIssuer = async function (cert) {
        let IssuerData = {};
        cert.issuer.typesAndValues.map(function (item) {
            IssuerData[OID[item.type].short] = item.value.valueBlock.value;
        });

        let isValid = false;

        _issuers.forEach(function (issuer) {
            if (_isEquivalent(issuer, IssuerData)) {
                isValid = true;
            }
        });

        if(!isValid) {
            logger.error('Invalid issuer: ' + JSON.stringify(IssuerData));
            throw new ValidationError('Invalid certificate issuer');
        }

        return true;
    };

    const _validateCert = async function (cert, format) {
        if (typeof cert === 'string' && format) {
            cert = await _prepareCert(cert, format);
        }

        const now = new Date();

        if (now <= new Date(cert.notBefore.value) ||  now >= new Date(cert.notAfter.value)) {
            throw new ValidationError('Certificate not active');
        }

        return _validateIssuer(cert);
    };

    const _validateAuthorization = async function (authResponse, sessionHash) {
        const cert = await _prepareCert(authResponse.cert, 'base64');

        await _validateCert(cert);
        if (cert.subjectPublicKeyInfo.parsedKey.x && cert.subjectPublicKeyInfo.parsedKey.y) {
            return _validateEC(cert, sessionHash, authResponse.signature.value);
        }

        const certPem = forge.pki.certificateFromPem('-----BEGIN CERTIFICATE-----\n' +authResponse.cert.value + '\n-----END CERTIFICATE-----');

        return _validateRSA(certPem, sessionHash, authResponse.signature.value);
    };

    const _statusAuth = async function (sessionId, sessionHash, timeoutMs) {
        const data = (await _getSessionStatusData('authentication', sessionId, timeoutMs)).data;
        if (data.state === 'COMPLETE' && data.result === 'OK') {
            await _validateAuthorization(data, sessionHash);
            const personalInfo = await _getCertUserData(data.cert, 'base64');
            data.personalInfo = personalInfo;
            return data;
        }

        return data;
    };

    const _signature = async function (nationalIdentityNumber, phoneNumber, sessionHash, language) {
        const hashType = 'sha256';
        language = LANGUAGES[language] || LANGUAGES.en;

        const path = _apiPath + '/signature';
        let params = JSON.stringify({
            relyingPartyUUID: _replyingPartyUUID,
            relyingPartyName: _replyingPartyName,
            phoneNumber,
            nationalIdentityNumber,
            language,
            hash: sessionHash,
            hashType: hashType.toUpperCase()
        });

        const options = {
            hostname: _hostname,
            path: path,
            method: 'POST',
            port: _port,
            headers: {
                'Authorization': 'Bearer ' + _authorizeToken,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(params, 'utf8')
            }
        };

        const result = await _apiRequest(params, options);
            if (result.data.sessionID) {
                const verficationCode = await _getVerificationCode(sessionHash, 'base64');

                return {
                    sessionId: result.data.sessionID,
                    challengeID: verficationCode,
                    sessionHash: sessionHash
                };
            } else if (result.data.error) {
                let err = new Error(result.data.error);
                logger.error(err);
                err.code = result.statusCode;

                throw err;
            } else {
                return result;
            }
    };

    const _statusSign = async function (sessionId, timeoutMs) {
        return (await _getSessionStatusData('signature', sessionId, timeoutMs)).data;
    };

    return {
        init: _init,
        getUserCertificate: _getUserCertificate,
        getCertUserData: _getCertUserData,
        getVerificationCode: _getVerificationCode,
        authenticate: _authenticate,
        statusAuth: _statusAuth,
        signature: _signature,
        statusSign: _statusSign,
        validateCert: _validateCert
    };
}

module.exports = MobileId;
