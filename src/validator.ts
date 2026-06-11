import * as Asn1js from 'asn1js';
import * as Pkijs from 'pkijs';
import { ec as EC } from 'elliptic';
import forge from 'node-forge';
import rsautl from 'simple_rsautl';
import { OID } from './constants';
import { ValidationError } from './errors';
import { isEquivalent } from './utils';
import { Issuer, PersonalInfo } from './types';

export const prepareCert = (certificateString: string, format: BufferEncoding = 'base64'): Pkijs.Certificate => {
    if (typeof certificateString !== 'string') {
        throw new Error('Expected PEM as string, received: ' + typeof certificateString);
    }

    const der = Buffer.from(certificateString, format);
    const ber = new Uint8Array(der).buffer;
    const asn1 = Asn1js.fromBER(ber);
    return new Pkijs.Certificate({ schema: asn1.result });
};

export const validateEC = async (cert: Pkijs.Certificate, hash: string, signatureString: string): Promise<boolean> => {
    const ec = new EC('p256');
    const parsedKey = cert.subjectPublicKeyInfo.parsedKey as any;
    if (!parsedKey || !parsedKey.x || !parsedKey.y) {
        throw new ValidationError("Invalid public key in certificate");
    }
    const publicKeyData = {
        x: Buffer.from(parsedKey.x).toString('hex'),
        y: Buffer.from(parsedKey.y).toString('hex')
    };
    const key = ec.keyFromPublic(publicKeyData, 'hex');

    const m = Buffer.from(signatureString, 'base64').toString('hex').match(/([a-f\d]{64})/gi);
    if (!m || m.length < 2) {
        throw new ValidationError("Invalid signature format");
    }

    const signature = {
        r: m[0],
        s: m[1]
    };

    if (key.verify(hash, signature)) {
        return true;
    } else {
        throw new ValidationError("Invalid signature");
    }
};

export const validateRSA = async (cert: forge.pki.Certificate, hash: string, signatureString: string): Promise<boolean> => {
    const publicKey = forge.pki.publicKeyToPem(cert.publicKey);
    const sha256Prefix = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
    const items = [Buffer.from(sha256Prefix), Buffer.from(hash, 'hex')];

    const verified = await rsautl.verify(signatureString, publicKey, { padding: null, encoding: null });
    const verificationResult = Buffer.from(verified).toString('hex');
    const prefixedHash = Buffer.concat(items).toString('hex');
    
    if (verificationResult === prefixedHash) {
        return true;
    } else {
        throw new ValidationError("Invalid signature");
    }
};

export const validateIssuer = (cert: Pkijs.Certificate, allowedIssuers: Issuer[]): boolean => {
    const issuerData: Record<string, string> = {};
    cert.issuer.typesAndValues.forEach((item) => {
        const oidInfo = OID[item.type];
        if (oidInfo && oidInfo.short) {
            issuerData[oidInfo.short] = (item.value.valueBlock as any).value;
        }
    });

    const isValid = allowedIssuers.some((issuer) => isEquivalent(issuer, issuerData));

    if (!isValid) {
        throw new ValidationError('Invalid certificate issuer');
    }

    return true;
};

export const validateCert = (cert: Pkijs.Certificate | string, allowedIssuers: Issuer[], format?: BufferEncoding): boolean => {
    let certificate: Pkijs.Certificate;
    if (typeof cert === 'string' && format) {
        certificate = prepareCert(cert, format);
    } else if (typeof cert !== 'string') {
        certificate = cert;
    } else {
        throw new Error('Invalid certificate or format missing');
    }

    const now = new Date();
    if (now <= new Date(certificate.notBefore.value) || now >= new Date(certificate.notAfter.value)) {
        throw new ValidationError('Certificate not active');
    }

    return validateIssuer(certificate, allowedIssuers);
};

export const getCertValue = (key: 'subject' | 'issuer', cert: Pkijs.Certificate): Record<string, string> => {
    const res: Record<string, string> = {};
    cert[key].typesAndValues.forEach((typeAndValue) => {
        const type = typeAndValue.type.toString();
        const oid = OID[type];
        const name = oid ? oid.long : type;
        res[name] = (typeAndValue.value.valueBlock as any).value;
    });

    return res;
};

export const getCertUserData = (certificate: string, format: BufferEncoding = 'base64'): PersonalInfo => {
    const cert = prepareCert(certificate, format);
    const subject = getCertValue('subject', cert);
    const commonName = subject.CommonName || '';
    const givenName = subject.GivenName || '';
    const surName = subject.SurName || '';
    
    let pid = subject.DeviceSerialNumber || commonName.split(',').filter((item) => item !== givenName && item !== surName)[0];

    if (pid && pid.indexOf('PNO') > -1) {
        pid = pid.substring(6);
    }

    return {
        firstName: givenName,
        lastName: surName,
        pid,
        country: subject.Country
    };
};
