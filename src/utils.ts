import crypto from 'crypto';

export const createHash = async (input: string | Buffer = '', hashType: string = 'sha256'): Promise<string> => {
    const inputStr = input.toString() || crypto.randomBytes(20).toString();
    const hash = crypto.createHash(hashType);
    hash.update(inputStr);
    return hash.digest('hex');
};

export const getVerificationCode = async (sessionHash: string, format: BufferEncoding = 'hex'): Promise<string> => {
    const buf = Buffer.from(sessionHash, format);
    let binary = '';
    for (const value of buf.values()) {
        binary += value.toString(2).padStart(8, '0');
    }
    const finalNumber = binary.slice(0, 6) + binary.slice(-7);

    return parseInt(finalNumber, 2).toString(10).padStart(4, '0');
};

export const isEquivalent = (a: any, b: any): boolean => {
    const aProps = Object.getOwnPropertyNames(a);
    const bProps = Object.getOwnPropertyNames(b);

    if (aProps.length !== bProps.length) {
        return false;
    }

    for (let i = 0; i < aProps.length; i++) {
        const propName = aProps[i];
        if (a[propName] !== b[propName]) {
            return false;
        }
    }

    return true;
};
