import axios, { AxiosInstance } from 'axios';
import forge from 'node-forge';
import { MobileIdOptions, AuthenticationResponse, SessionStatusResponse, SignatureResponse } from './types';
import { MobileIdError } from './errors';
import { createHash, getVerificationCode } from './utils';
import { prepareCert, validateCert, validateEC, validateRSA, getCertUserData } from './validator';
import { LANGUAGES } from './constants';

export class MobileId {
    private options!: MobileIdOptions;
    private client!: AxiosInstance;

    constructor(options?: MobileIdOptions) {
        if (options) {
            this.init(options);
        }
    }

    public init(options: MobileIdOptions): void {
        this.options = {
            ...options,
            relyingPartyName: options.relyingPartyName || options.replyingPartyName || ''
        };
        const baseURL = `https://${options.hostname}${options.apiPath}`;
        this.client = axios.create({
            baseURL,
            headers: {
                'Authorization': `Bearer ${options.authorizeToken}`,
                'Content-Type': 'application/json'
            }
        });
    }

    public async authenticate(
        nationalIdentityNumber: string,
        phoneNumber: string,
        language: string = 'en',
        displayText?: string,
        displayTextFormat?: 'GSM-7' | 'UCS-2'
    ): Promise<AuthenticationResponse> {
        const sessionHash = await createHash();
        const path = '/authentication';
        const lang = LANGUAGES[language] || LANGUAGES.en;
        const hashType = 'SHA256';

        try {
            const response = await this.client.post(path, {
                relyingPartyUUID: this.options.relyingPartyUUID,
                relyingPartyName: this.options.relyingPartyName,
                phoneNumber,
                nationalIdentityNumber,
                language: lang,
                hash: Buffer.from(sessionHash, 'hex').toString('base64'),
                hashType: hashType,
                displayText,
                displayTextFormat
            });

            const data = response.data;
            if (data.sessionID) {
                const verificationCode = await getVerificationCode(sessionHash);
                return {
                    sessionId: data.sessionID,
                    challengeID: verificationCode,
                    sessionHash: sessionHash
                };
            }

            throw new MobileIdError(data.error || 'Authentication failed');
        } catch (error: any) {
            if (error.response && error.response.data) {
                throw new MobileIdError(error.response.data.error || error.message, error.response.status);
            }
            throw error;
        }
    }

    public async getSessionStatus(type: 'authentication' | 'signature', sessionId: string, timeoutMs?: number): Promise<SessionStatusResponse> {
        let path = `/${type}/session/${sessionId}`;
        if (timeoutMs) {
            path += `?timeoutMs=${timeoutMs}`;
        }

        try {
            const response = await this.client.get(path);
            return response.data;
        } catch (error: any) {
            if (error.response && error.response.data) {
                throw new MobileIdError(error.response.data.error || error.message, error.response.status);
            }
            throw error;
        }
    }

    public async statusAuth(sessionId: string, sessionHash: string, timeoutMs?: number): Promise<SessionStatusResponse> {
        const data = await this.getSessionStatus('authentication', sessionId, timeoutMs);

        if (data.state === 'COMPLETE' && data.result === 'OK') {
            await this.validateAuthorization(data, sessionHash);
            if (data.cert) {
                data.personalInfo = getCertUserData(data.cert, 'base64');
            }
        }

        return data;
    }

    private async validateAuthorization(authResponse: any, sessionHash: string): Promise<boolean> {
        const cert = prepareCert(authResponse.cert, 'base64');
        validateCert(cert, this.options.issuers);

        const parsedKey = cert.subjectPublicKeyInfo.parsedKey as any;
        if (parsedKey && parsedKey.x && parsedKey.y) {
            return validateEC(cert, sessionHash, authResponse.signature.value);
        }

        const certPem = forge.pki.certificateFromPem(`-----BEGIN CERTIFICATE-----\n${authResponse.cert}\n-----END CERTIFICATE-----`);
        return validateRSA(certPem, sessionHash, authResponse.signature.value);
    }

    public async getUserCertificate(nationalIdentityNumber: string, phoneNumber: string): Promise<string> {
        const path = '/certificate';

        try {
            const response = await this.client.post(path, {
                relyingPartyUUID: this.options.relyingPartyUUID,
                relyingPartyName: this.options.relyingPartyName,
                phoneNumber,
                nationalIdentityNumber
            });

            const data = response.data;
            if (data && data.cert) {
                validateCert(prepareCert(data.cert, 'base64'), this.options.issuers);
                return data.cert;
            }

            throw new MobileIdError(data.error || 'Certificate choice failed');
        } catch (error: any) {
            if (error.response && error.response.data) {
                throw new MobileIdError(error.response.data.error || error.message, error.response.status);
            }
            throw error;
        }
    }

    public async signature(
        nationalIdentityNumber: string,
        phoneNumber: string,
        sessionHash: string,
        language: string = 'en',
        displayText?: string,
        displayTextFormat?: 'GSM-7' | 'UCS-2'
    ): Promise<SignatureResponse> {
        const hashType = 'SHA256';
        const lang = LANGUAGES[language] || LANGUAGES.en;
        const path = '/signature';

        try {
            const response = await this.client.post(path, {
                relyingPartyUUID: this.options.relyingPartyUUID,
                relyingPartyName: this.options.relyingPartyName,
                phoneNumber,
                nationalIdentityNumber,
                language: lang,
                hash: sessionHash,
                hashType: hashType,
                displayText,
                displayTextFormat
            });

            const data = response.data;
            if (data.sessionID) {
                const verificationCode = await getVerificationCode(sessionHash, 'base64');
                return {
                    sessionId: data.sessionID,
                    challengeID: verificationCode,
                    sessionHash: sessionHash
                };
            }

            throw new MobileIdError(data.error || 'Signature request failed');
        } catch (error: any) {
            if (error.response && error.response.data) {
                throw new MobileIdError(error.response.data.error || error.message, error.response.status);
            }
            throw error;
        }
    }

    public async statusSign(sessionId: string, timeoutMs?: number): Promise<SessionStatusResponse> {
        return this.getSessionStatus('signature', sessionId, timeoutMs);
    }
}
