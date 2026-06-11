export interface MobileIdOptions {
    hostname: string;
    apiPath: string;
    relyingPartyUUID: string;
    relyingPartyName: string;
    replyingPartyName?: string; // For backward compatibility
    authorizeToken?: string;
    issuers: Issuer[];
    loggerLevel?: string;
}

export interface Issuer {
    C?: string;
    O?: string;
    OID?: string;
    CN: string;
    E?: string;
    [key: string]: string | undefined;
}

export interface AuthenticationResponse {
    sessionId: string;
    challengeID: string;
    sessionHash: string;
}

export interface SessionStatusResponse {
    state: 'RUNNING' | 'COMPLETE';
    result: 'OK' | 'USER_REFUSED' | 'TIMEOUT' | 'QUARANTINE_FULL' | 'USER_SELECTED_WRONG_VC' | 'DOCUMENT_UNUSABLE' | 'NOT_MID_CLIENT' | 'PHONE_ABSENT' | 'SIGNATURE_HASH_MISMATCH' | 'SIM_ERROR' | 'DELIVERY_ERROR';
    signature?: {
        value: string;
        algorithm: string;
    };
    cert?: string;
    personalInfo?: PersonalInfo;
    traceId?: string;
    time?: string;
    [key: string]: any;
}

export interface PersonalInfo {
    firstName: string;
    lastName: string;
    pid: string;
    country: string;
}

export interface SignatureResponse {
    sessionId: string;
    challengeID: string;
    sessionHash: string;
}
