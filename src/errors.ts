export class MobileIdError extends Error {
    public code?: string | number;
    constructor(message: string, code?: string | number) {
        super(message);
        this.name = "MobileIdError";
        this.code = code;
    }
}

export class ValidationError extends MobileIdError {
    constructor(message: string) {
        super(message);
        this.name = "ValidationError";
    }
}
