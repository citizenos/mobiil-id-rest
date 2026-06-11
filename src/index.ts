import { MobileId } from './MobileId';
import { MobileIdOptions } from './types';

export * from './MobileId';
export * from './types';
export * from './errors';
export * from './utils';
export * from './validator';
export * from './constants';

/**
 * Factory function for backward compatibility
 */
export default function createMobileId(options?: MobileIdOptions): MobileId {
    return new MobileId(options);
}

// For CommonJS compatibility
module.exports = createMobileId;
Object.assign(module.exports, { MobileId, default: createMobileId });
