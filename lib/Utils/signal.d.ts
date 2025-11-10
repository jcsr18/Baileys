import type { SignalAuthState, SignalRepository } from '../Types/index.js';
import type { AuthenticationCreds, AuthenticationState, KeyPair, SignalIdentity, SignalKeyStore, SignedKeyPair } from '../Types/Auth.js';
import { type BinaryNode, type JidWithDevice } from '../WABinary/index.js';
import type { USyncQueryResultList } from '../WAUSync/index.js';
import * as libsignal from "libsignal";
import { SenderKeyRecord } from '../Signal/Group/index.js';
export declare const createSignalIdentity: (wid: string, accountSignatureKey: Uint8Array) => SignalIdentity;
export declare const getPreKeys: ({ get }: SignalKeyStore, min: number, limit: number) => Promise<{
    [id: string]: KeyPair;
}>;
export declare const generateOrGetPreKeys: (creds: AuthenticationCreds, range: number) => {
    newPreKeys: {
        [id: number]: KeyPair;
    };
    lastPreKeyId: number;
    preKeysRange: readonly [number, number];
};
export declare const xmppSignedPreKey: (key: SignedKeyPair) => BinaryNode;
export declare const xmppPreKey: (pair: KeyPair, id: number) => BinaryNode;
export declare const parseAndInjectE2ESessions: (node: BinaryNode, repository: SignalRepository) => Promise<void>;
export declare const extractDeviceJids: (result: USyncQueryResultList[], myJid: string, excludeZeroDevices: boolean) => JidWithDevice[];
/**
 * get the next N keys for upload or processing
 * @param count number of pre-keys to get or generate
 */
export declare const getNextPreKeys: ({ creds, keys }: AuthenticationState, count: number) => Promise<{
    update: Partial<AuthenticationCreds>;
    preKeys: {
        [id: string]: KeyPair;
    };
}>;
export declare const getNextPreKeysNode: (state: AuthenticationState, count: number) => Promise<{
    update: Partial<AuthenticationCreds>;
    node: BinaryNode;
}>;
export declare const jidToSignalProtocolAddress: (jid: string) => libsignal.ProtocolAddress;
export declare const signalStorage: ({ creds, keys }: SignalAuthState) => {
    loadSession: (id: string) => Promise<libsignal.SessionRecord | undefined>;
    storeSession: (id: any, session: any) => Promise<void>;
    isTrustedIdentity: () => boolean;
    loadPreKey: (id: number | string) => Promise<{
        privKey: Buffer<Uint8Array<ArrayBufferLike>>;
        pubKey: Buffer<Uint8Array<ArrayBufferLike>>;
    } | undefined>;
    removePreKey: (id: number) => void | Promise<void>;
    loadSignedPreKey: () => {
        privKey: Buffer<Uint8Array<ArrayBufferLike>>;
        pubKey: Buffer<Uint8Array<ArrayBufferLike>>;
    };
    loadSenderKey: (keyId: string) => Promise<SenderKeyRecord | undefined>;
    storeSenderKey: (keyId: any, key: any) => Promise<void>;
    getOurRegistrationId: () => number;
    getOurIdentity: () => {
        privKey: Buffer<Uint8Array<ArrayBufferLike>>;
        pubKey: Uint8Array<ArrayBufferLike> | Buffer<ArrayBufferLike>;
    };
};
export declare const encryptSignalProto: (user: string, buffer: Buffer, auth: SignalAuthState) => Promise<{
    type: string;
    ciphertext: Buffer<ArrayBuffer>;
}>;
//# sourceMappingURL=signal.d.ts.map