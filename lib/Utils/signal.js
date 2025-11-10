import { KEY_BUNDLE_TYPE } from '../Defaults/index.js';
import { assertNodeErrorFree, getBinaryNodeChild, getBinaryNodeChildBuffer, getBinaryNodeChildren, getBinaryNodeChildUInt, jidDecode, S_WHATSAPP_NET } from '../WABinary/index.js';
import { Curve, generateSignalPubKey } from './crypto.js';
import { encodeBigEndian } from './generics.js';
/* @ts-ignore */
import * as libsignal from '@whiskeysockets/libsignal';
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage, SenderKeyName, SenderKeyRecord } from '../Signal/Group/index.js';
import { proto } from '../../WAProto';
function chunk(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}
export const createSignalIdentity = (wid, accountSignatureKey) => {
    return {
        identifier: { name: wid, deviceId: 0 },
        identifierKey: generateSignalPubKey(accountSignatureKey)
    };
};
export const getPreKeys = async ({ get }, min, limit) => {
    const idList = [];
    for (let id = min; id < limit; id++) {
        idList.push(id.toString());
    }
    return get('pre-key', idList);
};
export const generateOrGetPreKeys = (creds, range) => {
    const avaliable = creds.nextPreKeyId - creds.firstUnuploadedPreKeyId;
    const remaining = range - avaliable;
    const lastPreKeyId = creds.nextPreKeyId + remaining - 1;
    const newPreKeys = {};
    if (remaining > 0) {
        for (let i = creds.nextPreKeyId; i <= lastPreKeyId; i++) {
            newPreKeys[i] = Curve.generateKeyPair();
        }
    }
    return {
        newPreKeys,
        lastPreKeyId,
        preKeysRange: [creds.firstUnuploadedPreKeyId, range]
    };
};
export const xmppSignedPreKey = (key) => ({
    tag: 'skey',
    attrs: {},
    content: [
        { tag: 'id', attrs: {}, content: encodeBigEndian(key.keyId, 3) },
        { tag: 'value', attrs: {}, content: key.keyPair.public },
        { tag: 'signature', attrs: {}, content: key.signature }
    ]
});
export const xmppPreKey = (pair, id) => ({
    tag: 'key',
    attrs: {},
    content: [
        { tag: 'id', attrs: {}, content: encodeBigEndian(id, 3) },
        { tag: 'value', attrs: {}, content: pair.public }
    ]
});
export const parseAndInjectE2ESessions = async (node, repository) => {
    const extractKey = (key) => key
        ? {
            keyId: getBinaryNodeChildUInt(key, 'id', 3),
            publicKey: generateSignalPubKey(getBinaryNodeChildBuffer(key, 'value')),
            signature: getBinaryNodeChildBuffer(key, 'signature')
        }
        : undefined;
    const nodes = getBinaryNodeChildren(getBinaryNodeChild(node, 'list'), 'user');
    for (const node of nodes) {
        assertNodeErrorFree(node);
    }
    // Most of the work in repository.injectE2ESession is CPU intensive, not IO
    // So Promise.all doesn't really help here,
    // but blocks even loop if we're using it inside keys.transaction, and it makes it "sync" actually
    // This way we chunk it in smaller parts and between those parts we can yield to the event loop
    // It's rare case when you need to E2E sessions for so many users, but it's possible
    const chunkSize = 100;
    const chunks = chunk(nodes, chunkSize);
    for (const nodesChunk of chunks) {
        await Promise.all(nodesChunk.map(async (node) => {
            const signedKey = getBinaryNodeChild(node, 'skey');
            const key = getBinaryNodeChild(node, 'key');
            const identity = getBinaryNodeChildBuffer(node, 'identity');
            const jid = node.attrs.jid;
            const registrationId = getBinaryNodeChildUInt(node, 'registration', 4);
            await repository.injectE2ESession({
                jid,
                session: {
                    registrationId: registrationId,
                    identityKey: generateSignalPubKey(identity),
                    signedPreKey: extractKey(signedKey),
                    preKey: extractKey(key)
                }
            });
        }));
    }
};
export const extractDeviceJids = (result, myJid, excludeZeroDevices) => {
    const { user: myUser, device: myDevice } = jidDecode(myJid);
    const extracted = [];
    for (const node of result.content) {
        const list = getBinaryNodeChild(node, "list")?.content;
        if (list && Array.isArray(list)) {
            for (const item of list) {
                const { user } = jidDecode(item.attrs.jid);
                const devicesNode = getBinaryNodeChild(item, "devices");
                const lidNode = getBinaryNodeChild(item, "lid");
                const lid = jidDecode(lidNode?.attrs?.val)?.user;
                const deviceListNode = getBinaryNodeChild(devicesNode, "device-list");
                if (Array.isArray(deviceListNode?.content)) {
                    for (const { tag, attrs } of deviceListNode.content) {
                        if (attrs && attrs.id) {
                            const device = +attrs.id;
                            if (tag === "device" && // ensure the "device" tag
                                (!excludeZeroDevices || device !== 0) && // if zero devices are not-excluded, or device is non zero
                                (myUser !== user || myDevice !== device) && // either different user or if me user, not this device
                                (device === 0 || !!attrs["key-index"]) // ensure that "key-index" is specified for "non-zero" devices, produces a bad req otherwise
                            ) {
                                extracted.push({ user, device });
                                extracted.push({
                                    user: lid || user,
                                    device
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    return extracted;
};
/**
 * get the next N keys for upload or processing
 * @param count number of pre-keys to get or generate
 */
export const getNextPreKeys = async ({ creds, keys }, count) => {
    const { newPreKeys, lastPreKeyId, preKeysRange } = generateOrGetPreKeys(creds, count);
    const update = {
        nextPreKeyId: Math.max(lastPreKeyId + 1, creds.nextPreKeyId),
        firstUnuploadedPreKeyId: Math.max(creds.firstUnuploadedPreKeyId, lastPreKeyId + 1)
    };
    await keys.set({ 'pre-key': newPreKeys });
    const preKeys = await getPreKeys(keys, preKeysRange[0], preKeysRange[0] + preKeysRange[1]);
    return { update, preKeys };
};
export const getNextPreKeysNode = async (state, count) => {
    const { creds } = state;
    const { update, preKeys } = await getNextPreKeys(state, count);
    const node = {
        tag: 'iq',
        attrs: {
            xmlns: 'encrypt',
            type: 'set',
            to: S_WHATSAPP_NET
        },
        content: [
            { tag: 'registration', attrs: {}, content: encodeBigEndian(creds.registrationId) },
            { tag: 'type', attrs: {}, content: KEY_BUNDLE_TYPE },
            { tag: 'identity', attrs: {}, content: creds.signedIdentityKey.public },
            { tag: 'list', attrs: {}, content: Object.keys(preKeys).map(k => xmppPreKey(preKeys[+k], +k)) },
            xmppSignedPreKey(creds.signedPreKey)
        ]
    };
    return { update, node };
};
const jidToSignalAddress = (jid) => jid.split("@")[0];
export const jidToSignalProtocolAddress = (jid) => {
    return new libsignal.ProtocolAddress(jidToSignalAddress(jid), 0);
};
export const signalStorage = ({ creds, keys }) => ({
    loadSession: async (id) => {
        const { [id]: sess } = await keys.get("session", [id]);
        if (sess) {
            return libsignal.SessionRecord.deserialize(sess);
        }
    },
    storeSession: async (id, session) => {
        await keys.set({ session: { [id]: session.serialize() } });
    },
    isTrustedIdentity: () => {
        return true;
    },
    loadPreKey: async (id) => {
        const keyId = id.toString();
        const { [keyId]: key } = await keys.get("pre-key", [keyId]);
        if (key) {
            return {
                privKey: Buffer.from(key.private),
                pubKey: Buffer.from(key.public)
            };
        }
    },
    removePreKey: (id) => keys.set({ "pre-key": { [id]: null } }),
    loadSignedPreKey: () => {
        const key = creds.signedPreKey;
        return {
            privKey: Buffer.from(key.keyPair.private),
            pubKey: Buffer.from(key.keyPair.public)
        };
    },
    loadSenderKey: async (keyId) => {
        const { [keyId]: key } = await keys.get("sender-key", [keyId]);
        if (key) {
            return new SenderKeyRecord(key);
        }
    },
    storeSenderKey: async (keyId, key) => {
        await keys.set({ "sender-key": { [keyId]: key.serialize() } });
    },
    getOurRegistrationId: () => creds.registrationId,
    getOurIdentity: () => {
        const { signedIdentityKey } = creds;
        return {
            privKey: Buffer.from(signedIdentityKey.private),
            pubKey: generateSignalPubKey(signedIdentityKey.public)
        };
    }
});
export const encryptSignalProto = async (user, buffer, auth) => {
    const addr = jidToSignalProtocolAddress(user);
    const cipher = new libsignal.SessionCipher(signalStorage(auth), addr);
    const { type: sigType, body } = await cipher.encrypt(buffer);
    const type = sigType === 3 ? "pkmsg" : "msg";
    return { type, ciphertext: Buffer.from(body, "binary") };
};
export const jidToSignalSenderKeyName = (group, user) => {
    return new SenderKeyName(group, jidToSignalProtocolAddress(user));
};
export const decryptGroupSignalProto = (group, user, msg, auth) => {
    const senderName = jidToSignalSenderKeyName(group, user);
    // @ts-ignore
    const cipher = new GroupCipher(signalStorage(auth), senderName);
    return cipher.decrypt(Buffer.from(msg));
};
export const decryptSignalProto = async (user, type, msg, auth) => {
    const addr = jidToSignalProtocolAddress(user);
    const session = new libsignal.SessionCipher(signalStorage(auth), addr);
    let result;
    switch (type) {
        case "pkmsg":
            result = await session.decryptPreKeyWhisperMessage(msg);
            break;
        case "msg":
            result = await session.decryptWhisperMessage(msg);
            break;
    }
    return result;
};
export const processSenderKeyMessage = async (authorJid, item, auth) => {
    // @ts-ignore
    const builder = new GroupSessionBuilder(signalStorage(auth));
    const senderName = jidToSignalSenderKeyName(item.groupId, authorJid);
    const senderMsg = new SenderKeyDistributionMessage(null, null, null, null, item.axolotlSenderKeyDistributionMessage);
    const { [senderName.toString()]: senderKey } = await auth.keys.get("sender-key", [
        senderName.toString()
    ]);
    if (!senderKey) {
        const record = new SenderKeyRecord();
        await auth.keys.set({ "sender-key": { [senderName.toString()]: record } });
    }
    await builder.process(senderName, senderMsg);
};
//# sourceMappingURL=signal.js.map