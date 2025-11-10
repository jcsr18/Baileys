import { KEY_BUNDLE_TYPE } from '../Defaults'
import type { SignalAuthState, SignalRepository } from '../Types'
import type {
	AuthenticationCreds,
	AuthenticationState,
	KeyPair,
	SignalIdentity,
	SignalKeyStore,
	SignedKeyPair
} from '../Types/Auth'
import {
	assertNodeErrorFree,
	type BinaryNode,
	getBinaryNodeChild,
	getBinaryNodeChildBuffer,
	getBinaryNodeChildren,
	getBinaryNodeChildUInt,
	jidDecode,
	type JidWithDevice,
	S_WHATSAPP_NET
} from '../WABinary'
import type { DeviceListData, ParsedDeviceInfo, USyncQueryResultList } from '../WAUSync'
import { Curve, generateSignalPubKey } from './crypto'
import { encodeBigEndian } from './generics'
/* @ts-ignore */
import * as libsignal from '@whiskeysockets/libsignal'
import {
	GroupCipher,
	GroupSessionBuilder,
	SenderKeyDistributionMessage,
	SenderKeyName,
	SenderKeyRecord
} from '../Signal/Group'
import type { SenderKeyStore } from '../Signal/Group/group_cipher.ts'
import { proto } from '../../WAProto/index.js'

function chunk<T>(array: T[], size: number): T[][] {
	const chunks: T[][] = []
	for (let i = 0; i < array.length; i += size) {
		chunks.push(array.slice(i, i + size))
	}

	return chunks
}

export const createSignalIdentity = (wid: string, accountSignatureKey: Uint8Array): SignalIdentity => {
	return {
		identifier: { name: wid, deviceId: 0 },
		identifierKey: generateSignalPubKey(accountSignatureKey)
	}
}

export const getPreKeys = async ({ get }: SignalKeyStore, min: number, limit: number) => {
	const idList: string[] = []
	for (let id = min; id < limit; id++) {
		idList.push(id.toString())
	}

	return get('pre-key', idList)
}

export const generateOrGetPreKeys = (creds: AuthenticationCreds, range: number) => {
	const avaliable = creds.nextPreKeyId - creds.firstUnuploadedPreKeyId
	const remaining = range - avaliable
	const lastPreKeyId = creds.nextPreKeyId + remaining - 1
	const newPreKeys: { [id: number]: KeyPair } = {}
	if (remaining > 0) {
		for (let i = creds.nextPreKeyId; i <= lastPreKeyId; i++) {
			newPreKeys[i] = Curve.generateKeyPair()
		}
	}

	return {
		newPreKeys,
		lastPreKeyId,
		preKeysRange: [creds.firstUnuploadedPreKeyId, range] as const
	}
}

export const xmppSignedPreKey = (key: SignedKeyPair): BinaryNode => ({
	tag: 'skey',
	attrs: {},
	content: [
		{ tag: 'id', attrs: {}, content: encodeBigEndian(key.keyId, 3) },
		{ tag: 'value', attrs: {}, content: key.keyPair.public },
		{ tag: 'signature', attrs: {}, content: key.signature }
	]
})

export const xmppPreKey = (pair: KeyPair, id: number): BinaryNode => ({
	tag: 'key',
	attrs: {},
	content: [
		{ tag: 'id', attrs: {}, content: encodeBigEndian(id, 3) },
		{ tag: 'value', attrs: {}, content: pair.public }
	]
})

export const parseAndInjectE2ESessions = async (node: BinaryNode, repository: SignalRepository) => {
	const extractKey = (key: BinaryNode) =>
		key
			? {
					keyId: getBinaryNodeChildUInt(key, 'id', 3)!,
					publicKey: generateSignalPubKey(getBinaryNodeChildBuffer(key, 'value')!),
					signature: getBinaryNodeChildBuffer(key, 'signature')!
				}
			: undefined
	const nodes = getBinaryNodeChildren(getBinaryNodeChild(node, 'list'), 'user')
	for (const node of nodes) {
		assertNodeErrorFree(node)
	}

	// Most of the work in repository.injectE2ESession is CPU intensive, not IO
	// So Promise.all doesn't really help here,
	// but blocks even loop if we're using it inside keys.transaction, and it makes it "sync" actually
	// This way we chunk it in smaller parts and between those parts we can yield to the event loop
	// It's rare case when you need to E2E sessions for so many users, but it's possible
	const chunkSize = 100
	const chunks = chunk(nodes, chunkSize)
	for (const nodesChunk of chunks) {
		await Promise.all(
			nodesChunk.map(async (node: BinaryNode) => {
				const signedKey = getBinaryNodeChild(node, 'skey')!
				const key = getBinaryNodeChild(node, 'key')!
				const identity = getBinaryNodeChildBuffer(node, 'identity')!
				const jid = node.attrs.jid!
				const registrationId = getBinaryNodeChildUInt(node, 'registration', 4)

				await repository.injectE2ESession({
					jid,
					session: {
						registrationId: registrationId!,
						identityKey: generateSignalPubKey(identity),
						signedPreKey: extractKey(signedKey)!,
						preKey: extractKey(key)!
					}
				})
			})
		)
	}
}

export const extractDeviceJids = (
	result: BinaryNode,
	myJid: string,
	excludeZeroDevices: boolean
) => {
	const { user: myUser, device: myDevice } = jidDecode(myJid)!;
	const extracted: JidWithDevice[] = [];
	for (const node of result.content as BinaryNode[]) {
		const list = getBinaryNodeChild(node, "list")?.content;
		if (list && Array.isArray(list)) {
			for (const item of list) {
				const { user } = jidDecode(item.attrs.jid)!;
				const devicesNode = getBinaryNodeChild(item, "devices");
				const lidNode = getBinaryNodeChild(item, "lid");
				const lid = jidDecode(lidNode?.attrs?.val)?.user;
				const deviceListNode = getBinaryNodeChild(devicesNode, "device-list");
				if (Array.isArray(deviceListNode?.content)) {
					for (const { tag, attrs } of deviceListNode!.content) {
						if (attrs && attrs.id) {
							const device = +attrs.id;

							if (
								tag === "device" && // ensure the "device" tag
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
}

/**
 * get the next N keys for upload or processing
 * @param count number of pre-keys to get or generate
 */
export const getNextPreKeys = async ({ creds, keys }: AuthenticationState, count: number) => {
	const { newPreKeys, lastPreKeyId, preKeysRange } = generateOrGetPreKeys(creds, count)

	const update: Partial<AuthenticationCreds> = {
		nextPreKeyId: Math.max(lastPreKeyId + 1, creds.nextPreKeyId),
		firstUnuploadedPreKeyId: Math.max(creds.firstUnuploadedPreKeyId, lastPreKeyId + 1)
	}

	await keys.set({ 'pre-key': newPreKeys })

	const preKeys = await getPreKeys(keys, preKeysRange[0], preKeysRange[0] + preKeysRange[1])

	return { update, preKeys }
}

export const getNextPreKeysNode = async (state: AuthenticationState, count: number) => {
	const { creds } = state
	const { update, preKeys } = await getNextPreKeys(state, count)

	const node: BinaryNode = {
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
			{ tag: 'list', attrs: {}, content: Object.keys(preKeys).map(k => xmppPreKey(preKeys[+k]!, +k)) },
			xmppSignedPreKey(creds.signedPreKey)
		]
	}

	return { update, node }
}

const jidToSignalAddress = (jid: string) => jid.split("@")[0];

export const jidToSignalProtocolAddress = (jid: string) => {
	return new libsignal.ProtocolAddress(jidToSignalAddress(jid) as string, 0);
};

export const signalStorage = ({ creds, keys }: SignalAuthState) => ({
	loadSession: async (id: string) => {
		const { [id]: sess } = await keys.get("session", [id]);
		if (sess) {
			return libsignal.SessionRecord.deserialize(sess);
		}
	},
	storeSession: async (id: any, session: any) => {
		await keys.set({ session: { [id]: session.serialize() } });
	},
	isTrustedIdentity: () => {
		return true;
	},
	loadPreKey: async (id: number | string) => {
		const keyId = id.toString();
		const { [keyId]: key } = await keys.get("pre-key", [keyId]);
		if (key) {
			return {
				privKey: Buffer.from(key.private),
				pubKey: Buffer.from(key.public)
			};
		}
	},
	removePreKey: (id: number) => keys.set({ "pre-key": { [id]: null } }),
	loadSignedPreKey: () => {
		const key = creds.signedPreKey;
		return {
			privKey: Buffer.from(key.keyPair.private),
			pubKey: Buffer.from(key.keyPair.public)
		};
	},
	loadSenderKey: async (keyId: string) => {
		const { [keyId]: key } = await keys.get("sender-key", [keyId]);
		if (key) {
			return new SenderKeyRecord(key as any);
		}
	},
	storeSenderKey: async (keyId: any, key: any) => {
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

export const encryptSignalProto = async (
	user: string,
	buffer: Buffer,
	auth: SignalAuthState
) => {
		const addr = jidToSignalProtocolAddress(user);
	const cipher = new libsignal.SessionCipher(signalStorage(auth) as any, addr);

	const { type: sigType, body } = await cipher.encrypt(buffer);
	const type = sigType === 3 ? "pkmsg" : "msg";
	return { type, ciphertext: Buffer.from(body, "binary") };
};

export const jidToSignalSenderKeyName = (
	group: string,
	user: string
): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user));
};

export const decryptGroupSignalProto = (
	group: string,
	user: string,
	msg: Buffer | Uint8Array,
	auth: SignalAuthState
) => {
	const senderName = jidToSignalSenderKeyName(group, user);
	// @ts-ignore
	const cipher = new GroupCipher(signalStorage(auth), senderName);

	return cipher.decrypt(Buffer.from(msg));
};

export const decryptSignalProto = async (
	user: string,
	type: "pkmsg" | "msg",
	msg: Buffer | Uint8Array,
	auth: SignalAuthState
) => {
	const addr = jidToSignalProtocolAddress(user);
	const session = new libsignal.SessionCipher(signalStorage(auth), addr);
	let result: Buffer;
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

export const processSenderKeyMessage = async (
	authorJid: string,
	item: proto.Message.ISenderKeyDistributionMessage,
	auth: SignalAuthState
) => {
	// @ts-ignore
	const builder = new GroupSessionBuilder(signalStorage(auth));
	const senderName = jidToSignalSenderKeyName(item.groupId!, authorJid);

	const senderMsg = new SenderKeyDistributionMessage(
		null,
		null,
		null,
		null,
		item.axolotlSenderKeyDistributionMessage
	);
	const { [senderName.toString()]: senderKey } = await auth.keys.get("sender-key", [
		senderName.toString()
	]);
	if (!senderKey) {
		const record = new SenderKeyRecord() as any;
		await auth.keys.set({ "sender-key": { [senderName.toString()]: record} });
	}

	await builder.process(senderName, senderMsg);
};
