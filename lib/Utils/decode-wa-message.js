import { Boom } from '@hapi/boom';
import { proto } from '../../WAProto/index.js';
import { areJidsSameUser, isJidBroadcast, isJidGroup, isJidMetaIa, isJidNewsletter, isJidStatusBroadcast, isJidUser, isLidUser, jidDecode, jidEncode } from '../WABinary/index.js';
import { unpadRandomMax16 } from './generics.js';
import { decryptGroupSignalProto, decryptSignalProto, processSenderKeyMessage } from './signal.js';
export const NO_MESSAGE_FOUND_ERROR_TEXT = "Message absent from node";
export const MISSING_KEYS_ERROR_TEXT = 'Key used already or never filled';
export const NACK_REASONS = {
    ParsingError: 487,
    UnrecognizedStanza: 488,
    UnrecognizedStanzaClass: 489,
    UnrecognizedStanzaType: 490,
    InvalidProtobuf: 491,
    InvalidHostedCompanionStanza: 493,
    MissingMessageSecret: 495,
    SignalErrorOldCounter: 496,
    MessageDeletedOnPeer: 499,
    UnhandledError: 500,
    UnsupportedAdminRevoke: 550,
    UnsupportedLIDGroup: 551,
    DBOperationFailed: 552
};
export const decodeMessageStanza = (stanza, auth) => {
    let msgType;
    let chatId;
    let author;
    const meLidUser = jidDecode(auth.creds.me.lid)?.user;
    const senderPn = stanza.attrs.sender_lid
        ? stanza.attrs.from
        : stanza.attrs.sender_pn;
    const senderLid = stanza.attrs.sender_pn
        ? stanza.attrs.from
        : stanza.attrs.sender_lid;
    const participantPn = isJidUser(stanza.attrs.participant)
        ? stanza.attrs.participant
        : stanza.attrs.participant_pn;
    const participantLid = isLidUser(stanza.attrs.participant)
        ? stanza.attrs.participant
        : stanza.attrs.participant_lid;
    const isGroup = isJidGroup(stanza.attrs.from);
    const fromLidUser = jidDecode(senderLid)?.user;
    const fromDevice = jidDecode(stanza.attrs.from)?.device;
    const participantLidUser = jidDecode(participantLid)?.user;
    const participantDevice = jidDecode(stanza.attrs.participant)?.device;
    const participantFullLid = participantLidUser
        ? jidEncode(participantLidUser, "lid", participantDevice)
        : undefined;
    const fromFullLid = !isGroup && fromLidUser
        ? jidEncode(fromLidUser, "lid", fromDevice)
        : undefined;
    const msgId = stanza.attrs.id;
    const from = String(fromFullLid || stanza.attrs.from);
    const participant = participantFullLid || stanza.attrs.participant;
    const recipient = stanza.attrs.recipient;
    const recipientLid = stanza.attrs.peer_recipient_lid;
    const isMe = (jid) => areJidsSameUser(jid, auth.creds.me.id);
    const isMeLid = (jid) => areJidsSameUser(jid, auth.creds.me.lid);
    if (isJidUser(from) || isLidUser(from)) {
        if (recipient && !isJidMetaIa(recipient)) {
            if (!isMe(from) && !isMeLid(from)) {
                throw new Boom("recipient present, but msg not from me", {
                    data: stanza
                });
            }
            chatId = recipient;
        }
        else {
            chatId = from;
        }
        msgType = "chat";
        author = isMe(from) ? jidEncode(meLidUser, "lid", fromDevice) : from;
    }
    else if (isJidGroup(from)) {
        if (!participant) {
            throw new Boom("No participant in group message");
        }
        msgType = "group";
        author = participant;
        chatId = from;
    }
    else if (isJidBroadcast(from)) {
        if (!participant) {
            throw new Boom("No participant in group message");
        }
        const isParticipantMe = isMe(participant);
        if (isJidStatusBroadcast(from)) {
            msgType = isParticipantMe ? "direct_peer_status" : "other_status";
        }
        else {
            msgType = isParticipantMe ? "peer_broadcast" : "other_broadcast";
        }
        chatId = from;
        author = participant;
    }
    else if (isJidNewsletter(from)) {
        msgType = "newsletter";
        chatId = from;
        author = from;
    }
    else {
        throw new Boom("Unknown message type", { data: stanza });
    }
    const sender = msgType === "chat" ? author : chatId;
    const fromMe = (isLidUser(from) || isLidUser(participant) ? isMeLid : isMe)(
    // @ts-ignore
    stanza.attrs.participant || stanza.attrs.from);
    const pushname = stanza.attrs.notify;
    const key = {
        remoteJid: chatId,
        fromMe,
        id: msgId,
        senderLid,
        senderPn,
        participant,
        participantPn,
        participantLid,
        recipientLid
    };
    const fullMessage = {
        key,
        category: stanza.attrs.category,
        // @ts-ignore
        messageTimestamp: +stanza.attrs.t,
        pushName: pushname
    };
    if (key.fromMe) {
        fullMessage.status = proto.WebMessageInfo.Status.SERVER_ACK;
    }
    return {
        fullMessage,
        category: stanza.attrs.category,
        author,
        decryptionTask: (async () => {
            let decryptables = 0;
            if (Array.isArray(stanza.content)) {
                for (const { tag, attrs, content } of stanza.content) {
                    if (tag === "unavailable" && attrs.type === "view_once") {
                        fullMessage.key.isViewOnce = true;
                    }
                    if (tag === "verified_name" && content instanceof Uint8Array) {
                        const cert = proto.VerifiedNameCertificate.decode(content);
                        const details = proto.VerifiedNameCertificate.Details.decode(cert.details);
                        fullMessage.verifiedBizName = details.verifiedName;
                    }
                    if (attrs.count && tag === "enc") {
                        fullMessage.retryCount = Number(attrs.count);
                    }
                    if (tag !== "enc" && tag !== "plaintext") {
                        continue;
                    }
                    if (!(content instanceof Uint8Array)) {
                        continue;
                    }
                    decryptables += 1;
                    let msgBuffer;
                    try {
                        const e2eType = tag === "plaintext" ? "plaintext" : attrs.type;
                        switch (e2eType) {
                            case "skmsg":
                                msgBuffer = await decryptGroupSignalProto(sender, author, content, auth);
                                break;
                            case "pkmsg":
                            case "msg":
                                const user = isJidUser(sender) ? sender : author;
                                msgBuffer = await decryptSignalProto(user, e2eType, content, auth);
                                break;
                            case "msmsg":
                                return; // ignore meta IA messages
                            case "plaintext":
                                msgBuffer = content;
                                break;
                            default:
                                throw new Error(`Unknown e2e type: ${e2eType}`);
                        }
                        let msg = proto.Message.decode(e2eType !== "plaintext" ? unpadRandomMax16(msgBuffer) : msgBuffer);
                        msg = msg.deviceSentMessage?.message || msg;
                        if (msg.senderKeyDistributionMessage) {
                            await processSenderKeyMessage(author, msg.senderKeyDistributionMessage, auth);
                        }
                        if (fullMessage.message) {
                            Object.assign(fullMessage.message, msg);
                        }
                        else {
                            fullMessage.message = msg;
                        }
                    }
                    catch (error) {
                        fullMessage.messageStubType =
                            proto.WebMessageInfo.StubType.CIPHERTEXT;
                        fullMessage.messageStubParameters = [error.message];
                    }
                }
            }
            // if nothing was found to decrypt
            if (!decryptables && !fullMessage.key?.isViewOnce) {
                fullMessage.messageStubType = proto.WebMessageInfo.StubType.CIPHERTEXT;
                fullMessage.messageStubParameters = [NO_MESSAGE_FOUND_ERROR_TEXT];
            }
        })()
    };
};
//# sourceMappingURL=decode-wa-message.js.map