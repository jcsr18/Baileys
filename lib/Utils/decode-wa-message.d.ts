import type { AuthenticationState, WAMessage } from '../Types/index.js';
import { type BinaryNode } from '../WABinary/index.js';
export declare const NO_MESSAGE_FOUND_ERROR_TEXT = "Message absent from node";
export declare const MISSING_KEYS_ERROR_TEXT = "Key used already or never filled";
export declare const NACK_REASONS: {
    ParsingError: number;
    UnrecognizedStanza: number;
    UnrecognizedStanzaClass: number;
    UnrecognizedStanzaType: number;
    InvalidProtobuf: number;
    InvalidHostedCompanionStanza: number;
    MissingMessageSecret: number;
    SignalErrorOldCounter: number;
    MessageDeletedOnPeer: number;
    UnhandledError: number;
    UnsupportedAdminRevoke: number;
    UnsupportedLIDGroup: number;
    DBOperationFailed: number;
};
export declare const decodeMessageStanza: (stanza: BinaryNode, auth: AuthenticationState) => {
    fullMessage: WAMessage;
    category: string | undefined;
    author: string;
    decryptionTask: Promise<void>;
};
//# sourceMappingURL=decode-wa-message.d.ts.map