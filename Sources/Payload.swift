//
//  Payload.swift
//  S3SignerAWS
//
//  Created by Justin on 10/10/16.
//
//

import CryptoSwift

public enum Payload {
case bytes([UInt8])
    case none
    case unsigned

    func hashed() throws -> String {
        switch self {
        case .bytes(let bytes):
            return bytes.sha256().toHexString()
        case .none:
            return "".sha256()
        case .unsigned:
            return "UNSIGNED-PAYLOAD"

        }
    }

    var isBytes: Bool {
        switch self {
        case .bytes( _), .none:
            return true
        default:
            return false
        }
    }

    var isUnsigned: Bool {
        switch self {
        case .unsigned:
            return true
        default:
            return false
        }
    }

    var bytes: [UInt8] {
        switch self {
        case .bytes(let bytes):
            return bytes
        default:
            return []
        }
    }
}
