public enum PackBridgeError {
    case InvalidKey(RustString)
    case UntrustedIdentity(RustString)
    case DuplicateMessage
    case InvalidMessage(RustString)
    case InvalidMac
    case NoSession(RustString)
    case SessionNotFound
    case InvalidSignature
    case StaleKeyExchange
    case TooManySkippedMessages
    case ExpiredCertificate
    case InvalidCertificate
    case Storage(RustString)
    case Crypto(RustString)
}
extension PackBridgeError {
    func intoFfiRepr() -> __swift_bridge__$PackBridgeError {
        switch self {
            case PackBridgeError.InvalidKey(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$InvalidKey, payload: __swift_bridge__$PackBridgeErrorFields(InvalidKey: __swift_bridge__$PackBridgeError$FieldOfInvalidKey(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
            case PackBridgeError.UntrustedIdentity(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$UntrustedIdentity, payload: __swift_bridge__$PackBridgeErrorFields(UntrustedIdentity: __swift_bridge__$PackBridgeError$FieldOfUntrustedIdentity(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
            case PackBridgeError.DuplicateMessage:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$DuplicateMessage; return val }()
            case PackBridgeError.InvalidMessage(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$InvalidMessage, payload: __swift_bridge__$PackBridgeErrorFields(InvalidMessage: __swift_bridge__$PackBridgeError$FieldOfInvalidMessage(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
            case PackBridgeError.InvalidMac:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$InvalidMac; return val }()
            case PackBridgeError.NoSession(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$NoSession, payload: __swift_bridge__$PackBridgeErrorFields(NoSession: __swift_bridge__$PackBridgeError$FieldOfNoSession(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
            case PackBridgeError.SessionNotFound:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$SessionNotFound; return val }()
            case PackBridgeError.InvalidSignature:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$InvalidSignature; return val }()
            case PackBridgeError.StaleKeyExchange:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$StaleKeyExchange; return val }()
            case PackBridgeError.TooManySkippedMessages:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$TooManySkippedMessages; return val }()
            case PackBridgeError.ExpiredCertificate:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$ExpiredCertificate; return val }()
            case PackBridgeError.InvalidCertificate:
                return {var val = __swift_bridge__$PackBridgeError(); val.tag = __swift_bridge__$PackBridgeError$InvalidCertificate; return val }()
            case PackBridgeError.Storage(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$Storage, payload: __swift_bridge__$PackBridgeErrorFields(Storage: __swift_bridge__$PackBridgeError$FieldOfStorage(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
            case PackBridgeError.Crypto(let _0):
                return __swift_bridge__$PackBridgeError(tag: __swift_bridge__$PackBridgeError$Crypto, payload: __swift_bridge__$PackBridgeErrorFields(Crypto: __swift_bridge__$PackBridgeError$FieldOfCrypto(_0: { let rustString = _0.intoRustString(); rustString.isOwned = false; return rustString.ptr }())))
        }
    }
}
extension __swift_bridge__$PackBridgeError {
    func intoSwiftRepr() -> PackBridgeError {
        switch self.tag {
            case __swift_bridge__$PackBridgeError$InvalidKey:
                return PackBridgeError.InvalidKey(RustString(ptr: self.payload.InvalidKey._0))
            case __swift_bridge__$PackBridgeError$UntrustedIdentity:
                return PackBridgeError.UntrustedIdentity(RustString(ptr: self.payload.UntrustedIdentity._0))
            case __swift_bridge__$PackBridgeError$DuplicateMessage:
                return PackBridgeError.DuplicateMessage
            case __swift_bridge__$PackBridgeError$InvalidMessage:
                return PackBridgeError.InvalidMessage(RustString(ptr: self.payload.InvalidMessage._0))
            case __swift_bridge__$PackBridgeError$InvalidMac:
                return PackBridgeError.InvalidMac
            case __swift_bridge__$PackBridgeError$NoSession:
                return PackBridgeError.NoSession(RustString(ptr: self.payload.NoSession._0))
            case __swift_bridge__$PackBridgeError$SessionNotFound:
                return PackBridgeError.SessionNotFound
            case __swift_bridge__$PackBridgeError$InvalidSignature:
                return PackBridgeError.InvalidSignature
            case __swift_bridge__$PackBridgeError$StaleKeyExchange:
                return PackBridgeError.StaleKeyExchange
            case __swift_bridge__$PackBridgeError$TooManySkippedMessages:
                return PackBridgeError.TooManySkippedMessages
            case __swift_bridge__$PackBridgeError$ExpiredCertificate:
                return PackBridgeError.ExpiredCertificate
            case __swift_bridge__$PackBridgeError$InvalidCertificate:
                return PackBridgeError.InvalidCertificate
            case __swift_bridge__$PackBridgeError$Storage:
                return PackBridgeError.Storage(RustString(ptr: self.payload.Storage._0))
            case __swift_bridge__$PackBridgeError$Crypto:
                return PackBridgeError.Crypto(RustString(ptr: self.payload.Crypto._0))
            default:
                fatalError("Unreachable")
        }
    }
}
extension __swift_bridge__$Option$PackBridgeError {
    @inline(__always)
    func intoSwiftRepr() -> Optional<PackBridgeError> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }
    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<PackBridgeError>) -> __swift_bridge__$Option$PackBridgeError {
        if let v = val {
            return __swift_bridge__$Option$PackBridgeError(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$PackBridgeError(is_some: false, val: __swift_bridge__$PackBridgeError())
        }
    }
}
public struct SealedSenderDecryptResult {
    public var sender_uuid: RustString
    public var sender_device_id: UInt32
    public var plaintext: RustVec<UInt8>

    public init(sender_uuid: RustString,sender_device_id: UInt32,plaintext: RustVec<UInt8>) {
        self.sender_uuid = sender_uuid
        self.sender_device_id = sender_device_id
        self.plaintext = plaintext
    }

    @inline(__always)
    func intoFfiRepr() -> __swift_bridge__$SealedSenderDecryptResult {
        { let val = self; return __swift_bridge__$SealedSenderDecryptResult(sender_uuid: { let rustString = val.sender_uuid.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), sender_device_id: val.sender_device_id, plaintext: { let val = val.plaintext; val.isOwned = false; return val.ptr }()); }()
    }
}
extension __swift_bridge__$SealedSenderDecryptResult {
    @inline(__always)
    func intoSwiftRepr() -> SealedSenderDecryptResult {
        { let val = self; return SealedSenderDecryptResult(sender_uuid: RustString(ptr: val.sender_uuid), sender_device_id: val.sender_device_id, plaintext: RustVec(ptr: val.plaintext)); }()
    }
}
extension __swift_bridge__$Option$SealedSenderDecryptResult {
    @inline(__always)
    func intoSwiftRepr() -> Optional<SealedSenderDecryptResult> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }

    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<SealedSenderDecryptResult>) -> __swift_bridge__$Option$SealedSenderDecryptResult {
        if let v = val {
            return __swift_bridge__$Option$SealedSenderDecryptResult(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$SealedSenderDecryptResult(is_some: false, val: __swift_bridge__$SealedSenderDecryptResult())
        }
    }
}

public class PackSessionBridge: PackSessionBridgeRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PackSessionBridge$_free(ptr)
        }
    }
}
extension PackSessionBridge {
    class public func initiate<GenericToRustStr: ToRustStr>(_ our_name: GenericToRustStr, _ our_device_id: UInt32, _ identity_public: UnsafeBufferPointer<UInt8>, _ identity_private: UnsafeBufferPointer<UInt8>, _ registration_id: UInt32, _ remote_name: GenericToRustStr, _ remote_device_id: UInt32, _ bundle_identity_key: UnsafeBufferPointer<UInt8>, _ bundle_spk_id: UInt32, _ bundle_spk: UnsafeBufferPointer<UInt8>, _ bundle_spk_signature: UnsafeBufferPointer<UInt8>, _ bundle_spk_timestamp: UInt64, _ bundle_opk_id: Optional<UInt32>, _ bundle_opk: Optional<RustVec<UInt8>>, _ first_message: UnsafeBufferPointer<UInt8>) throws -> PackSessionBridge {
        return try remote_name.toRustStr({ remote_nameAsRustStr in
            return try our_name.toRustStr({ our_nameAsRustStr in
            try { let val = __swift_bridge__$PackSessionBridge$initiate(our_nameAsRustStr, our_device_id, identity_public.toFfiSlice(), identity_private.toFfiSlice(), registration_id, remote_nameAsRustStr, remote_device_id, bundle_identity_key.toFfiSlice(), bundle_spk_id, bundle_spk.toFfiSlice(), bundle_spk_signature.toFfiSlice(), bundle_spk_timestamp, bundle_opk_id.intoFfiRepr(), { if let val = bundle_opk { val.isOwned = false; return val.ptr } else { return nil } }(), first_message.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultOk: return PackSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
        })
    }

    class public func respond<GenericToRustStr: ToRustStr>(_ our_name: GenericToRustStr, _ our_device_id: UInt32, _ identity_public: UnsafeBufferPointer<UInt8>, _ identity_private: UnsafeBufferPointer<UInt8>, _ registration_id: UInt32, _ remote_name: GenericToRustStr, _ remote_device_id: UInt32, _ spk_id: UInt32, _ spk_public: UnsafeBufferPointer<UInt8>, _ spk_private: UnsafeBufferPointer<UInt8>, _ spk_signature: UnsafeBufferPointer<UInt8>, _ spk_timestamp: UInt64, _ opk_id: Optional<UInt32>, _ opk_public: Optional<RustVec<UInt8>>, _ opk_private: Optional<RustVec<UInt8>>, _ pre_key_message_bytes: UnsafeBufferPointer<UInt8>) throws -> PackSessionBridge {
        return try remote_name.toRustStr({ remote_nameAsRustStr in
            return try our_name.toRustStr({ our_nameAsRustStr in
            try { let val = __swift_bridge__$PackSessionBridge$respond(our_nameAsRustStr, our_device_id, identity_public.toFfiSlice(), identity_private.toFfiSlice(), registration_id, remote_nameAsRustStr, remote_device_id, spk_id, spk_public.toFfiSlice(), spk_private.toFfiSlice(), spk_signature.toFfiSlice(), spk_timestamp, opk_id.intoFfiRepr(), { if let val = opk_public { val.isOwned = false; return val.ptr } else { return nil } }(), { if let val = opk_private { val.isOwned = false; return val.ptr } else { return nil } }(), pre_key_message_bytes.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultOk: return PackSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
        })
    }

    class public func from_bytes(_ data: UnsafeBufferPointer<UInt8>) throws -> PackSessionBridge {
        try { let val = __swift_bridge__$PackSessionBridge$from_bytes(data.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultOk: return PackSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func from_bytes_encrypted(_ data: UnsafeBufferPointer<UInt8>, _ storage_key: UnsafeBufferPointer<UInt8>) throws -> PackSessionBridge {
        try { let val = __swift_bridge__$PackSessionBridge$from_bytes_encrypted(data.toFfiSlice(), storage_key.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultOk: return PackSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackSessionBridgeRefMut: PackSessionBridgeRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
extension PackSessionBridgeRefMut {
    public func encrypt(_ plaintext: UnsafeBufferPointer<UInt8>) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackSessionBridge$encrypt(ptr, plaintext.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    public func decrypt(_ message_bytes: UnsafeBufferPointer<UInt8>) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackSessionBridge$decrypt(ptr, message_bytes.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackSessionBridgeRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PackSessionBridgeRef {
    public func pre_key_message() -> Optional<RustVec<UInt8>> {
        { let val = __swift_bridge__$PackSessionBridge$pre_key_message(ptr); if val != nil { return RustVec(ptr: val!) } else { return nil } }()
    }

    public func first_plaintext() -> Optional<RustVec<UInt8>> {
        { let val = __swift_bridge__$PackSessionBridge$first_plaintext(ptr); if val != nil { return RustVec(ptr: val!) } else { return nil } }()
    }

    public func remote_identity_key() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$PackSessionBridge$remote_identity_key(ptr))
    }

    public func to_bytes() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$PackSessionBridge$to_bytes(ptr))
    }

    public func to_bytes_encrypted(_ storage_key: UnsafeBufferPointer<UInt8>) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackSessionBridge$to_bytes_encrypted(ptr, storage_key.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
extension PackSessionBridge: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PackSessionBridge$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PackSessionBridge$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PackSessionBridge) {
        __swift_bridge__$Vec_PackSessionBridge$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PackSessionBridge$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PackSessionBridge(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackSessionBridgeRef> {
        let pointer = __swift_bridge__$Vec_PackSessionBridge$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackSessionBridgeRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackSessionBridgeRefMut> {
        let pointer = __swift_bridge__$Vec_PackSessionBridge$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackSessionBridgeRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PackSessionBridgeRef> {
        UnsafePointer<PackSessionBridgeRef>(OpaquePointer(__swift_bridge__$Vec_PackSessionBridge$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PackSessionBridge$len(vecPtr)
    }
}


public class PackGroupSessionBridge: PackGroupSessionBridgeRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PackGroupSessionBridge$_free(ptr)
        }
    }
}
extension PackGroupSessionBridge {
    class public func create_sender<GenericToRustStr: ToRustStr>(_ distribution_id: GenericToRustStr) throws -> PackGroupSessionBridge {
        return try distribution_id.toRustStr({ distribution_idAsRustStr in
            try { let val = __swift_bridge__$PackGroupSessionBridge$create_sender(distribution_idAsRustStr); switch val.tag { case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultOk: return PackGroupSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
    }

    class public func from_bytes(_ data: UnsafeBufferPointer<UInt8>) throws -> PackGroupSessionBridge {
        try { let val = __swift_bridge__$PackGroupSessionBridge$from_bytes(data.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultOk: return PackGroupSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackGroupSessionBridgeRefMut: PackGroupSessionBridgeRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PackGroupSessionBridgeRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PackGroupSessionBridgeRef {
    public func distribution_message() -> Optional<RustVec<UInt8>> {
        { let val = __swift_bridge__$PackGroupSessionBridge$distribution_message(ptr); if val != nil { return RustVec(ptr: val!) } else { return nil } }()
    }

    public func to_bytes() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$PackGroupSessionBridge$to_bytes(ptr))
    }
}
extension PackGroupSessionBridge: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PackGroupSessionBridge$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PackGroupSessionBridge$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PackGroupSessionBridge) {
        __swift_bridge__$Vec_PackGroupSessionBridge$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PackGroupSessionBridge$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PackGroupSessionBridge(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackGroupSessionBridgeRef> {
        let pointer = __swift_bridge__$Vec_PackGroupSessionBridge$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackGroupSessionBridgeRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackGroupSessionBridgeRefMut> {
        let pointer = __swift_bridge__$Vec_PackGroupSessionBridge$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackGroupSessionBridgeRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PackGroupSessionBridgeRef> {
        UnsafePointer<PackGroupSessionBridgeRef>(OpaquePointer(__swift_bridge__$Vec_PackGroupSessionBridge$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PackGroupSessionBridge$len(vecPtr)
    }
}


public class PackSealedSenderBridge: PackSealedSenderBridgeRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PackSealedSenderBridge$_free(ptr)
        }
    }
}
extension PackSealedSenderBridge {
    class public func sealed_encrypt<GenericToRustStr: ToRustStr>(_ sender_identity_public: UnsafeBufferPointer<UInt8>, _ sender_identity_private: UnsafeBufferPointer<UInt8>, _ sender_uuid: GenericToRustStr, _ sender_device_id: UInt32, _ server_cert_key: UnsafeBufferPointer<UInt8>, _ server_cert_id: UInt32, _ cert_expiration: UInt64, _ cert_signature: UnsafeBufferPointer<UInt8>, _ recipient_identity: UnsafeBufferPointer<UInt8>, _ inner_message: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> RustVec<UInt8> {
        return try sender_uuid.toRustStr({ sender_uuidAsRustStr in
            try { let val = __swift_bridge__$PackSealedSenderBridge$sealed_encrypt(sender_identity_public.toFfiSlice(), sender_identity_private.toFfiSlice(), sender_uuidAsRustStr, sender_device_id, server_cert_key.toFfiSlice(), server_cert_id, cert_expiration, cert_signature.toFfiSlice(), recipient_identity.toFfiSlice(), inner_message.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
    }

    class public func sealed_decrypt(_ our_identity_public: UnsafeBufferPointer<UInt8>, _ our_identity_private: UnsafeBufferPointer<UInt8>, _ ciphertext: UnsafeBufferPointer<UInt8>, _ trust_root: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> SealedSenderDecryptResult {
        try { let val = __swift_bridge__$PackSealedSenderBridge$sealed_decrypt(our_identity_public.toFfiSlice(), our_identity_private.toFfiSlice(), ciphertext.toFfiSlice(), trust_root.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func sealed_encrypt_raw_cert(_ sender_identity_public: UnsafeBufferPointer<UInt8>, _ sender_identity_private: UnsafeBufferPointer<UInt8>, _ raw_cert_blob: UnsafeBufferPointer<UInt8>, _ recipient_identity: UnsafeBufferPointer<UInt8>, _ inner_message: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackSealedSenderBridge$sealed_encrypt_raw_cert(sender_identity_public.toFfiSlice(), sender_identity_private.toFfiSlice(), raw_cert_blob.toFfiSlice(), recipient_identity.toFfiSlice(), inner_message.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func sealed_decrypt_raw_cert(_ our_identity_public: UnsafeBufferPointer<UInt8>, _ our_identity_private: UnsafeBufferPointer<UInt8>, _ ciphertext: UnsafeBufferPointer<UInt8>, _ trust_root: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> SealedSenderDecryptResult {
        try { let val = __swift_bridge__$PackSealedSenderBridge$sealed_decrypt_raw_cert(our_identity_public.toFfiSlice(), our_identity_private.toFfiSlice(), ciphertext.toFfiSlice(), trust_root.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func distribute_sender_key<GenericToRustStr: ToRustStr>(_ session: PackSessionBridgeRefMut, _ sender_uuid: GenericToRustStr, _ sender_device_id: UInt32, _ server_cert_key: UnsafeBufferPointer<UInt8>, _ server_cert_id: UInt32, _ cert_expiration: UInt64, _ cert_signature: UnsafeBufferPointer<UInt8>, _ skdm_bytes: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> RustVec<UInt8> {
        return try sender_uuid.toRustStr({ sender_uuidAsRustStr in
            try { let val = __swift_bridge__$PackSealedSenderBridge$distribute_sender_key(session.ptr, sender_uuidAsRustStr, sender_device_id, server_cert_key.toFfiSlice(), server_cert_id, cert_expiration, cert_signature.toFfiSlice(), skdm_bytes.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
    }

    class public func receive_sender_key<GenericToRustStr: ToRustStr>(_ session: PackSessionBridgeRefMut, _ ciphertext: UnsafeBufferPointer<UInt8>, _ trust_root: UnsafeBufferPointer<UInt8>, _ current_time: UInt64, _ distribution_id: GenericToRustStr) throws -> PackGroupSessionBridge {
        return try distribution_id.toRustStr({ distribution_idAsRustStr in
            try { let val = __swift_bridge__$PackSealedSenderBridge$receive_sender_key(session.ptr, ciphertext.toFfiSlice(), trust_root.toFfiSlice(), current_time, distribution_idAsRustStr); switch val.tag { case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultOk: return PackGroupSessionBridge(ptr: val.payload.ok) case __swift_bridge__$ResultPackGroupSessionBridgeAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
    }

    class public func encrypt_message<GenericToRustStr: ToRustStr>(_ group_session: PackGroupSessionBridgeRefMut, _ sender_identity_public: UnsafeBufferPointer<UInt8>, _ sender_identity_private: UnsafeBufferPointer<UInt8>, _ sender_uuid: GenericToRustStr, _ sender_device_id: UInt32, _ server_cert_key: UnsafeBufferPointer<UInt8>, _ server_cert_id: UInt32, _ cert_expiration: UInt64, _ cert_signature: UnsafeBufferPointer<UInt8>, _ recipient_address_name: GenericToRustStr, _ recipient_address_device_id: UInt32, _ recipient_identity_key: UnsafeBufferPointer<UInt8>, _ plaintext: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> RustVec<UInt8> {
        return try recipient_address_name.toRustStr({ recipient_address_nameAsRustStr in
            return try sender_uuid.toRustStr({ sender_uuidAsRustStr in
            try { let val = __swift_bridge__$PackSealedSenderBridge$encrypt_message(group_session.ptr, sender_identity_public.toFfiSlice(), sender_identity_private.toFfiSlice(), sender_uuidAsRustStr, sender_device_id, server_cert_key.toFfiSlice(), server_cert_id, cert_expiration, cert_signature.toFfiSlice(), recipient_address_nameAsRustStr, recipient_address_device_id, recipient_identity_key.toFfiSlice(), plaintext.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
        })
    }

    class public func decrypt_message(_ our_identity_public: UnsafeBufferPointer<UInt8>, _ our_identity_private: UnsafeBufferPointer<UInt8>, _ ciphertext: UnsafeBufferPointer<UInt8>, _ trust_root: UnsafeBufferPointer<UInt8>, _ current_time: UInt64) throws -> SealedSenderDecryptResult {
        try { let val = __swift_bridge__$PackSealedSenderBridge$decrypt_message(our_identity_public.toFfiSlice(), our_identity_private.toFfiSlice(), ciphertext.toFfiSlice(), trust_root.toFfiSlice(), current_time); switch val.tag { case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultSealedSenderDecryptResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func decrypt_envelope(_ group_session: PackGroupSessionBridgeRefMut, _ inner_ciphertext: UnsafeBufferPointer<UInt8>) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackSealedSenderBridge$decrypt_envelope(group_session.ptr, inner_ciphertext.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackSealedSenderBridgeRefMut: PackSealedSenderBridgeRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PackSealedSenderBridgeRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PackSealedSenderBridge: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PackSealedSenderBridge$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PackSealedSenderBridge$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PackSealedSenderBridge) {
        __swift_bridge__$Vec_PackSealedSenderBridge$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PackSealedSenderBridge$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PackSealedSenderBridge(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackSealedSenderBridgeRef> {
        let pointer = __swift_bridge__$Vec_PackSealedSenderBridge$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackSealedSenderBridgeRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackSealedSenderBridgeRefMut> {
        let pointer = __swift_bridge__$Vec_PackSealedSenderBridge$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackSealedSenderBridgeRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PackSealedSenderBridgeRef> {
        UnsafePointer<PackSealedSenderBridgeRef>(OpaquePointer(__swift_bridge__$Vec_PackSealedSenderBridge$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PackSealedSenderBridge$len(vecPtr)
    }
}

public struct FingerprintResult {
    public var display_text: RustString
    public var scannable_bytes: RustVec<UInt8>

    public init(display_text: RustString,scannable_bytes: RustVec<UInt8>) {
        self.display_text = display_text
        self.scannable_bytes = scannable_bytes
    }

    @inline(__always)
    func intoFfiRepr() -> __swift_bridge__$FingerprintResult {
        { let val = self; return __swift_bridge__$FingerprintResult(display_text: { let rustString = val.display_text.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), scannable_bytes: { let val = val.scannable_bytes; val.isOwned = false; return val.ptr }()); }()
    }
}
extension __swift_bridge__$FingerprintResult {
    @inline(__always)
    func intoSwiftRepr() -> FingerprintResult {
        { let val = self; return FingerprintResult(display_text: RustString(ptr: val.display_text), scannable_bytes: RustVec(ptr: val.scannable_bytes)); }()
    }
}
extension __swift_bridge__$Option$FingerprintResult {
    @inline(__always)
    func intoSwiftRepr() -> Optional<FingerprintResult> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }

    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<FingerprintResult>) -> __swift_bridge__$Option$FingerprintResult {
        if let v = val {
            return __swift_bridge__$Option$FingerprintResult(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$FingerprintResult(is_some: false, val: __swift_bridge__$FingerprintResult())
        }
    }
}

public class PackFingerprintBridge: PackFingerprintBridgeRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PackFingerprintBridge$_free(ptr)
        }
    }
}
extension PackFingerprintBridge {
    class public func generate<GenericToRustStr: ToRustStr>(_ local_identifier: GenericToRustStr, _ local_identity_key: UnsafeBufferPointer<UInt8>, _ remote_identifier: GenericToRustStr, _ remote_identity_key: UnsafeBufferPointer<UInt8>) throws -> FingerprintResult {
        return try remote_identifier.toRustStr({ remote_identifierAsRustStr in
            return try local_identifier.toRustStr({ local_identifierAsRustStr in
            try { let val = __swift_bridge__$PackFingerprintBridge$generate(local_identifierAsRustStr, local_identity_key.toFfiSlice(), remote_identifierAsRustStr, remote_identity_key.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultFingerprintResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultFingerprintResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
        })
        })
    }

    class public func generate_for_session<GenericToRustStr: ToRustStr>(_ session: PackSessionBridgeRef, _ local_identifier: GenericToRustStr, _ remote_identifier: GenericToRustStr) -> FingerprintResult {
        return remote_identifier.toRustStr({ remote_identifierAsRustStr in
            return local_identifier.toRustStr({ local_identifierAsRustStr in
            __swift_bridge__$PackFingerprintBridge$generate_for_session(session.ptr, local_identifierAsRustStr, remote_identifierAsRustStr).intoSwiftRepr()
        })
        })
    }

    class public func verify_scanned(_ local_scannable: UnsafeBufferPointer<UInt8>, _ scanned: UnsafeBufferPointer<UInt8>) throws -> Bool {
        try { let val = __swift_bridge__$PackFingerprintBridge$verify_scanned(local_scannable.toFfiSlice(), scanned.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultBoolAndPackBridgeError$ResultOk: return val.payload.ok case __swift_bridge__$ResultBoolAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackFingerprintBridgeRefMut: PackFingerprintBridgeRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PackFingerprintBridgeRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PackFingerprintBridge: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PackFingerprintBridge$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PackFingerprintBridge$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PackFingerprintBridge) {
        __swift_bridge__$Vec_PackFingerprintBridge$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PackFingerprintBridge$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PackFingerprintBridge(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackFingerprintBridgeRef> {
        let pointer = __swift_bridge__$Vec_PackFingerprintBridge$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackFingerprintBridgeRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackFingerprintBridgeRefMut> {
        let pointer = __swift_bridge__$Vec_PackFingerprintBridge$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackFingerprintBridgeRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PackFingerprintBridgeRef> {
        UnsafePointer<PackFingerprintBridgeRef>(OpaquePointer(__swift_bridge__$Vec_PackFingerprintBridge$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PackFingerprintBridge$len(vecPtr)
    }
}

public struct KeyPairResult {
    public var public_key: RustVec<UInt8>
    public var private_key: RustVec<UInt8>

    public init(public_key: RustVec<UInt8>,private_key: RustVec<UInt8>) {
        self.public_key = public_key
        self.private_key = private_key
    }

    @inline(__always)
    func intoFfiRepr() -> __swift_bridge__$KeyPairResult {
        { let val = self; return __swift_bridge__$KeyPairResult(public_key: { let val = val.public_key; val.isOwned = false; return val.ptr }(), private_key: { let val = val.private_key; val.isOwned = false; return val.ptr }()); }()
    }
}
extension __swift_bridge__$KeyPairResult {
    @inline(__always)
    func intoSwiftRepr() -> KeyPairResult {
        { let val = self; return KeyPairResult(public_key: RustVec(ptr: val.public_key), private_key: RustVec(ptr: val.private_key)); }()
    }
}
extension __swift_bridge__$Option$KeyPairResult {
    @inline(__always)
    func intoSwiftRepr() -> Optional<KeyPairResult> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }

    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<KeyPairResult>) -> __swift_bridge__$Option$KeyPairResult {
        if let v = val {
            return __swift_bridge__$Option$KeyPairResult(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$KeyPairResult(is_some: false, val: __swift_bridge__$KeyPairResult())
        }
    }
}
public struct SignedPreKeyResult {
    public var id: UInt32
    public var public_key: RustVec<UInt8>
    public var private_key: RustVec<UInt8>
    public var signature: RustVec<UInt8>
    public var timestamp: UInt64

    public init(id: UInt32,public_key: RustVec<UInt8>,private_key: RustVec<UInt8>,signature: RustVec<UInt8>,timestamp: UInt64) {
        self.id = id
        self.public_key = public_key
        self.private_key = private_key
        self.signature = signature
        self.timestamp = timestamp
    }

    @inline(__always)
    func intoFfiRepr() -> __swift_bridge__$SignedPreKeyResult {
        { let val = self; return __swift_bridge__$SignedPreKeyResult(id: val.id, public_key: { let val = val.public_key; val.isOwned = false; return val.ptr }(), private_key: { let val = val.private_key; val.isOwned = false; return val.ptr }(), signature: { let val = val.signature; val.isOwned = false; return val.ptr }(), timestamp: val.timestamp); }()
    }
}
extension __swift_bridge__$SignedPreKeyResult {
    @inline(__always)
    func intoSwiftRepr() -> SignedPreKeyResult {
        { let val = self; return SignedPreKeyResult(id: val.id, public_key: RustVec(ptr: val.public_key), private_key: RustVec(ptr: val.private_key), signature: RustVec(ptr: val.signature), timestamp: val.timestamp); }()
    }
}
extension __swift_bridge__$Option$SignedPreKeyResult {
    @inline(__always)
    func intoSwiftRepr() -> Optional<SignedPreKeyResult> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }

    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<SignedPreKeyResult>) -> __swift_bridge__$Option$SignedPreKeyResult {
        if let v = val {
            return __swift_bridge__$Option$SignedPreKeyResult(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$SignedPreKeyResult(is_some: false, val: __swift_bridge__$SignedPreKeyResult())
        }
    }
}
public struct PQPreKeyResult {
    public var id: UInt32
    public var encapsulation_key: RustVec<UInt8>
    public var decapsulation_key: RustVec<UInt8>
    public var signature: RustVec<UInt8>
    public var timestamp: UInt64

    public init(id: UInt32,encapsulation_key: RustVec<UInt8>,decapsulation_key: RustVec<UInt8>,signature: RustVec<UInt8>,timestamp: UInt64) {
        self.id = id
        self.encapsulation_key = encapsulation_key
        self.decapsulation_key = decapsulation_key
        self.signature = signature
        self.timestamp = timestamp
    }

    @inline(__always)
    func intoFfiRepr() -> __swift_bridge__$PQPreKeyResult {
        { let val = self; return __swift_bridge__$PQPreKeyResult(id: val.id, encapsulation_key: { let val = val.encapsulation_key; val.isOwned = false; return val.ptr }(), decapsulation_key: { let val = val.decapsulation_key; val.isOwned = false; return val.ptr }(), signature: { let val = val.signature; val.isOwned = false; return val.ptr }(), timestamp: val.timestamp); }()
    }
}
extension __swift_bridge__$PQPreKeyResult {
    @inline(__always)
    func intoSwiftRepr() -> PQPreKeyResult {
        { let val = self; return PQPreKeyResult(id: val.id, encapsulation_key: RustVec(ptr: val.encapsulation_key), decapsulation_key: RustVec(ptr: val.decapsulation_key), signature: RustVec(ptr: val.signature), timestamp: val.timestamp); }()
    }
}
extension __swift_bridge__$Option$PQPreKeyResult {
    @inline(__always)
    func intoSwiftRepr() -> Optional<PQPreKeyResult> {
        if self.is_some {
            return self.val.intoSwiftRepr()
        } else {
            return nil
        }
    }

    @inline(__always)
    static func fromSwiftRepr(_ val: Optional<PQPreKeyResult>) -> __swift_bridge__$Option$PQPreKeyResult {
        if let v = val {
            return __swift_bridge__$Option$PQPreKeyResult(is_some: true, val: v.intoFfiRepr())
        } else {
            return __swift_bridge__$Option$PQPreKeyResult(is_some: false, val: __swift_bridge__$PQPreKeyResult())
        }
    }
}

public class PackKeyGeneratorBridge: PackKeyGeneratorBridgeRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PackKeyGeneratorBridge$_free(ptr)
        }
    }
}
extension PackKeyGeneratorBridge {
    class public func generate_signed_pre_key(_ id: UInt32, _ identity_public: UnsafeBufferPointer<UInt8>, _ identity_private: UnsafeBufferPointer<UInt8>, _ timestamp: UInt64) throws -> SignedPreKeyResult {
        try { let val = __swift_bridge__$PackKeyGeneratorBridge$generate_signed_pre_key(id, identity_public.toFfiSlice(), identity_private.toFfiSlice(), timestamp); switch val.tag { case __swift_bridge__$ResultSignedPreKeyResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultSignedPreKeyResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func generate_one_time_pre_key(_ id: UInt32) -> KeyPairResult {
        __swift_bridge__$PackKeyGeneratorBridge$generate_one_time_pre_key(id).intoSwiftRepr()
    }

    class public func generate_pq_pre_key(_ id: UInt32, _ identity_public: UnsafeBufferPointer<UInt8>, _ identity_private: UnsafeBufferPointer<UInt8>, _ timestamp: UInt64) throws -> PQPreKeyResult {
        try { let val = __swift_bridge__$PackKeyGeneratorBridge$generate_pq_pre_key(id, identity_public.toFfiSlice(), identity_private.toFfiSlice(), timestamp); switch val.tag { case __swift_bridge__$ResultPQPreKeyResultAndPackBridgeError$ResultOk: return val.payload.ok.intoSwiftRepr() case __swift_bridge__$ResultPQPreKeyResultAndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }

    class public func xeddsa_sign(_ private_key: UnsafeBufferPointer<UInt8>, _ message: UnsafeBufferPointer<UInt8>) throws -> RustVec<UInt8> {
        try { let val = __swift_bridge__$PackKeyGeneratorBridge$xeddsa_sign(private_key.toFfiSlice(), message.toFfiSlice()); switch val.tag { case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultOk: return RustVec(ptr: val.payload.ok) case __swift_bridge__$ResultVec_U8AndPackBridgeError$ResultErr: throw val.payload.err.intoSwiftRepr() default: fatalError() } }()
    }
}
public class PackKeyGeneratorBridgeRefMut: PackKeyGeneratorBridgeRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PackKeyGeneratorBridgeRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PackKeyGeneratorBridgeRef {
    class public func generate_identity_key_pair() -> KeyPairResult {
        __swift_bridge__$PackKeyGeneratorBridge$generate_identity_key_pair().intoSwiftRepr()
    }
}
extension PackKeyGeneratorBridge: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PackKeyGeneratorBridge$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PackKeyGeneratorBridge$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PackKeyGeneratorBridge) {
        __swift_bridge__$Vec_PackKeyGeneratorBridge$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PackKeyGeneratorBridge$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PackKeyGeneratorBridge(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackKeyGeneratorBridgeRef> {
        let pointer = __swift_bridge__$Vec_PackKeyGeneratorBridge$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackKeyGeneratorBridgeRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PackKeyGeneratorBridgeRefMut> {
        let pointer = __swift_bridge__$Vec_PackKeyGeneratorBridge$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PackKeyGeneratorBridgeRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PackKeyGeneratorBridgeRef> {
        UnsafePointer<PackKeyGeneratorBridgeRef>(OpaquePointer(__swift_bridge__$Vec_PackKeyGeneratorBridge$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PackKeyGeneratorBridge$len(vecPtr)
    }
}



