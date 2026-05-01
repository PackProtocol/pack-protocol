// Pack Protocol C++ RAII Bindings
//
// Header-only C++ wrapper around the signal-protocol C FFI.
// All classes are move-only and release their handles on destruction.

#ifndef PACK_PROTOCOL_HPP
#define PACK_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Forward-declare opaque C types used by the FFI header.
// These are incomplete types; the C API only ever traffics in pointers to them.
struct IdentityKeyPair;
struct IdentityKey;
struct KeyPair;
struct Fingerprint;
struct SenderKeyRecord;
struct SenderKeyDistributionMessage;

extern "C" {
#include "pack_protocol.h"
}

namespace pack {

// ---------------------------------------------------------------------------
// Exception type
// ---------------------------------------------------------------------------

class PackException : public std::runtime_error {
public:
    explicit PackException(PackFfiError code)
        : std::runtime_error(error_string(code)), code_(code) {}

    PackFfiError code() const noexcept { return code_; }

private:
    PackFfiError code_;

    static const char* error_string(PackFfiError c) {
        switch (c) {
        case OK:                       return "OK";
        case INVALID_ARGUMENT:         return "Invalid argument";
        case INVALID_KEY:              return "Invalid key";
        case INVALID_SIGNATURE:        return "Invalid signature";
        case INVALID_MESSAGE:          return "Invalid message";
        case INVALID_MAC:              return "Invalid MAC";
        case UNTRUSTED_IDENTITY:       return "Untrusted identity";
        case NO_SESSION:               return "No session";
        case DUPLICATE_MESSAGE:        return "Duplicate message";
        case EXPIRED_CERTIFICATE:      return "Expired certificate";
        case INVALID_CERTIFICATE:      return "Invalid certificate";
        case TOO_MANY_SKIPPED_MESSAGES:return "Too many skipped messages";
        case INTERNAL_ERROR:           return "Internal error";
        default:                       return "Unknown error";
        }
    }
};

inline void check(PackFfiError err) {
    if (err != OK) {
        throw PackException(err);
    }
}

// ---------------------------------------------------------------------------
// IdentityKeyPair
// ---------------------------------------------------------------------------

class IdentityKeyPairWrapper {
public:
    /// Generate a new identity key pair.
    IdentityKeyPairWrapper() : handle_(nullptr) {
        check(pack_identity_key_pair_generate(&handle_));
    }

    ~IdentityKeyPairWrapper() {
        if (handle_) {
            pack_identity_key_pair_destroy(handle_);
        }
    }

    // Move-only
    IdentityKeyPairWrapper(IdentityKeyPairWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    IdentityKeyPairWrapper& operator=(IdentityKeyPairWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_identity_key_pair_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    IdentityKeyPairWrapper(const IdentityKeyPairWrapper&) = delete;
    IdentityKeyPairWrapper& operator=(const IdentityKeyPairWrapper&) = delete;

    /// Retrieve the public key bytes.
    std::vector<uint8_t> get_public() const {
        // First call to learn the length.
        std::size_t len = 0;
        pack_identity_key_pair_get_public(handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_identity_key_pair_get_public(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    /// Sign a message, returning the signature bytes.
    std::vector<uint8_t> sign(const uint8_t* message, std::size_t message_len) const {
        // First call to learn the required signature length.
        std::size_t sig_len = 0;
        pack_identity_key_pair_sign(
            handle_, message, message_len, nullptr, 0, &sig_len);
        std::vector<uint8_t> sig(sig_len);
        check(pack_identity_key_pair_sign(
            handle_, message, message_len, sig.data(), sig.size(), &sig_len));
        sig.resize(sig_len);
        return sig;
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const {
        return sign(message.data(), message.size());
    }

    /// Access the raw C handle (non-owning).
    const ::IdentityKeyPair* get() const noexcept { return handle_; }
    ::IdentityKeyPair* get() noexcept { return handle_; }

private:
    ::IdentityKeyPair* handle_;
};

// ---------------------------------------------------------------------------
// IdentityKey  (public key only)
// ---------------------------------------------------------------------------

class IdentityKeyWrapper {
public:
    /// Deserialise an identity key from raw bytes.
    IdentityKeyWrapper(const uint8_t* data, std::size_t data_len)
        : handle_(nullptr) {
        check(pack_identity_key_from_bytes(data, data_len, &handle_));
    }

    explicit IdentityKeyWrapper(const std::vector<uint8_t>& data)
        : IdentityKeyWrapper(data.data(), data.size()) {}

    ~IdentityKeyWrapper() {
        if (handle_) {
            pack_identity_key_destroy(handle_);
        }
    }

    // Move-only
    IdentityKeyWrapper(IdentityKeyWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    IdentityKeyWrapper& operator=(IdentityKeyWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_identity_key_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    IdentityKeyWrapper(const IdentityKeyWrapper&) = delete;
    IdentityKeyWrapper& operator=(const IdentityKeyWrapper&) = delete;

    /// Serialise the key to bytes.
    std::vector<uint8_t> get_bytes() const {
        std::size_t len = 0;
        pack_identity_key_get_bytes(handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_identity_key_get_bytes(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    /// Verify a signature over a message.  Throws on verification failure.
    void verify(const uint8_t* message, std::size_t message_len,
                const uint8_t* signature, std::size_t signature_len) const {
        check(pack_identity_key_verify(
            handle_, message, message_len, signature, signature_len));
    }

    void verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature) const {
        verify(message.data(), message.size(),
               signature.data(), signature.size());
    }

    const ::IdentityKey* get() const noexcept { return handle_; }

private:
    ::IdentityKey* handle_;
};

// ---------------------------------------------------------------------------
// KeyPair  (ephemeral Curve25519 key pair)
// ---------------------------------------------------------------------------

class KeyPairWrapper {
public:
    KeyPairWrapper() : handle_(nullptr) {
        check(pack_keypair_generate(&handle_));
    }

    ~KeyPairWrapper() {
        if (handle_) {
            pack_keypair_destroy(handle_);
        }
    }

    // Move-only
    KeyPairWrapper(KeyPairWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    KeyPairWrapper& operator=(KeyPairWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_keypair_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    KeyPairWrapper(const KeyPairWrapper&) = delete;
    KeyPairWrapper& operator=(const KeyPairWrapper&) = delete;

    std::vector<uint8_t> get_public() const {
        std::size_t len = 0;
        pack_keypair_get_public(handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_keypair_get_public(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    const ::KeyPair* get() const noexcept { return handle_; }

private:
    ::KeyPair* handle_;
};

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

class FingerprintWrapper {
public:
    /// Generate a fingerprint from local and remote identity information.
    FingerprintWrapper(const uint8_t* local_id, std::size_t local_id_len,
                       const IdentityKeyWrapper& local_key,
                       const uint8_t* remote_id, std::size_t remote_id_len,
                       const IdentityKeyWrapper& remote_key)
        : handle_(nullptr) {
        check(pack_fingerprint_generate(
            local_id, local_id_len, local_key.get(),
            remote_id, remote_id_len, remote_key.get(),
            &handle_));
    }

    FingerprintWrapper(const std::vector<uint8_t>& local_id,
                       const IdentityKeyWrapper& local_key,
                       const std::vector<uint8_t>& remote_id,
                       const IdentityKeyWrapper& remote_key)
        : FingerprintWrapper(local_id.data(), local_id.size(), local_key,
                             remote_id.data(), remote_id.size(), remote_key) {}

    ~FingerprintWrapper() {
        if (handle_) {
            pack_fingerprint_destroy(handle_);
        }
    }

    // Move-only
    FingerprintWrapper(FingerprintWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    FingerprintWrapper& operator=(FingerprintWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_fingerprint_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    FingerprintWrapper(const FingerprintWrapper&) = delete;
    FingerprintWrapper& operator=(const FingerprintWrapper&) = delete;

    /// Get the human-readable display string (numeric code) as raw bytes.
    std::vector<uint8_t> display() const {
        std::size_t len = 0;
        pack_fingerprint_display(handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_fingerprint_display(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    /// Get the display string as a std::string.
    std::string display_string() const {
        auto bytes = display();
        return std::string(bytes.begin(), bytes.end());
    }

    /// Get the scannable fingerprint bytes (for QR code, etc.).
    std::vector<uint8_t> scannable_bytes() const {
        std::size_t len = 0;
        pack_fingerprint_scannable_bytes(handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_fingerprint_scannable_bytes(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    /// Compare two scannable fingerprints (static, does not require a handle).
    static bool verify_scannable(const uint8_t* ours, std::size_t ours_len,
                                 const uint8_t* theirs, std::size_t theirs_len) {
        bool match = false;
        check(pack_scannable_fingerprint_verify(
            ours, ours_len, theirs, theirs_len, &match));
        return match;
    }

    static bool verify_scannable(const std::vector<uint8_t>& ours,
                                 const std::vector<uint8_t>& theirs) {
        return verify_scannable(ours.data(), ours.size(),
                                theirs.data(), theirs.size());
    }

    const ::Fingerprint* get() const noexcept { return handle_; }

private:
    ::Fingerprint* handle_;
};

// ---------------------------------------------------------------------------
// GroupCipher  (sender-key based group messaging)
// ---------------------------------------------------------------------------

class SenderKeyRecordWrapper {
public:
    SenderKeyRecordWrapper() : handle_(nullptr) {
        check(pack_sender_key_record_create(&handle_));
    }

    ~SenderKeyRecordWrapper() {
        if (handle_) {
            pack_sender_key_record_destroy(handle_);
        }
    }

    // Move-only
    SenderKeyRecordWrapper(SenderKeyRecordWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    SenderKeyRecordWrapper& operator=(SenderKeyRecordWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_sender_key_record_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    SenderKeyRecordWrapper(const SenderKeyRecordWrapper&) = delete;
    SenderKeyRecordWrapper& operator=(const SenderKeyRecordWrapper&) = delete;

    ::SenderKeyRecord* get() noexcept { return handle_; }
    const ::SenderKeyRecord* get() const noexcept { return handle_; }

private:
    ::SenderKeyRecord* handle_;
};

class SenderKeyDistributionMessageWrapper {
public:
    /// Create a new sender key distribution message for the given distribution id.
    SenderKeyDistributionMessageWrapper(const uint8_t* distribution_id,
                                        std::size_t distribution_id_len,
                                        SenderKeyRecordWrapper& record)
        : handle_(nullptr) {
        check(pack_create_sender_key_distribution_message(
            distribution_id, distribution_id_len, record.get(), &handle_));
    }

    SenderKeyDistributionMessageWrapper(const std::vector<uint8_t>& distribution_id,
                                        SenderKeyRecordWrapper& record)
        : SenderKeyDistributionMessageWrapper(
              distribution_id.data(), distribution_id.size(), record) {}

    ~SenderKeyDistributionMessageWrapper() {
        if (handle_) {
            pack_sender_key_distribution_message_destroy(handle_);
        }
    }

    // Move-only
    SenderKeyDistributionMessageWrapper(SenderKeyDistributionMessageWrapper&& other) noexcept
        : handle_(other.handle_) { other.handle_ = nullptr; }

    SenderKeyDistributionMessageWrapper& operator=(SenderKeyDistributionMessageWrapper&& other) noexcept {
        if (this != &other) {
            if (handle_) pack_sender_key_distribution_message_destroy(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    SenderKeyDistributionMessageWrapper(const SenderKeyDistributionMessageWrapper&) = delete;
    SenderKeyDistributionMessageWrapper& operator=(const SenderKeyDistributionMessageWrapper&) = delete;

    /// Serialise the distribution message.
    std::vector<uint8_t> serialize() const {
        std::size_t len = 0;
        pack_sender_key_distribution_message_serialize(
            handle_, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_sender_key_distribution_message_serialize(
            handle_, buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    const ::SenderKeyDistributionMessage* get() const noexcept { return handle_; }

private:
    ::SenderKeyDistributionMessage* handle_;
};

/// High-level group cipher that owns a SenderKeyRecord.
class GroupCipher {
public:
    GroupCipher() = default;

    /// Process a received sender key distribution message into the record.
    void process_distribution_message(const uint8_t* message_data,
                                      std::size_t message_len) {
        check(pack_process_sender_key_distribution_message(
            record_.get(), message_data, message_len));
    }

    void process_distribution_message(const std::vector<uint8_t>& message) {
        process_distribution_message(message.data(), message.size());
    }

    /// Create a sender key distribution message for this group.
    SenderKeyDistributionMessageWrapper create_distribution_message(
            const uint8_t* distribution_id, std::size_t distribution_id_len) {
        return SenderKeyDistributionMessageWrapper(
            distribution_id, distribution_id_len, record_);
    }

    SenderKeyDistributionMessageWrapper create_distribution_message(
            const std::vector<uint8_t>& distribution_id) {
        return create_distribution_message(
            distribution_id.data(), distribution_id.size());
    }

    /// Encrypt plaintext for the group.
    std::vector<uint8_t> encrypt(const uint8_t* plaintext,
                                 std::size_t plaintext_len) {
        std::size_t len = 0;
        pack_group_encrypt(
            record_.get(), plaintext, plaintext_len, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_group_encrypt(
            record_.get(), plaintext, plaintext_len,
            buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        return encrypt(plaintext.data(), plaintext.size());
    }

    /// Decrypt ciphertext from the group.
    std::vector<uint8_t> decrypt(const uint8_t* ciphertext,
                                 std::size_t ciphertext_len) {
        std::size_t len = 0;
        pack_group_decrypt(
            record_.get(), ciphertext, ciphertext_len, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        check(pack_group_decrypt(
            record_.get(), ciphertext, ciphertext_len,
            buf.data(), buf.size(), &len));
        buf.resize(len);
        return buf;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        return decrypt(ciphertext.data(), ciphertext.size());
    }

    /// Access the underlying record.
    SenderKeyRecordWrapper& record() noexcept { return record_; }
    const SenderKeyRecordWrapper& record() const noexcept { return record_; }

private:
    SenderKeyRecordWrapper record_;
};

// ---------------------------------------------------------------------------
// SealedSender  (unidentified sender / sealed-sender messages)
// ---------------------------------------------------------------------------

namespace SealedSender {

/// Encrypt a sealed-sender message.
///
/// @param sender_identity  The sender's identity key pair.
/// @param sender_cert_data Raw bytes of the sender certificate.
/// @param recipient_key    The recipient's identity (public) key.
/// @param inner_message    The plaintext inner message.
/// @param current_time     Current UNIX timestamp in milliseconds.
/// @return                 The sealed-sender ciphertext.
inline std::vector<uint8_t> encrypt(
        const IdentityKeyPairWrapper& sender_identity,
        const uint8_t* sender_cert_data, std::size_t sender_cert_len,
        const IdentityKeyWrapper& recipient_key,
        const uint8_t* inner_message, std::size_t inner_message_len,
        uint64_t current_time) {
    std::size_t len = 0;
    pack_sealed_sender_encrypt(
        sender_identity.get(),
        sender_cert_data, sender_cert_len,
        recipient_key.get(),
        inner_message, inner_message_len,
        current_time,
        nullptr, 0, &len);
    std::vector<uint8_t> buf(len);
    check(pack_sealed_sender_encrypt(
        sender_identity.get(),
        sender_cert_data, sender_cert_len,
        recipient_key.get(),
        inner_message, inner_message_len,
        current_time,
        buf.data(), buf.size(), &len));
    buf.resize(len);
    return buf;
}

inline std::vector<uint8_t> encrypt(
        const IdentityKeyPairWrapper& sender_identity,
        const std::vector<uint8_t>& sender_cert,
        const IdentityKeyWrapper& recipient_key,
        const std::vector<uint8_t>& inner_message,
        uint64_t current_time) {
    return encrypt(sender_identity,
                   sender_cert.data(), sender_cert.size(),
                   recipient_key,
                   inner_message.data(), inner_message.size(),
                   current_time);
}

/// Result of a sealed-sender decryption.
struct DecryptResult {
    std::vector<uint8_t> sender_uuid;
    std::vector<uint8_t> message;
};

/// Decrypt a sealed-sender message.
///
/// @param our_identity    Our identity key pair.
/// @param ciphertext      The sealed-sender ciphertext.
/// @param trust_root_data Raw bytes of the trust root public key.
/// @param current_time    Current UNIX timestamp in milliseconds.
/// @return                DecryptResult containing sender UUID and plaintext.
inline DecryptResult decrypt(
        const IdentityKeyPairWrapper& our_identity,
        const uint8_t* ciphertext, std::size_t ciphertext_len,
        const uint8_t* trust_root_data, std::size_t trust_root_len,
        uint64_t current_time) {
    // Probe for required buffer sizes.
    std::size_t uuid_len = 0;
    std::size_t msg_len = 0;
    pack_sealed_sender_decrypt(
        our_identity.get(),
        ciphertext, ciphertext_len,
        trust_root_data, trust_root_len,
        current_time,
        nullptr, 0, &uuid_len,
        nullptr, 0, &msg_len);

    std::vector<uint8_t> uuid_buf(uuid_len);
    std::vector<uint8_t> msg_buf(msg_len);
    check(pack_sealed_sender_decrypt(
        our_identity.get(),
        ciphertext, ciphertext_len,
        trust_root_data, trust_root_len,
        current_time,
        uuid_buf.data(), uuid_buf.size(), &uuid_len,
        msg_buf.data(), msg_buf.size(), &msg_len));
    uuid_buf.resize(uuid_len);
    msg_buf.resize(msg_len);
    return DecryptResult{std::move(uuid_buf), std::move(msg_buf)};
}

inline DecryptResult decrypt(
        const IdentityKeyPairWrapper& our_identity,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& trust_root,
        uint64_t current_time) {
    return decrypt(our_identity,
                   ciphertext.data(), ciphertext.size(),
                   trust_root.data(), trust_root.size(),
                   current_time);
}

} // namespace SealedSender

} // namespace pack

#endif // PACK_PROTOCOL_HPP
