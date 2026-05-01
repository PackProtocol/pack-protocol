/*
 * test_cpp_roundtrip.cpp -- Round-trip tests for the Pack Protocol C++ RAII wrapper.
 *
 * Requires the pack_protocol_ffi library to be built first:
 *   cargo build --release -p pack-protocol-ffi
 *
 * Build with CMake:
 *   cmake -B build -DPACK_BUILD_TESTS=ON && cmake --build build
 *   ctest --test-dir build
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>

#include "pack_protocol.hpp"

/* ------------------------------------------------------------------ */
/* Test: IdentityKeyPairWrapper generate + get public key              */
/* ------------------------------------------------------------------ */
static void test_identity_key_pair_generate() {
    std::printf("  identity_key_pair_generate ... ");

    pack::IdentityKeyPairWrapper kp;
    auto pub = kp.get_public();
    assert(!pub.empty());

    /* A second pair must yield a different public key. */
    pack::IdentityKeyPairWrapper kp2;
    auto pub2 = kp2.get_public();
    assert(pub.size() == pub2.size());
    assert(pub != pub2);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: public key round-trips through IdentityKeyWrapper             */
/* ------------------------------------------------------------------ */
static void test_identity_key_roundtrip() {
    std::printf("  identity_key_roundtrip ... ");

    pack::IdentityKeyPairWrapper kp;
    auto pub = kp.get_public();

    pack::IdentityKeyWrapper ik(pub);
    auto roundtrip = ik.get_bytes();

    assert(pub == roundtrip);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: sign and verify                                               */
/* ------------------------------------------------------------------ */
static void test_sign_and_verify() {
    std::printf("  sign_and_verify ... ");

    pack::IdentityKeyPairWrapper kp;
    std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};

    auto sig = kp.sign(message);
    assert(!sig.empty());

    /* Verify through the public key. */
    auto pub = kp.get_public();
    pack::IdentityKeyWrapper ik(pub);
    ik.verify(message, sig); /* throws on failure */

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: move semantics                                                */
/* ------------------------------------------------------------------ */
static void test_move_semantics() {
    std::printf("  move_semantics ... ");

    pack::IdentityKeyPairWrapper kp;
    auto pub_original = kp.get_public();

    /* Move-construct. */
    pack::IdentityKeyPairWrapper kp2(std::move(kp));
    auto pub_moved = kp2.get_public();
    assert(pub_original == pub_moved);

    /* The source handle should be null (safe to destruct, but unusable). */
    assert(kp.get() == nullptr);

    /* Move-assign. */
    pack::IdentityKeyPairWrapper kp3;
    kp3 = std::move(kp2);
    auto pub_assigned = kp3.get_public();
    assert(pub_original == pub_assigned);
    assert(kp2.get() == nullptr);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: FingerprintWrapper creation and display                       */
/* ------------------------------------------------------------------ */
static void test_fingerprint_creation() {
    std::printf("  fingerprint_creation ... ");

    pack::IdentityKeyPairWrapper kp_local;
    pack::IdentityKeyPairWrapper kp_remote;

    pack::IdentityKeyWrapper ik_local(kp_local.get_public());
    pack::IdentityKeyWrapper ik_remote(kp_remote.get_public());

    std::vector<uint8_t> local_id  = {'+', '1', '4', '1', '5', '5', '5', '5', '1', '2', '3', '4'};
    std::vector<uint8_t> remote_id = {'+', '1', '4', '1', '5', '5', '5', '5', '5', '6', '7', '8'};

    pack::FingerprintWrapper fp(local_id, ik_local, remote_id, ik_remote);

    /* Display string should be non-empty. */
    auto display = fp.display();
    assert(!display.empty());

    std::string display_str = fp.display_string();
    assert(!display_str.empty());

    /* Scannable bytes should be non-empty. */
    auto scannable = fp.scannable_bytes();
    assert(!scannable.empty());

    /* Scannable bytes should verify against themselves. */
    bool match = pack::FingerprintWrapper::verify_scannable(scannable, scannable);
    assert(match);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: KeyPairWrapper (ephemeral Curve25519)                         */
/* ------------------------------------------------------------------ */
static void test_keypair_wrapper() {
    std::printf("  keypair_wrapper ... ");

    pack::KeyPairWrapper kp;
    auto pub = kp.get_public();
    assert(!pub.empty());

    pack::KeyPairWrapper kp2;
    auto pub2 = kp2.get_public();
    assert(pub != pub2);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: exception handling for invalid inputs                         */
/* ------------------------------------------------------------------ */
static void test_exception_on_invalid_key() {
    std::printf("  exception_on_invalid_key ... ");

    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
    bool caught = false;
    try {
        pack::IdentityKeyWrapper ik(garbage);
        (void)ik; /* should not reach here */
    } catch (const pack::PackException& e) {
        caught = true;
        assert(e.code() != OK);
    }
    assert(caught);

    std::printf("OK\n");
}

static void test_exception_on_invalid_signature() {
    std::printf("  exception_on_invalid_signature ... ");

    pack::IdentityKeyPairWrapper kp;
    pack::IdentityKeyWrapper ik(kp.get_public());

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    std::vector<uint8_t> bad_sig = {0x00, 0x01, 0x02, 0x03};

    bool caught = false;
    try {
        ik.verify(message, bad_sig);
    } catch (const pack::PackException& e) {
        caught = true;
        assert(e.code() != OK);
    }
    assert(caught);

    std::printf("OK\n");
}

/* ------------------------------------------------------------------ */
int main() {
    std::printf("test_cpp_roundtrip\n");
    test_identity_key_pair_generate();
    test_identity_key_roundtrip();
    test_sign_and_verify();
    test_move_semantics();
    test_fingerprint_creation();
    test_keypair_wrapper();
    test_exception_on_invalid_key();
    test_exception_on_invalid_signature();
    std::printf("All C++ round-trip tests passed.\n");
    return 0;
}
