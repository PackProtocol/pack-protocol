/*
 * test_c_roundtrip.c -- Round-trip tests for the Pack Protocol C API.
 *
 * Requires the pack_protocol_ffi library to be built first:
 *   cargo build --release -p pack-protocol-ffi
 *
 * Build with CMake:
 *   cmake -B build -DPACK_BUILD_TESTS=ON && cmake --build build
 *   ctest --test-dir build
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Forward-declare the opaque types the C header references. */
struct IdentityKeyPair;
typedef struct IdentityKeyPair IdentityKeyPair;

struct IdentityKey;
typedef struct IdentityKey IdentityKey;

struct Fingerprint;
typedef struct Fingerprint Fingerprint;

#include "pack_protocol.h"

/* ------------------------------------------------------------------ */
/* Test: generate an IdentityKeyPair and read its public key bytes     */
/* ------------------------------------------------------------------ */
static void test_identity_key_pair_roundtrip(void) {
    printf("  identity_key_pair_roundtrip ... ");

    IdentityKeyPair *kp = NULL;
    enum PackFfiError err = pack_identity_key_pair_generate(&kp);
    assert(err == OK);
    assert(kp != NULL);

    /* First call: query required length. */
    size_t pub_len = 0;
    pack_identity_key_pair_get_public(kp, NULL, 0, &pub_len);
    assert(pub_len > 0);

    /* Second call: actually copy the bytes. */
    uint8_t pub_buf[128];
    assert(pub_len <= sizeof(pub_buf));
    size_t written = 0;
    err = pack_identity_key_pair_get_public(kp, pub_buf, sizeof(pub_buf), &written);
    assert(err == OK);
    assert(written == pub_len);

    /* A second generation must produce a different key. */
    IdentityKeyPair *kp2 = NULL;
    err = pack_identity_key_pair_generate(&kp2);
    assert(err == OK);

    uint8_t pub_buf2[128];
    size_t written2 = 0;
    err = pack_identity_key_pair_get_public(kp2, pub_buf2, sizeof(pub_buf2), &written2);
    assert(err == OK);
    assert(written2 == written); /* same length */
    assert(memcmp(pub_buf, pub_buf2, written) != 0); /* different content */

    pack_identity_key_pair_destroy(kp2);
    pack_identity_key_pair_destroy(kp);

    printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: public key bytes survive an IdentityKey round-trip            */
/* ------------------------------------------------------------------ */
static void test_identity_key_serialize_roundtrip(void) {
    printf("  identity_key_serialize_roundtrip ... ");

    /* Generate a key pair and extract the public key bytes. */
    IdentityKeyPair *kp = NULL;
    assert(pack_identity_key_pair_generate(&kp) == OK);

    uint8_t pub_bytes[128];
    size_t pub_len = 0;
    assert(pack_identity_key_pair_get_public(kp, pub_bytes, sizeof(pub_bytes), &pub_len) == OK);

    /* Deserialise those bytes into a standalone IdentityKey. */
    IdentityKey *ik = NULL;
    assert(pack_identity_key_from_bytes(pub_bytes, pub_len, &ik) == OK);
    assert(ik != NULL);

    /* Re-serialise and compare. */
    uint8_t roundtrip[128];
    size_t rt_len = 0;
    assert(pack_identity_key_get_bytes(ik, roundtrip, sizeof(roundtrip), &rt_len) == OK);
    assert(rt_len == pub_len);
    assert(memcmp(pub_bytes, roundtrip, pub_len) == 0);

    pack_identity_key_destroy(ik);
    pack_identity_key_pair_destroy(kp);

    printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: sign a message and verify via the public key                  */
/* ------------------------------------------------------------------ */
static void test_sign_and_verify(void) {
    printf("  sign_and_verify ... ");

    IdentityKeyPair *kp = NULL;
    assert(pack_identity_key_pair_generate(&kp) == OK);

    const uint8_t message[] = "hello, pack protocol";
    uint8_t sig[256];
    size_t sig_len = 0;
    assert(pack_identity_key_pair_sign(kp, message, sizeof(message),
                                         sig, sizeof(sig), &sig_len) == OK);
    assert(sig_len > 0);

    /* Get the public key, wrap it in an IdentityKey, and verify. */
    uint8_t pub_bytes[128];
    size_t pub_len = 0;
    assert(pack_identity_key_pair_get_public(kp, pub_bytes, sizeof(pub_bytes), &pub_len) == OK);

    IdentityKey *ik = NULL;
    assert(pack_identity_key_from_bytes(pub_bytes, pub_len, &ik) == OK);
    assert(pack_identity_key_verify(ik, message, sizeof(message), sig, sig_len) == OK);

    pack_identity_key_destroy(ik);
    pack_identity_key_pair_destroy(kp);

    printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: fingerprint generation and display string                     */
/* ------------------------------------------------------------------ */
static void test_fingerprint_generation(void) {
    printf("  fingerprint_generation ... ");

    /* Generate two identity key pairs (local and remote). */
    IdentityKeyPair *kp_local = NULL;
    IdentityKeyPair *kp_remote = NULL;
    assert(pack_identity_key_pair_generate(&kp_local) == OK);
    assert(pack_identity_key_pair_generate(&kp_remote) == OK);

    /* Extract public keys into IdentityKey handles. */
    uint8_t pub_local[128], pub_remote[128];
    size_t pub_local_len = 0, pub_remote_len = 0;
    assert(pack_identity_key_pair_get_public(kp_local, pub_local,
                                               sizeof(pub_local), &pub_local_len) == OK);
    assert(pack_identity_key_pair_get_public(kp_remote, pub_remote,
                                               sizeof(pub_remote), &pub_remote_len) == OK);

    IdentityKey *ik_local = NULL;
    IdentityKey *ik_remote = NULL;
    assert(pack_identity_key_from_bytes(pub_local, pub_local_len, &ik_local) == OK);
    assert(pack_identity_key_from_bytes(pub_remote, pub_remote_len, &ik_remote) == OK);

    /* User identifiers (arbitrary bytes). */
    const uint8_t local_id[]  = "+14155551234";
    const uint8_t remote_id[] = "+14155555678";

    Fingerprint *fp = NULL;
    enum PackFfiError err = pack_fingerprint_generate(
        local_id, sizeof(local_id) - 1, ik_local,
        remote_id, sizeof(remote_id) - 1, ik_remote,
        &fp);
    assert(err == OK);
    assert(fp != NULL);

    /* Get the display string. */
    size_t disp_len = 0;
    pack_fingerprint_display(fp, NULL, 0, &disp_len);
    assert(disp_len > 0);

    uint8_t disp_buf[512];
    assert(disp_len <= sizeof(disp_buf));
    size_t disp_written = 0;
    assert(pack_fingerprint_display(fp, disp_buf, sizeof(disp_buf), &disp_written) == OK);
    assert(disp_written == disp_len);
    assert(disp_written > 0);

    /* Get scannable bytes. */
    size_t scan_len = 0;
    pack_fingerprint_scannable_bytes(fp, NULL, 0, &scan_len);
    assert(scan_len > 0);

    uint8_t scan_buf[512];
    assert(scan_len <= sizeof(scan_buf));
    size_t scan_written = 0;
    assert(pack_fingerprint_scannable_bytes(fp, scan_buf, sizeof(scan_buf), &scan_written) == OK);
    assert(scan_written == scan_len);

    /* Scannable bytes should verify against themselves. */
    bool match = false;
    assert(pack_scannable_fingerprint_verify(scan_buf, scan_written,
                                               scan_buf, scan_written, &match) == OK);
    assert(match);

    pack_fingerprint_destroy(fp);
    pack_identity_key_destroy(ik_remote);
    pack_identity_key_destroy(ik_local);
    pack_identity_key_pair_destroy(kp_remote);
    pack_identity_key_pair_destroy(kp_local);

    printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* Test: invalid input produces an error, not a crash                   */
/* ------------------------------------------------------------------ */
static void test_invalid_key_rejected(void) {
    printf("  invalid_key_rejected ... ");

    const uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF};
    IdentityKey *ik = NULL;
    enum PackFfiError err = pack_identity_key_from_bytes(garbage, sizeof(garbage), &ik);
    assert(err != OK);
    assert(ik == NULL);

    printf("OK\n");
}

/* ------------------------------------------------------------------ */
int main(void) {
    printf("test_c_roundtrip\n");
    test_identity_key_pair_roundtrip();
    test_identity_key_serialize_roundtrip();
    test_sign_and_verify();
    test_fingerprint_generation();
    test_invalid_key_rejected();
    printf("All C round-trip tests passed.\n");
    return 0;
}
