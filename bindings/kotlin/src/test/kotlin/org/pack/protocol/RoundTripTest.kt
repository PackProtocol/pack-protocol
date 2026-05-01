package org.pack.protocol

// These tests require the native pack_protocol_jni library to be built first:
//   cargo build --release -p pack-protocol-jni

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RoundTripTest {

    @Test
    fun identityKeyPairPublicKeyIs32Bytes() {
        IdentityKeyPair.generate().use { keyPair ->
            val publicKey = keyPair.getPublicKey()
            assertNotNull(publicKey)
            assertEquals(32, publicKey.size, "Curve25519 public key must be 32 bytes")
        }
    }

    @Test
    fun fingerprintDisplayStringIs60Digits() {
        IdentityKeyPair.generate().use { alice ->
            IdentityKeyPair.generate().use { bob ->
                val localId = "alice".toByteArray(Charsets.UTF_8)
                val remoteId = "bob".toByteArray(Charsets.UTF_8)

                val fingerprintBytes = Fingerprint.generate(
                    localId, alice.getPublicKey(),
                    remoteId, bob.getPublicKey()
                )

                val displayString = String(fingerprintBytes, Charsets.UTF_8)
                assertTrue(
                    displayString.matches(Regex("^\\d{60}$")),
                    "Fingerprint display string must be exactly 60 digits, got: $displayString"
                )
            }
        }
    }

    @Test
    fun groupCipherEncryptDecryptRoundTrip() {
        GroupCipher.create().use { cipher ->
            val distributionMessage = cipher.createDistributionMessage("test-group-001")
            assertNotNull(distributionMessage)
            assertTrue(distributionMessage.isNotEmpty(), "Distribution message must not be empty")

            val plaintext = "Hello, group!".toByteArray(Charsets.UTF_8)
            val ciphertext = cipher.encrypt(plaintext)
            assertNotNull(ciphertext)
            assertTrue(ciphertext.size > plaintext.size, "Ciphertext should be larger than plaintext")

            val decrypted = cipher.decrypt(ciphertext)
            assertArrayEquals(plaintext, decrypted, "Decrypted text must match original plaintext")
        }
    }
}
