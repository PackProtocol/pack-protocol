package org.pack.protocol

import kotlin.test.Test
import kotlin.test.assertNotNull

/**
 * Basic smoke test. The native library must be on java.library.path for
 * these tests to pass (build the pack-protocol-jni crate first).
 */
class SmokeTest {

    @Test
    fun identityKeyPairGenerates() {
        val keyPair = IdentityKeyPair.generate()
        keyPair.use {
            assertNotNull(it.getPublicKey())
        }
    }
}
