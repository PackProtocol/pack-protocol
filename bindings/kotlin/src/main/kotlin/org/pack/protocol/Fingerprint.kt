package org.pack.protocol

object Fingerprint {
    init {
        System.loadLibrary("pack_protocol_jni")
    }

    fun generate(
        localIdentifier: ByteArray,
        localKey: ByteArray,
        remoteIdentifier: ByteArray,
        remoteKey: ByteArray
    ): ByteArray {
        return nativeGenerate(localIdentifier, localKey, remoteIdentifier, remoteKey)
    }

    @JvmStatic
    private external fun nativeGenerate(
        localId: ByteArray,
        localKey: ByteArray,
        remoteId: ByteArray,
        remoteKey: ByteArray
    ): ByteArray
}
