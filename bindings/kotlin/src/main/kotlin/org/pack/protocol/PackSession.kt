package org.pack.protocol

class PackSession private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("pack_protocol_jni")
        }

        fun initiate(
            ourName: String,
            ourDeviceId: Int,
            identityPublic: ByteArray,
            identityPrivate: ByteArray,
            registrationId: Int,
            remoteName: String,
            remoteDeviceId: Int,
            bundleIdentityKey: ByteArray,
            bundleSpkId: Int,
            bundleSpk: ByteArray,
            bundleSpkSignature: ByteArray,
            bundleSpkTimestamp: Long,
            bundleOpkId: Int,
            bundleOpk: ByteArray?,
            firstMessage: ByteArray
        ): InitiateResult {
            val sessionHandle = nativeInitiate(
                ourName, ourDeviceId,
                identityPublic, identityPrivate, registrationId,
                remoteName, remoteDeviceId,
                bundleIdentityKey, bundleSpkId, bundleSpk,
                bundleSpkSignature, bundleSpkTimestamp,
                bundleOpkId, bundleOpk ?: ByteArray(0),
                firstMessage
            )
            val preKeyMessage = nativeInitiateGetMessage(
                ourName, ourDeviceId,
                identityPublic, identityPrivate, registrationId,
                remoteName, remoteDeviceId,
                bundleIdentityKey, bundleSpkId, bundleSpk,
                bundleSpkSignature, bundleSpkTimestamp,
                bundleOpkId, bundleOpk ?: ByteArray(0),
                firstMessage
            )
            return InitiateResult(PackSession(sessionHandle), preKeyMessage)
        }

        @JvmStatic private external fun nativeInitiate(
            ourName: String, ourDeviceId: Int,
            identityPublic: ByteArray, identityPrivate: ByteArray,
            registrationId: Int,
            remoteName: String, remoteDeviceId: Int,
            bundleIdentityKey: ByteArray, bundleSpkId: Int,
            bundleSpk: ByteArray, bundleSpkSig: ByteArray,
            bundleSpkTimestamp: Long,
            bundleOpkId: Int, bundleOpk: ByteArray,
            firstMessage: ByteArray
        ): Long

        @JvmStatic private external fun nativeInitiateGetMessage(
            ourName: String, ourDeviceId: Int,
            identityPublic: ByteArray, identityPrivate: ByteArray,
            registrationId: Int,
            remoteName: String, remoteDeviceId: Int,
            bundleIdentityKey: ByteArray, bundleSpkId: Int,
            bundleSpk: ByteArray, bundleSpkSig: ByteArray,
            bundleSpkTimestamp: Long,
            bundleOpkId: Int, bundleOpk: ByteArray,
            firstMessage: ByteArray
        ): ByteArray
    }

    data class InitiateResult(
        val session: PackSession,
        val preKeyMessage: ByteArray
    )

    fun encrypt(plaintext: ByteArray): ByteArray {
        return nativeEncrypt(handle, plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        return nativeDecrypt(handle, ciphertext)
    }

    override fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0
        }
    }

    protected fun finalize() = close()

    private external fun nativeDestroy(handle: Long)
    private external fun nativeEncrypt(handle: Long, plaintext: ByteArray): ByteArray
    private external fun nativeDecrypt(handle: Long, ciphertext: ByteArray): ByteArray
}
