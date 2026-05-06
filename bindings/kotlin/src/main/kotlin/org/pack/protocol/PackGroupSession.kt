package org.pack.protocol

class PackGroupSession private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("pack_protocol_jni")
        }

        fun createSender(distributionId: String): CreateSenderResult {
            val handle = nativeCreateSender(distributionId)
            val distMsg = nativeCreateSenderGetDistribution(distributionId)
            return CreateSenderResult(PackGroupSession(handle), distMsg)
        }

        fun createReceiver(distributionId: String, distributionMessage: ByteArray): PackGroupSession {
            val handle = nativeCreateReceiver(distributionId, distributionMessage)
            return PackGroupSession(handle)
        }

        @JvmStatic private external fun nativeCreateSender(distributionId: String): Long
        @JvmStatic private external fun nativeCreateSenderGetDistribution(distributionId: String): ByteArray
        @JvmStatic private external fun nativeCreateReceiver(distributionId: String, distributionMessage: ByteArray): Long
    }

    data class CreateSenderResult(
        val session: PackGroupSession,
        val distributionMessage: ByteArray
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
