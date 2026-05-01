package org.pack.protocol

class GroupCipher private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("pack_protocol_jni")
        }

        fun create(): GroupCipher {
            return GroupCipher(nativeCreateRecord())
        }

        @JvmStatic private external fun nativeCreateRecord(): Long
    }

    fun createDistributionMessage(distributionId: String): ByteArray {
        return nativeCreateDistributionMessage(handle, distributionId.toByteArray(Charsets.UTF_8))
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        return nativeEncrypt(handle, plaintext)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        return nativeDecrypt(handle, ciphertext)
    }

    override fun close() {
        if (handle != 0L) {
            nativeDestroyRecord(handle)
            handle = 0
        }
    }

    protected fun finalize() = close()

    private external fun nativeDestroyRecord(handle: Long)
    private external fun nativeCreateDistributionMessage(handle: Long, distributionId: ByteArray): ByteArray
    private external fun nativeEncrypt(handle: Long, plaintext: ByteArray): ByteArray
    private external fun nativeDecrypt(handle: Long, ciphertext: ByteArray): ByteArray
}
