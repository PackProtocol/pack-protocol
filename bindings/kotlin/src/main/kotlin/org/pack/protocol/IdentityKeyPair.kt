package org.pack.protocol

class IdentityKeyPair private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("pack_protocol_jni")
        }

        fun generate(): IdentityKeyPair {
            val handle = nativeGenerate()
            return IdentityKeyPair(handle)
        }

        @JvmStatic private external fun nativeGenerate(): Long
    }

    fun getPublicKey(): ByteArray = nativeGetPublicKey(handle)

    fun sign(message: ByteArray): ByteArray = nativeSign(handle, message)

    override fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0
        }
    }

    protected fun finalize() = close()

    private external fun nativeDestroy(handle: Long)
    private external fun nativeGetPublicKey(handle: Long): ByteArray
    private external fun nativeSign(handle: Long, message: ByteArray): ByteArray
}
