package org.pack.protocol

object PackSealedSender {
    init {
        System.loadLibrary("pack_protocol_jni")
    }

    data class DecryptResult(
        val senderUuid: String,
        val plaintext: ByteArray
    )

    fun encrypt(
        senderIdentityPublic: ByteArray,
        senderIdentityPrivate: ByteArray,
        senderCertificate: ByteArray,
        recipientKey: ByteArray,
        innerMessage: ByteArray,
        currentTime: Long
    ): ByteArray {
        return nativeEncrypt(
            senderIdentityPublic, senderIdentityPrivate,
            senderCertificate, recipientKey, innerMessage, currentTime
        )
    }

    fun decrypt(
        ourIdentityPublic: ByteArray,
        ourIdentityPrivate: ByteArray,
        ciphertext: ByteArray,
        trustRoot: ByteArray,
        currentTime: Long
    ): DecryptResult {
        val resultBytes = nativeDecrypt(
            ourIdentityPublic, ourIdentityPrivate,
            ciphertext, trustRoot, currentTime
        )
        val uuidLen = (resultBytes[0].toInt() and 0xFF shl 24) or
            (resultBytes[1].toInt() and 0xFF shl 16) or
            (resultBytes[2].toInt() and 0xFF shl 8) or
            (resultBytes[3].toInt() and 0xFF)
        val uuid = String(resultBytes, 4, uuidLen, Charsets.UTF_8)
        val plaintext = resultBytes.copyOfRange(4 + uuidLen, resultBytes.size)
        return DecryptResult(uuid, plaintext)
    }

    @JvmStatic
    private external fun nativeEncrypt(
        senderPub: ByteArray, senderPriv: ByteArray,
        senderCert: ByteArray, recipientKey: ByteArray,
        innerMessage: ByteArray, currentTime: Long
    ): ByteArray

    @JvmStatic
    private external fun nativeDecrypt(
        ourPub: ByteArray, ourPriv: ByteArray,
        ciphertext: ByteArray, trustRoot: ByteArray,
        currentTime: Long
    ): ByteArray
}
