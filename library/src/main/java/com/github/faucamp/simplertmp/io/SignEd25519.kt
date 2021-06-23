package com.github.faucamp.simplertmp.io


import android.util.Base64
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import java.security.SignatureException

class SignEd25519 {
    private var engine: EdDSAEngine? = null

    constructor(privateKey: String?) {
        engine = EdDSAEngine()
        val privateKeySpec = EdDSAPrivateKeySpec(
                Base64.decode(privateKey, Base64.NO_WRAP),
                EdDSANamedCurveTable.ED_25519_CURVE_SPEC
        )
        engine!!.initSign(EdDSAPrivateKey(privateKeySpec))
    }

    @Throws(SignatureException::class)
    fun signToBase64(data: ByteArray?): String? {
        val signature = engine!!.signOneShot(data)
        return Base64.encodeToString(signature, Base64.NO_WRAP)
                .replace(" ", "")
                .replace("\n", "")
    }

    @Throws(SignatureException::class)
    fun sign(data: ByteArray?): ByteArray? {
        return engine!!.signOneShot(data);
    }

    @Throws(SignatureException::class)
    fun signBase64(data: String?): String? {
        return signToBase64(Base64.decode(data, Base64.NO_WRAP))
    }
}