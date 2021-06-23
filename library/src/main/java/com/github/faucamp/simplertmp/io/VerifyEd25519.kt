package com.github.faucamp.simplertmp.io

import android.util.Base64
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.SignatureException

class VerifyEd25519 {
    private var engine: EdDSAEngine? = null

    constructor(publicKey: String?) {
        engine = EdDSAEngine()
        val publicKeySpec = EdDSAPublicKeySpec(
                Base64.decode(publicKey, Base64.DEFAULT),
                EdDSANamedCurveTable.ED_25519_CURVE_SPEC
        )
        engine!!.initVerify(EdDSAPublicKey(publicKeySpec))
    }

    @Throws(SignatureException::class)
    fun verify(data: ByteArray?, signature: String?): Boolean {
        val sign =
                Base64.decode(signature, Base64.DEFAULT)
        return engine!!.verifyOneShot(data, sign)
    }
}