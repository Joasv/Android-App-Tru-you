package com.github.faucamp.simplertmp.packets;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import com.coremedia.iso.Hex;
import com.github.faucamp.simplertmp.io.ChunkStreamInfo;
import com.github.faucamp.simplertmp.io.SignEd25519;


/**
 *
 * @author francois, leo
 */
public abstract class RtmpPacket {

    private static final String TAG = "RTMPPACKET";
    protected RtmpHeader header;

    public RtmpPacket(RtmpHeader header) {
        this.header = header;
    }

    public RtmpHeader getHeader() {
        return header;
    }
    
    public abstract void readBody(InputStream in) throws IOException;    
    
    protected abstract void writeBody(OutputStream out) throws IOException;

    protected abstract byte[] array();

    protected abstract int size();
    public byte[] getPacketData() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        return this instanceof ContentData ? array() : baos.toByteArray();
    }

    public void writeTo(OutputStream out, final int chunkSize, final ChunkStreamInfo chunkStreamInfo, MessageDigest md, OutputStream dout, SignEd25519 signer, String PUBLIC_KEY, boolean sign) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeBody(baos);
        byte[] body = this instanceof ContentData ? array() : baos.toByteArray();

        if (sign) {

            String hexbody = null;

            String hexStringBody = Hex.encodeHex(this.getPacketData());
            String[] bodySplitted = {};
            bodySplitted = hexStringBody.split("0000000000000000000000000000000000");
            hexbody = bodySplitted[0];

            String hashString = String.format("%040x", new BigInteger(1,  md.digest(hexbody.getBytes("UTF-8"))));

            String s = null;
            try {
                s = "{" + PUBLIC_KEY + "," + this.getHeader().getAbsoluteTimestamp() +"," + signer.signToBase64(hashString.getBytes("UTF-8")) + "}";
                byte [] fullToSend = s.getBytes();
                //RTCP send / write
                dout.write(fullToSend);
                md.reset();
            } catch (SignatureException e) {
                e.printStackTrace();
            }
        }



        int length = this instanceof ContentData ? size() : body.length;
        header.setPacketLength(length);
        // Write header for first chunk
        header.writeTo(out, RtmpHeader.ChunkType.TYPE_0_FULL, chunkStreamInfo);
        int pos = 0;
        while (length > chunkSize) {
            // Write packet for chunk
            out.write(body, pos, chunkSize);
            length -= chunkSize;
            pos += chunkSize;
            // Write header for remain chunk
            header.writeTo(out, RtmpHeader.ChunkType.TYPE_3_RELATIVE_SINGLE_BYTE, chunkStreamInfo);
        }
        out.write(body, pos, length);
    }
}
