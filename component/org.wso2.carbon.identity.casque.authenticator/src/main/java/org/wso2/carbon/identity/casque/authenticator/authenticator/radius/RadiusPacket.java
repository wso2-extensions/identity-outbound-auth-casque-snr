/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.casque.authenticator.authenticator.radius;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.casque.authenticator.authenticator.CasqueConfig;

import java.io.Serializable;
import java.net.DatagramPacket;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class RadiusPacket implements Serializable {

    private static final Log log = LogFactory.getLog(RadiusPacket.class);
    private static final long serialVersionUID = 4341535155455223600L;
    private final static byte USER_NAME = 1;
    private final static byte USER_PASSWORD = 2;
    private final static byte SERVICE_TYPE = 6;
    private final static byte AUTHENTICATE_ONLY = 8;
    private final static byte REPLY_MESSAGE = 18;
    private final static byte STATE = 24;

    private static byte[] reqAuth = null;
    private static byte[] buffer = null;
    private static SecureRandom random = new SecureRandom();
    private static MessageDigest md5Digest = null;
    private static int currentID = 1; //random.nextInt(256);

    static {
        reqAuth = getRequestAuthenticator();
        random.setSeed(System.currentTimeMillis());
        byte[] seed = random.generateSeed(17);
        random.setSeed(seed);
    }

    public RadiusPacket() {

    }

    private static MessageDigest getMD5() {

        if (md5Digest == null) {
            try {
                md5Digest = MessageDigest.getInstance("MD5");
            } catch (java.security.NoSuchAlgorithmException e) {
                return null;
            }
        }

        MessageDigest md = null;
        try {
            md = (MessageDigest) md5Digest.clone();
        } catch (CloneNotSupportedException e) {
            log.error("Error while cloning the message digest. ", e);
        }
        return md;
    }

    private static byte[] getBuffer(int id) {

        byte[] b = new byte[buffer.length];
        System.arraycopy(buffer, 0, b, 0, buffer.length);
        b[1] = (byte) (id & 0xff);
        return b;
    }

    private static byte getNextID() {

        ++currentID;
        currentID &= 0xff;
        return (byte) (currentID & 0xff);
    }

    public static byte[] getBuffer(int id, byte[] state) {

        if (state == null) {
            return getBuffer(id);
        }
        int offset = buffer.length;
        byte[] b = new byte[offset + state.length + 2];
        System.arraycopy(buffer, 0, b, 0, offset);
        offset = addState(b, offset, state);
        b[1] = (byte) (id & 0xff);
        b[2] = (byte) ((offset >> 8) & 0xff);
        b[3] = (byte) (offset & 0xff);
        return b;
    }

    private static int addString(byte[] tempBuffer, int offset, String str, byte type) {

        if (str == null) return offset;
        byte[] strBytes = str.getBytes();
        return addByteArray(tempBuffer, offset, strBytes, type);
    }

    private static int addByteArray(byte[] tempBuffer, int offset, byte[] array, byte type) {

        int length = array.length;
        tempBuffer[offset++] = type;                // Attribute type
        tempBuffer[offset++] = (byte) (length + 2);    // Length of attribute
        System.arraycopy(array, 0, tempBuffer, offset, length);
        return offset + length;
    }

    private static int addUserName(byte[] tempBuffer, int offset, String uid) {

        if (uid == null) return offset;
        return addString(tempBuffer, offset, uid, USER_NAME);
    }

    private static int addPassword(byte[] tempBuffer, int offset, String password) {

        if (password == null) return offset;

        byte[] pass = password.getBytes();
        int passLength = (pass.length + 15) & ~0xf;
        System.arraycopy(pass, 0, tempBuffer, offset + 2, pass.length);
        MessageDigest messageDigest = getMD5();

        if (messageDigest != null) {
            messageDigest.update(CasqueConfig.radiusSecret);

            messageDigest.update(tempBuffer, 4, 16);

            byte[] digest = messageDigest.digest();

            tempBuffer[offset++] = USER_PASSWORD;                // USER_PASSWORD
            tempBuffer[offset++] = (byte) (passLength + 2);     // Length of USER_PASSWORD attribute
            int i;
            for (i = 0; i < 16; i++) {
                tempBuffer[i + offset] ^= digest[i];
            }
            while (i < passLength) {
                int k = i + offset;
                messageDigest.reset();
                messageDigest.update(CasqueConfig.radiusSecret);
                messageDigest.update(tempBuffer, k - 16, 16);
                digest = messageDigest.digest();
                for (int j = 0; j < 16; j++) {
                    tempBuffer[k + j] ^= digest[j];
                }
                i += 16;
            }
            return offset + passLength;
        }
        return -1;
    }

    private static int addServiceType(byte[] tempBuffer, int offset) {

        tempBuffer[offset++] = SERVICE_TYPE;    // SERVICE_TYPE
        tempBuffer[offset++] = 6;    // Length of SERVICE_TYPE attribute
        tempBuffer[offset++] = 0;    //
        tempBuffer[offset++] = 0;    //
        tempBuffer[offset++] = 0;    //
        tempBuffer[offset++] = AUTHENTICATE_ONLY;    // AUTHENTICATE_ONLY
        return offset;
    }

    private static int addState(byte[] buf, int offset, byte[] state) {

        if (state == null) return offset;
        return addByteArray(buf, offset, state, STATE);
    }

    static byte[] formRequestPacket(String uid, String pass, byte[] state) {

        byte[] tempBuffer = new byte[256];
        tempBuffer[0] = 1;   // ACCESS_REQUEST;
        tempBuffer[1] = getNextID();
        System.arraycopy(reqAuth, 0, tempBuffer, 4, 16);
        int offset = 20;
        if (uid != null && uid.length() > 0)
            offset = addUserName(tempBuffer, offset, uid);
        if (pass != null && pass.length() > 0)
            offset = addPassword(tempBuffer, offset, pass);
        if (state != null && state.length > 0)
            offset = addState(tempBuffer, offset, state);

        offset = addServiceType(tempBuffer, offset); //AUTHENTICATE_ONLY

        tempBuffer[2] = (byte) ((offset >> 8) & 0xff);
        tempBuffer[3] = (byte) (offset & 0xff);
        byte[] b = new byte[offset];
        System.arraycopy(tempBuffer, 0, b, 0, offset);
        return b;
    }

    private static byte[] getRequestAuthenticator() {

        byte[] r = new byte[16];
        random.nextBytes(r);
        return r;
    }

    private static byte[] getAttribute(int type, byte[][] attributes, byte[] packetData) {

        for (byte[] attribute : attributes) {
            if (attribute[0] == type) {
                byte[] att = new byte[(attribute[2] & 0xff)];
                System.arraycopy(packetData, attribute[1], att, 0, att.length);
                return att;
            }
        }
        return null;
    }

    private static void urlEncode(byte[] b) {

        if (b != null) {
            for (int i = 0; i < b.length; ++i) {
                if (b[i] == '+') {
                    b[i] = '-';
                } else {
                    if (b[i] == '/') {
                        b[i] = '_';
                    }
                }
            }
        }
    }

    static RadiusResponse parsePacket(DatagramPacket packet) {

        int packetLength = packet.getLength();
        if ((packetLength < 20) || (packetLength > 4096)) {
            return new RadiusResponse(RadiusResponse.PACKET_LENGTH_ERROR);
        }

        byte[] tempBuffer = packet.getData();
        int dataLength = (tempBuffer[2] & 0xff) * 256 + (tempBuffer[3] & 0xff);

        if (packetLength < dataLength) {
            return new RadiusResponse(RadiusResponse.PACKET_LENGTH_ERROR);
        }

        byte[] challenge = null;
        byte[] state = null;
        byte[] digest = new byte[16];
        System.arraycopy(tempBuffer, 4, digest, 0, 16);
        System.arraycopy(reqAuth, 0, tempBuffer, 4, 16);

        MessageDigest md = getMD5();

        if (md != null) {
            md.update(tempBuffer, 0, dataLength);

            md.update(CasqueConfig.radiusSecret);

            byte[] digest2 = md.digest();

            for (int i = 0; i < 16; i++) {
                if (digest[i] != digest2[i]) {
                    return new RadiusResponse(RadiusResponse.DIGEST_ERROR);
                }
            }

            int offset = 20;

            int index = 0;
            byte[][] attributes = new byte[16][3];

            while ((offset < dataLength) && (index < attributes.length)) {
                attributes[index][0] = tempBuffer[offset];
                attributes[index][1] = (byte) (offset + 2);
                int l = (tempBuffer[offset + 1] & 0xff);
                if (l < 2) {
                    return new RadiusResponse(RadiusResponse.ATTRIBUTE_ERROR);
                }
                attributes[index][2] = (byte) (l - 2);
                offset += l;
                index++;
            }

            challenge = getAttribute(REPLY_MESSAGE, attributes, tempBuffer);
            urlEncode(challenge);
            state = getAttribute(STATE, attributes, tempBuffer);
        }
        return new RadiusResponse(tempBuffer[0], challenge, state);
    }
}
