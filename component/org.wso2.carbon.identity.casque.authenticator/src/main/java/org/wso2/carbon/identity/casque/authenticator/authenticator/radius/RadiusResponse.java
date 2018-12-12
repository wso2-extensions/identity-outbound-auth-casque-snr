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

import java.io.Serializable;

/**
 * Received response from CASQUE SNR Authentication Server.
 * Holds the response type, challenge and state values.
 * A negative type indicates an error.
 */
public class RadiusResponse implements Serializable {

    private static final long serialVersionUID = 4341535155455223602L;
    private int type;
    private byte[] state;
    private byte[] message;

    public final static int ACCESS_CHALLENGE = 11;
    public final static int ACCESS_REJECT = 3;
    public final static int ACCESS_ACCEPT = 2;
    public final static int ACCESS_REQUEST = 1;
    public final static int PACKET_LENGTH_ERROR = -1;
    public final static int DIGEST_ERROR = -2;
    public final static int ATTRIBUTE_ERROR = -3;
    public final static int RADIUS_ERROR = -4;

    /**
     * Constructor
     * @param type the response type
     */
    public RadiusResponse(int type) {

        this.type = type;
    }

    /**
     * Constructor
     *
     * @param type  the response type
     * @param message the CASQUE SNR challenge string
     * @param state the state value to return with the response to the challenge
     */
    public RadiusResponse(int type, byte[] message, byte[] state) {

        this.type = type;
        this.state = state;
        this.message = message;
    }

    /**
     * Get the CASQUE SNR Challenge
     *
     * @return the challenge or "NONE"
     */
    public String getChallenge() {

        if (message == null) {
            message = new byte[]{'N', 'O', 'N', 'E'};
        }
        return new String(message);
    }

    /**
     * Get the STATE value
     *
     * @return the state value.
     */
    public byte[] getState() {

        return state;
    }

    /**
     * Get the Response Type.
     * ACCESS ACCEPT, ACCESS REJECT, ACCESS CHALLENGE or an Error
     * @return the state value.
     */
    public int getType() {

        return type;
    }

    /**
     * Return the Error as a String.
     * @return the error string.
     */
    public String getError() {

        return getErrorString(type);
    }

    /**
     * Get the Error String from the type value.
     * @param type the error type
     * @return the error string.
     */
    private String getErrorString(int type) {

        switch (type) {
            case PACKET_LENGTH_ERROR:
                return "Packet Length Error";
            case DIGEST_ERROR:
                return "Digest Error";
            case ATTRIBUTE_ERROR:
                return "Attribute Error";
            case RADIUS_ERROR:
                return "RADIUS Error";
            default:
                return "None";
        }
    }
}
