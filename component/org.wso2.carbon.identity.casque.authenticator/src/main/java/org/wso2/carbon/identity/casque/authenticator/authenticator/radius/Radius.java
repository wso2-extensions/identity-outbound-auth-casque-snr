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
import org.wso2.carbon.identity.casque.authenticator.exception.CasqueException;

import java.io.IOException;
import java.io.Serializable;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

/**
 * Communicate with the CASQUE SNR Authentication Server using the RADIUS protocol
 */
public class Radius implements Serializable {

    private static final Log log = LogFactory.getLog(Radius.class);
    private static final long serialVersionUID = 4341535155455223601L;
    private static DatagramSocket socket = null;

    /**
     * Send Send Request to CASQUE SNR Authentication Server
     * @param uid the user name to send
     * @param pass the password to send
     * @param state the RADIUS state value to send
     * @return Challenge, Accept, Reject or an Error.
     * @throws CasqueException throws CasqueException If DatagramSocket creation fails
     */
    public static RadiusResponse sendRequest(String uid, String pass, byte[] state) throws CasqueException {

        CasqueConfig.loadConfig();

        byte[] buffer = RadiusPacket.formRequestPacket(uid, pass, state);
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, CasqueConfig.casqueAddress,
                CasqueConfig.casquePort);
        try {
            if (socket == null) {
                socket = new DatagramSocket(CasqueConfig.localPort);
                socket.setSoTimeout(1000);
            }
        } catch (SocketException e) {
            throw new CasqueException("Error creating the Datagram Socket. ", e);
        }
        DatagramPacket responsePacket;
        int tries = 3;
        while (tries-- != 0) {
            try {
                byte[] b = new byte[512];
                responsePacket = new DatagramPacket(b, b.length);
                socket.setSoTimeout(1000);
                socket.send(packet);
                socket.setSoTimeout(2500);
                socket.receive(responsePacket);
                return RadiusPacket.parsePacket(responsePacket);
            } catch (IOException ioe) {
                log.error("Could not get the Datagram responsePacket",ioe);
            }
        }
        log.error("Error contacting the CASQUE SNR Server");
        return new RadiusResponse(RadiusResponse.RADIUS_ERROR);
    }
}
