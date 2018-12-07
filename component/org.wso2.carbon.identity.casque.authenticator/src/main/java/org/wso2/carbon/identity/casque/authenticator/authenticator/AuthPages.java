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
package org.wso2.carbon.identity.casque.authenticator.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.casque.authenticator.authenticator.radius.RadiusPacket;
import org.wso2.carbon.identity.casque.authenticator.constants.CasqueAuthenticatorConstants;
import org.wso2.carbon.identity.casque.authenticator.exception.CasqueException;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import javax.servlet.http.HttpServletResponse;

class AuthPages implements Serializable {

    private static final long serialVersionUID = 4341535155455223655L;
    private static final Log log = LogFactory.getLog(RadiusPacket.class);
    private void returnHtmlResponse(HttpServletResponse response, String data) throws IOException {

        response.setContentType(CasqueAuthenticatorConstants.CONTENT_TYPE);
        returnResponse(response, data);
    }

    private void returnResponse(HttpServletResponse response, String data) throws IOException {

        response.addHeader(CasqueAuthenticatorConstants.CACHE_CONTROL, "no-cache");
        response.addHeader(CasqueAuthenticatorConstants.PRAGMA, "no-cache");
        response.addHeader(CasqueAuthenticatorConstants.EXPIRES, "0");
        response.setContentLength(data.length());
        response.getOutputStream().print(data);
    }

    /**
     *load the challengPage
     * @param response : http servelet request
     * @param sessionDataKey ,
     * @param challenge ,
     * @throws CasqueException
     */
    void challengePage(HttpServletResponse response, String sessionDataKey, String challenge) throws
            CasqueException {

        try {
            String resource = loadResource(CasqueAuthenticatorConstants.QR_PLAYER);
            if (resource != null) {
                resource = resource.replace(CasqueAuthenticatorConstants.CASQUE_CHALLENGE, challenge);
                resource = resource.replace(CasqueAuthenticatorConstants.SESSION_DATA_KEY, sessionDataKey);
                returnHtmlResponse(response, resource);
            }else{
                log.error("QR player resources are not available");
            }
        } catch (IOException e) {
            throw new CasqueException("Failed to load the challenge page.", e);
        }
    }

    /**
     * load the casque QR player
     * @param path ,
     * @return ,
     * @throws CasqueException
     */
    private String loadResource(String path) throws
            CasqueException {

        InputStream in = AuthPages.class.getClassLoader().getResourceAsStream(path);
        if (in != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                char[] buffer = new char[20000];
                int len = reader.read(buffer, 0, 20000);
                return new String(buffer, 0, len);
            } catch (IOException e) {
                throw new CasqueException("Failed to load the casque QR player.", e);
            }
        }
        return null;
    }
}
