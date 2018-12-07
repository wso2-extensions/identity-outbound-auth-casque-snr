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

import org.wso2.carbon.identity.casque.authenticator.constants.CasqueAuthenticatorConstants;
import org.wso2.carbon.identity.casque.authenticator.exception.CasqueException;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.InetAddress;

public class CasqueConfig {

    public static byte[] radiusSecret = null;
    public static InetAddress casqueAddress = null;
    public static int casquePort = 0;
    public static int localPort = 0;
    private static boolean configLoaded = false;

    private static void parseLine(String line) throws IOException {

        if (line.startsWith("#")) {
            return;
        }
        if (line.startsWith(CasqueAuthenticatorConstants.CONF_CASQUE_SECRET)) {
            radiusSecret = line.substring(CasqueAuthenticatorConstants.CONF_CASQUE_SECRET.length()).trim().getBytes();
            return;
        }
        if (line.startsWith(CasqueAuthenticatorConstants.CONF_CASQUE_ADDRESS)) {
            String server = line.substring(CasqueAuthenticatorConstants.CONF_CASQUE_ADDRESS.length()).trim();
            casqueAddress = InetAddress.getByName(server);
            return;
        }
        if (line.startsWith(CasqueAuthenticatorConstants.CONF_CASQUE_PORT)) {
            String port = line.substring(CasqueAuthenticatorConstants.CONF_CASQUE_PORT.length()).trim();
            casquePort = Integer.parseInt(port);
            return;
        }
        if (line.startsWith(CasqueAuthenticatorConstants.CONF_LOCAL_PORT)) {
            String port = line.substring(CasqueAuthenticatorConstants.CONF_LOCAL_PORT.length()).trim();
            localPort = Integer.parseInt(port);
        }
    }

    public static void loadConfig() throws CasqueException {

        if (!configLoaded) {
            try {
                File casqueConf = new File(CarbonUtils.getCarbonConfigDirPath() + File.separator
                        + CasqueAuthenticatorConstants.CONF_FILE);
                InputStream in = new FileInputStream(casqueConf);
                BufferedReader br = new BufferedReader(new InputStreamReader(in));
                String line;
                while ((line = br.readLine()) != null) {
                    parseLine(line);
                }
                br.close();
                configLoaded = true;
            } catch (IOException e) {
                throw new CasqueException(" Failed to load Config file " + e.getMessage());
            }
        }
    }
}
