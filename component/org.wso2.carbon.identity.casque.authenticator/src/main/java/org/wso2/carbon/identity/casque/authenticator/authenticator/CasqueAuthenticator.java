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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.casque.authenticator.constants.CasqueAuthenticatorConstants;
import org.wso2.carbon.identity.casque.authenticator.authenticator.internal.CasqueAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.casque.authenticator.exception.CasqueException;
import org.wso2.carbon.identity.casque.authenticator.authenticator.radius.Radius;
import org.wso2.carbon.identity.casque.authenticator.authenticator.radius.RadiusResponse;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CasqueAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4341535155455223654L;
    private static final Log log = LogFactory.getLog(CasqueAuthenticator.class);
    private static final String CASQUE_SNR_CLAIM = "http://wso2.org/claims/identity/casqueSnrToken";
    private static final String TOKEN_ID_FORMAT = "^[a-fA-F0-9]{3} [0-9]{6}$";  // e.g. "FFF 000001"
    private static final AuthPages authPages = new AuthPages();

    /**
     *  Getting tokenId from the UserStoreManager.
     * @param userName ,
     * @return ,
     * @throws CasqueException
     */
    private String getCasqueTokenId(String userName) throws CasqueException {

        try {
            UserStoreManager userStoreManager = CasqueAuthenticatorServiceDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(userName))
                    .getUserStoreManager();

            // Getting the Token ID assigned to userName
            Map<String, String> tokenIdMap = userStoreManager.getUserClaimValues(userName,
                    new String[]{CASQUE_SNR_CLAIM}, null);

            if (tokenIdMap == null || tokenIdMap.get(CASQUE_SNR_CLAIM) == null) {
                throw new CasqueException("Token ID is null for user:" + userName);
            }
            String tokenId = tokenIdMap.get(CASQUE_SNR_CLAIM);
            if (tokenId.matches(TOKEN_ID_FORMAT)) {
                return tokenId;
            }
            throw new CasqueException(tokenId + "is a bad formatted Token ID for User" + userName);

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.info("User Store Exception:" + e.getMessage());
        }
        throw new CasqueException("Unable to get token id for user: " + userName);
    }

    /**
     * Initiate the authentication request
     * @param request,
     * @param response,
     * @param context,
     * @return
     * @throws AuthenticationFailedException
     * @throws CasqueException
     */
    private AuthenticatorFlowStatus start(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String userName = request.getParameter(CasqueAuthenticatorConstants.USER_NAME);

            if (StringUtils.isEmpty(userName)) {
                throw new CasqueException("userName is null");
            }

            context.setProperty(CasqueAuthenticatorConstants.USER_NAME, userName);
            String tokenId = getCasqueTokenId(userName);
            String tokenIdPlusName = tokenId + userName;

            context.setProperty(CasqueAuthenticatorConstants.RADIUS_STATE, null);
            // Initial Access Request, fixed user,  token ID + username as the password
            // Send request as Datagram packet
            RadiusResponse radiusResponse = Radius.sendRequest("CASQUE SNR", tokenIdPlusName, null);
            int radiusResponseType = radiusResponse.getType();

            if (radiusResponseType == RadiusResponse.ACCESS_CHALLENGE) { // Got a challenge
                context.setProperty(CasqueAuthenticatorConstants.RADIUS_STATE, radiusResponse.getState());
                String challenge = radiusResponse.getChallenge();
                String contextIdentifier = context.getContextIdentifier();
                authPages.challengePage(response, contextIdentifier, challenge);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }

            clearProperties(context);

            if (radiusResponseType == RadiusResponse.ACCESS_REJECT) {
                throw new InvalidCredentialsException(
                        " User authentication failed due to invalid credentials ", User.getUserFromUserName(userName));
            }

            throw new InvalidCredentialsException(" User authentication failed due to " + radiusResponse.getError(),
                    User.getUserFromUserName(userName));
        } catch (CasqueException ce) {
            throw new AuthenticationFailedException(ce.getMessage(), ce);
        }
    }

    private void clearProperties(AuthenticationContext context) {

        Map<String, Object> props = new HashMap<>();
        context.setProperties(props);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            try {
                processLogoutResponse(request, response, context);
            } catch (UnsupportedOperationException e) {
                if (log.isDebugEnabled()) {
                    log.error("Ignoring UnsupportedOperationException", e);
                }
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        byte[] radiusState = (byte[]) context.getProperty(CasqueAuthenticatorConstants.RADIUS_STATE);

        if (radiusState == null) { // Initial request, get a challenge
            AuthenticatorFlowStatus status = null;
            try {
                status = start(request, response, context);
            } catch (AuthenticationFailedException e) {

                throw new AuthenticationFailedException("Error Accord while sending request  ", e);
            }
            context.setCurrentAuthenticator(getName());
            return status;
        }
        // radiusState is not null so handle the response to the challenge
        context.setProperty(CasqueAuthenticatorConstants.RADIUS_STATE, null);

        String action = request.getParameter(CasqueAuthenticatorConstants.BTN_ACTION);
        if (action != null && "Login".equals(action)) { // action can be null, Login or Cancel

            String userName = (String) context.getProperty(CasqueAuthenticatorConstants.USER_NAME);
            String challengeResponse = request.getParameter(CasqueAuthenticatorConstants.RESPONSE);
            try {
                // Send the response to the CASQUE Server
                RadiusResponse radiusResponse = Radius.sendRequest(userName, challengeResponse, radiusState);
                int radiusResponseType = radiusResponse.getType();

                if (radiusResponseType == RadiusResponse.ACCESS_CHALLENGE) { // Another challenge.
                    context.setProperty(CasqueAuthenticatorConstants.RADIUS_STATE, radiusResponse.getState());
                    String challenge = radiusResponse.getChallenge();
                    String contextIdentifier = context.getContextIdentifier();
                    authPages.challengePage(response, contextIdentifier, challenge);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                }

                clearProperties(context);

                if (radiusResponseType == RadiusResponse.ACCESS_ACCEPT) { // Authentication Pass.
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName));
                    String tokenId = getCasqueTokenId(userName);
                    log.debug("CASQUE Authentication PASS for " + userName + "with Token" + tokenId);
                    request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }

                if (radiusResponseType == RadiusResponse.ACCESS_REJECT) { // Authentication Failed.
                    throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                            User.getUserFromUserName(userName));
                }

                throw new InvalidCredentialsException("User authentication failed due to" +
                        radiusResponse.getError(),
                        User.getUserFromUserName(userName));

            } catch (CasqueException ce) {
                throw new AuthenticationFailedException(ce.getMessage(), ce);
            }
        }

        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

    }

    @Override
    public boolean canHandle(HttpServletRequest req) {

        return true;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return false;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest req) {

        return req.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {

        return CasqueAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return CasqueAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
