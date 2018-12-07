/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.casque.authenticator.authenticator;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.Test;
import org.powermock.reflect.Whitebox;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.powermock.core.classloader.annotations.PrepareForTest;

import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.casque.authenticator.exception.CasqueException;
import org.wso2.carbon.identity.casque.authenticator.authenticator.radius.Radius;
import org.wso2.carbon.identity.casque.authenticator.authenticator.radius.RadiusResponse;
import org.wso2.carbon.identity.casque.authenticator.constants.CasqueAuthenticatorConstants;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.casque.authenticator.authenticator.internal.CasqueAuthenticatorServiceDataHolder;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({CasqueAuthenticatorServiceDataHolder.class, IdentityTenantUtil.class, RadiusResponse.class,
        Radius.class, AuthenticatedUser.class, User.class})

public class CasqueAuthenticatorTest {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private CasqueAuthenticator casqueAuthenticator;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    CasqueAuthenticatorServiceDataHolder casqueAuthenticatorServiceDataHolder;

    @Mock
    RealmService realmService;

    @Mock
    UserRealm tenantUserRealm;

    @Mock
    private AuthenticationContext context;

    @Mock
    private RadiusResponse radiusResponse;

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Mock
    private User user;

    @Mock
    private Map mockMap;

    @BeforeMethod
    public void setUp() {

        casqueAuthenticator = new CasqueAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for GetName() method.")
    public void testGetName() {

        Assert.assertEquals(casqueAuthenticator.getName(),
                CasqueAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for RetryAuthenticationEnabled() method.")
    protected void testRetryAuthenticationEnabled() {

        Assert.assertFalse(casqueAuthenticator.retryAuthenticationEnabled());
    }

    @Test(description = "Test case for GetFriendlyName() method.")
    public void testGetFriendlyName() {

        Assert.assertEquals(casqueAuthenticator.getFriendlyName(),
                CasqueAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for canHandle() method.")
    public void testCanHandle() {

        Assert.assertTrue(casqueAuthenticator.canHandle(httpServletRequest));

    }

    @Test(description = "Test case for testGetCasqueTokenId() method.")
    public void testGetCasqueTokenId() throws Exception {

        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);

        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn("FFF 000001");
        Whitebox.setInternalState(CasqueAuthenticatorServiceDataHolder.class, "instance",
                casqueAuthenticatorServiceDataHolder);
        Assert.assertEquals(Whitebox.invokeMethod(casqueAuthenticator, "getCasqueTokenId"
                , ""), "FFF 000001");

    }

    @Test(expectedExceptions = {CasqueException.class})
    public void testGetCasqueTokenIdforTokenNull() throws Exception {

        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);

        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);

        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn(" ");
        Whitebox.invokeMethod(casqueAuthenticator, "getCasqueTokenId", "");

    }

    @Test(expectedExceptions = {CasqueException.class})
    public void testGetCasqueTokenIdforToknIdBadFormat() throws Exception {

        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);
        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn("FFF 0000001");
        Whitebox.invokeMethod(casqueAuthenticator, "getCasqueTokenId", "");

    }

    @Test(expectedExceptions = {CasqueException.class})
    public void testGetCasqueTokenIdforToknIdForUnableToGetTokenId() throws Exception {

        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);
        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn(" ");
        Whitebox.invokeMethod(casqueAuthenticator, "getCasqueTokenId", "");

    }

    @Test(description = "Test case for successful logout request.")
    public void testProcessLogoutRequest() throws Exception {

        when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = casqueAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }



    @Test(description = "Test case for process() method for ForRadiusStateNull()")
    public void testProcessRadiusState5() throws Exception {

        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(Radius.class);

        int radiusResponseType = 11;

        when(context.isLogoutRequest()).thenReturn(false);
        when(context.getProperty(anyString())).thenReturn(null);
        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn("FFF 000001");
        when(httpServletRequest.getParameter(anyString())).thenReturn("Login");
        when(context.getProperty(CasqueAuthenticatorConstants.USER_NAME)).thenReturn("casque1");
        when(httpServletRequest.getParameter(CasqueAuthenticatorConstants.RESPONSE)).thenReturn("ACCESS_CHALLENGE ");
        when(Radius.sendRequest(anyString(), anyString(), (byte[]) anyObject())).thenReturn(radiusResponse);
        when(radiusResponse.getType()).thenReturn(radiusResponseType);
        AuthenticatorFlowStatus status = casqueAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method for Authentication Pass.")
    public void testProcessRadiusState2() throws Exception {

        byte[] radiusState = new byte[1];
        radiusState[0] = 10;
        int radiusResponseType = 2;

        mockStatic(Radius.class);
        mockStatic(AuthenticatedUser.class);
        mockStatic(CasqueAuthenticatorServiceDataHolder.class);
        mockStatic(IdentityTenantUtil.class);

        when(context.isLogoutRequest()).thenReturn(false);
        when(context.getProperty(anyString())).thenReturn(radiusState);
        when(httpServletRequest.getParameter(anyString())).thenReturn("Login");
        when(context.getProperty(CasqueAuthenticatorConstants.USER_NAME)).thenReturn("casque1");
        when(httpServletRequest.getParameter(CasqueAuthenticatorConstants.RESPONSE)).thenReturn("ACCESS_ACCEPT");
        when(Radius.sendRequest(anyString(), anyString(), (byte[]) anyObject())).thenReturn(radiusResponse);
        when(radiusResponse.getType()).thenReturn(radiusResponseType);
        when(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(authenticatedUser);
        when(CasqueAuthenticatorServiceDataHolder.getInstance()).thenReturn(casqueAuthenticatorServiceDataHolder);
        when(casqueAuthenticatorServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(IdentityTenantUtil.getTenantIdOfUser(anyString())))
                .thenReturn(tenantUserRealm);
        when(tenantUserRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), anyString())).thenReturn(mockMap);
        when(mockMap.get(anyString())).thenReturn("FFF 000001");
        when(userStoreManager.getUserClaimValue(anyString(), anyString(), anyString())).thenReturn("FFF 000001");
        AuthenticatorFlowStatus status = casqueAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method for  Authentication Failed.")
    public void testProcessRadiusState3() throws Exception {

        byte[] radiusState = new byte[1];
        radiusState[0] = 10;
        int radiusResponseType = 3;
        mockStatic(Radius.class);
        mockStatic(User.class);

        when(context.isLogoutRequest()).thenReturn(false);
        when(context.getProperty(anyString())).thenReturn(radiusState);
        when(httpServletRequest.getParameter(anyString())).thenReturn("Login");
        when(context.getProperty(CasqueAuthenticatorConstants.USER_NAME)).thenReturn("casque1");
        when(httpServletRequest.getParameter(CasqueAuthenticatorConstants.RESPONSE)).thenReturn("ACCESS_REJECT");
        when(Radius.sendRequest(anyString(), anyString(), (byte[]) anyObject())).thenReturn(radiusResponse);
        when(radiusResponse.getType()).thenReturn(radiusResponseType);
        when((String) context.getProperty(CasqueAuthenticatorConstants.USER_NAME)).thenReturn("casque1");
        when(User.getUserFromUserName(anyString())).thenReturn(user);
        Assert.assertEquals(User.getUserFromUserName(anyString()), user);

    }

    @Test(description = "Test case for process() method for login fail")
    public void testProcessRadiusStateLoginFail() throws Exception {

        byte[] radiusState = new byte[1];
        radiusState[0] = 10;
        mockStatic(Radius.class);

        when(context.isLogoutRequest()).thenReturn(false);
        when(context.getProperty(anyString())).thenReturn(radiusState);
        when(httpServletRequest.getParameter(anyString())).thenReturn(null);
        AuthenticatorFlowStatus status = casqueAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

}