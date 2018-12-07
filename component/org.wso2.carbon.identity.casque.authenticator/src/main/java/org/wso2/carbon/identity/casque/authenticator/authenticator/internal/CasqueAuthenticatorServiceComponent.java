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
package org.wso2.carbon.identity.casque.authenticator.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.casque.authenticator.authenticator.CasqueAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.casque.CasqueAuthenticator.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class CasqueAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CasqueAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        try {
            CasqueAuthenticator casqueAuth = new CasqueAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), casqueAuth,
                    null);
            if (log.isDebugEnabled()) {
                log.debug(" CasqueAuthenticator bundle is activated ");
            }
        } catch (Throwable e) {
            log.error(" CasqueAuthenticator bundle activation Failed ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug(" CasqueAuthenticator bundle is deactivated ");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        CasqueAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }

    protected void setRealmService(RealmService realmService) {

        CasqueAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }
}
