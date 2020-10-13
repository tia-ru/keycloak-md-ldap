/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ru.intertrust.keycloak.ldap_md;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.ldap.LDAPIdentityStoreRegistry;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;

import java.util.Map;

/**
 * @author Ilya Tugushev
 */
public class MdLDAPStorageProviderFactory extends LDAPStorageProviderFactory {

    private LDAPIdentityStoreRegistry ldapStoreRegistry;

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.ldapStoreRegistry = new LDAPIdentityStoreRegistry();
    }

    @Override
    public void close()
    {
        this.ldapStoreRegistry = null;
        super.close();
    }

    @Override
    public MdLDAPStorageProvider create(KeycloakSession session, ComponentModel model) {
        Map<ComponentModel, LDAPConfigDecorator> configDecorators = getLDAPConfigDecorators(session, model);

        LDAPIdentityStore ldapIdentityStore = this.ldapStoreRegistry.getLdapStore(session, model, configDecorators);
        return new MdLDAPStorageProvider(this, session, model, ldapIdentityStore);
    }

    protected MdSPNEGOAuthenticator createSPNEGOAuthenticator(String spnegoToken, CommonKerberosConfig kerberosConfig) {
        KerberosServerSubjectAuthenticator kerberosAuth = createKerberosSubjectAuthenticator(kerberosConfig);
        return new MdSPNEGOAuthenticator(kerberosConfig, kerberosAuth, spnegoToken);
    }

 }
