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

package ru.intertrust.keycloak.ldap_md.mappers;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import ru.intertrust.keycloak.ldap_md.MdLDAPConstants;
import ru.intertrust.keycloak.ldap_md.MdLDAPStorageProvider;
import ru.intertrust.keycloak.ldap_md.MdLDAPUtils;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KerberosLDAPAttributeMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(KerberosLDAPAttributeMapper.class);

    public static final String LDAP_USER_ATTRIBUTE_NAME = "ldap.username.attribute.name";

    public static final String LDAP_DOMAIN_ATTRIBUTE_NAME = "ldap.domain.attribute.name";

    private final KerberosLDAPAttributeMapperConfig mapperConfig;
    private final List<String> kerberosRealms;

    public KerberosLDAPAttributeMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
        kerberosRealms = MdLDAPUtils.getKerberosRealms(getLdapProvider().getLDAPProviderKerberosConfig());
        mapperConfig = new KerberosLDAPAttributeMapperConfig(mapperModel);
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {

    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        UserStorageProviderModel model = getLdapProvider().getModel();
        boolean isAllowKerberosAuthentication = getLdapProvider().getLDAPProviderKerberosConfig().isAllowKerberosAuthentication();
        if (model.isImportEnabled() && isAllowKerberosAuthentication) {
            String krbPrincipal = extractKrbPrincipal(ldapUser);
            String username = user.getUsername();
            FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(model.getProviderId(), krbPrincipal, username);
            session.userLocalStorage().addFederatedIdentity(realm, user, federatedIdentityModel);
        }
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        // Don't update attribute in LDAP later. It's supposed to be written just at registration time
        ldapUser.addReadOnlyAttributeName(mapperConfig.getUserAttributeName());
        ldapUser.addReadOnlyAttributeName(mapperConfig.getDomainAttributeName());

        return delegate;
    }

    @Override
    public MdLDAPStorageProvider getLdapProvider() {
        LDAPStorageProvider ldapProvider = super.getLdapProvider();
        if (!(ldapProvider instanceof MdLDAPStorageProvider)) {
            throw new ModelException("'" + KerberosLDAPAttributeMapperFactory.PROVIDER_ID + "' mapper is supported by '"
                    + MdLDAPConstants.EXTENSION_NAME + "' User Storage provider extension only");
        }
        return (MdLDAPStorageProvider) ldapProvider;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        String userAttr = mapperConfig.getUserAttributeName();
        String domainAttr = mapperConfig.getDomainAttributeName();

        // Add mapped attribute to returning ldap attributes
        query.addReturningLdapAttribute(userAttr);
        query.addReturningReadOnlyLdapAttribute(userAttr);
        query.addReturningLdapAttribute(domainAttr);
        query.addReturningReadOnlyLdapAttribute(domainAttr);
    }

    private String extractKrbPrincipal(LDAPObject ldapUser) {

        UserStorageProviderModel model = getLdapProvider().getModel();
        String userAttr = mapperModel.get(LDAP_USER_ATTRIBUTE_NAME);
        String domainAttr = mapperModel.get(LDAP_DOMAIN_ATTRIBUTE_NAME);

        String krbUserName = MdLDAPUtils.extractUsername(MdLDAPUtils.getRequiredAttributeValue(userAttr, ldapUser));
        String krbDomain = ldapUser.getAttributeAsString(domainAttr);
        if (krbDomain == null || krbDomain.isEmpty()) {
            throw new ModelException("Unable to determinate domain of user returned from LDAP!"
                    +" Check configuration of mapper '" + mapperConfig.getName() + "' in LDAP provider '" + model.getName()
                    +  "'. User DN: " + ldapUser.getDn());
        }
        String tmp = MdLDAPUtils.extractDomain(krbDomain);
        if (!tmp.isEmpty()) {
            krbDomain = tmp;
        }

        if (!kerberosRealms.contains(krbDomain)){
            throw new ModelException("User returned from LDAP has domain '" + krbDomain
                    + "' that is not from domain list " + kerberosRealms + " of LDAP provider!"
                    + " Check configuration of your LDAP provider '" + model.getName()
                    +  "'. User DN: " + ldapUser.getDn());
        }

        return krbUserName + '@' + krbDomain;
    }
}
