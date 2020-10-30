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

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPIdentityStoreRegistry;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import ru.intertrust.keycloak.ldap_md.mappers.KerberosLDAPAttributeMapper;
import ru.intertrust.keycloak.ldap_md.mappers.KerberosLDAPAttributeMapperFactory;

import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * @author Ilya Tugushev
 */
public class MdLDAPStorageProviderFactory extends LDAPStorageProviderFactory {

    private static final Logger logger = Logger.getLogger(MdLDAPStorageProviderFactory.class);
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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = super.getConfigProperties();
        for (ProviderConfigProperty property : configProperties) {
            if (KerberosConstants.SERVER_PRINCIPAL.equals(property.getName())){
                property.setDefaultValue("*");
            }
        }

        return configProperties;
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        super.onCreate(session, realm, model);
        LDAPConfig ldapConfig = new LDAPConfig(model.getConfig());
        LDAPProviderKerberosConfig krbConfig = new LDAPProviderKerberosConfig(model);
       /* UserStorageProviderModel providerModel = new UserStorageProviderModel(model);
        boolean importEnabled = providerModel.isImportEnabled();*/

        /*UserStorageProvider.EditMode editMode = ldapConfig.getEditMode();
        String readOnly = String.valueOf(editMode == UserStorageProvider.EditMode.READ_ONLY ||
                editMode == UserStorageProvider.EditMode.UNSYNCED);
        String alwaysReadValueFromLDAP = String.valueOf(editMode== UserStorageProvider.EditMode.READ_ONLY ||
                editMode== UserStorageProvider.EditMode.WRITABLE);*/

        boolean isActiveDirectory = ldapConfig.isActiveDirectory();
        if (isActiveDirectory) {
            if (krbConfig.isAllowKerberosAuthentication()) {
                ComponentModel mapperModel = MdKeycloakModelUtils.createComponentModel(
                        "kerberos principal",
                        model.getId(),
                        KerberosLDAPAttributeMapperFactory.PROVIDER_ID,
                        LDAPStorageMapper.class.getName(),
                        KerberosLDAPAttributeMapper.LDAP_USER_ATTRIBUTE_NAME,
                        MdLDAPConstants.SAM_ACCOUNT_NAME,
                        KerberosLDAPAttributeMapper.LDAP_DOMAIN_ATTRIBUTE_NAME,
                        MdLDAPConstants.USER_PRINCIPAL_NAME
                        );
                realm.addComponentModel(mapperModel);
            }
        }
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        super.validateConfiguration(session, realm, config);

        LDAPConfig ldapConfig = new LDAPConfig(config.getConfig());
        LDAPProviderKerberosConfig kerberosConfig = new LDAPProviderKerberosConfig(config);
        /*UserStorageProviderModel userStorageModel = new UserStorageProviderModel(config);
        ConfigurationValidationHelper helper = ConfigurationValidationHelper.check(config);*/

        /*if (ldapConfig.isActiveDirectory() && kerberosConfig.isAllowKerberosAuthentication()
                && !ldapConfig.getUsernameLdapAttribute().equalsIgnoreCase(MdLDAPConstants.SAM_ACCOUNT_NAME)){
            throw new ComponentValidationException("User name LDAP attribute has to be 'sAMAccountName' for Active Directory provider and enabled Kerberos integration");
        }*/
        if (ldapConfig.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
            throw new ComponentValidationException("LDAP WRITE mode is not supported by third party provider \"" + MdLDAPConstants.EXTENSION_NAME+"\"");
        }

        if (!"*".equals(kerberosConfig.getServerPrincipal())){
            throw new ComponentValidationException("\"Server principal\" field must has value \"*\" by requirements of third party provider \"" + MdLDAPConstants.EXTENSION_NAME+"\"");
        }

        //Make default value explicit
        String editModeString = config.getConfig().getFirst(MdLDAPConstants.EDIT_MODE);
        if (editModeString == null || editModeString.isEmpty()) {
            config.getConfig().putSingle(MdLDAPConstants.EDIT_MODE, UserStorageProvider.EditMode.READ_ONLY.name());
        }

        // Normalize field value
        if (ldapConfig.getUsernameLdapAttribute().equalsIgnoreCase(MdLDAPConstants.SAM_ACCOUNT_NAME)){
            config.getConfig().putSingle(MdLDAPConstants.USERNAME_LDAP_ATTRIBUTE, MdLDAPConstants.SAM_ACCOUNT_NAME);
        }
        // Normalize field value
        List<String> kerberosRealms = MdLDAPUtils.getKerberosRealms(kerberosConfig);
        StringJoiner stringJoiner = new StringJoiner(", ");
        for (String kerberosRealm : kerberosRealms) {
            stringJoiner.add(kerberosRealm);
        }
        config.getConfig().putSingle(KerberosConstants.KERBEROS_REALM, stringJoiner.toString());
    }

    protected MdSPNEGOAuthenticator createSPNEGOAuthenticator(String spnegoToken, CommonKerberosConfig kerberosConfig) {
        KerberosServerSubjectAuthenticator kerberosAuth = createKerberosSubjectAuthenticator(kerberosConfig);
        return new MdSPNEGOAuthenticator(kerberosConfig, kerberosAuth, spnegoToken);
    }

}
