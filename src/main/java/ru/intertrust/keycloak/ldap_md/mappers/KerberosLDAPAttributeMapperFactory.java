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

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import ru.intertrust.keycloak.ldap_md.MdLDAPConstants;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class KerberosLDAPAttributeMapperFactory extends AbstractLDAPStorageMapperFactory {

    // PROVIDER_ID limit is 40 chars
    public static final String PROVIDER_ID = "kerberos-principal-ldap-mapper";

    public static final String LDAP_KERBEROS_USER_LABEL = "Kerberos Username LDAP Attribute";

    public static final String LDAP_KERBEROS_REALM_LABEL = "Kerberos Realm LDAP Attribute";

    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>(4);

    static {
        ProviderConfigProperty attrName = createConfigProperty(
                KerberosLDAPAttributeMapper.LDAP_USER_ATTRIBUTE_NAME,
                LDAP_KERBEROS_USER_LABEL,
                "A name of the LDAP attribute that contains a username provided in the Kerberos token." +
                        " The part to the left of the \"@\" separator is taken if present." +
                        " For Active Directory the value MUST be \"sAMAccountName\".",
                ProviderConfigProperty.STRING_TYPE,
                null);
        attrName.setDefaultValue(MdLDAPConstants.SAM_ACCOUNT_NAME);


        ProviderConfigProperty attrDomain = createConfigProperty(
                KerberosLDAPAttributeMapper.LDAP_DOMAIN_ATTRIBUTE_NAME,
                LDAP_KERBEROS_REALM_LABEL,
                "A name of the LDAP attribute that contains a realm provided in the Kerberos token." +
                        " Part to the right of the '\"@\" separator is taken." +
                        " For Active Directory the value usually is \"userPrincipalName\"",
                ProviderConfigProperty.STRING_TYPE,
                null);
        attrDomain.setDefaultValue(MdLDAPConstants.USER_PRINCIPAL_NAME);

        configProperties.add(attrName);
        configProperties.add(attrDomain);
    }

    @Override
    public String getHelpText() {
        return "This mapper is supported just if LDAP Kerberos integration is enabled. It specify how Kerberos user principal name maps to LDAP attributes to search an user in LDAP.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        MdConfigurationValidationHelper check = MdConfigurationValidationHelper.check(model);
        for (ProviderConfigProperty property : configProperties) {
            check.checkRequired(property);
        }

        int count = 0;
        if (model.getId() == null){
            count = 1;
        }
        List<ComponentModel> mapperModels = realm.getComponents(model.getParentId(), LDAPStorageMapper.class.getName());
        for (ComponentModel mapperModel : mapperModels) {
            if (KerberosLDAPAttributeMapperFactory.PROVIDER_ID.equals(mapperModel.getProviderId())) {
                count++;
                if (count > 1){
                    throw new ComponentValidationException("Just one mapper of type \"" + KerberosLDAPAttributeMapperFactory.PROVIDER_ID + "\" is allowed.");
                }
            }
        }
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new KerberosLDAPAttributeMapper(mapperModel, federationProvider);
    }


}
