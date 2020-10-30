package ru.intertrust.keycloak.ldap_md.mappers;

import org.keycloak.component.ComponentModel;

public class KerberosLDAPAttributeMapperConfig {

    private final String userAttributeName;
    private final String domainAttributeName;
    private final String name;

    public KerberosLDAPAttributeMapperConfig(ComponentModel mapperModel) {
        userAttributeName = mapperModel.get(KerberosLDAPAttributeMapper.LDAP_USER_ATTRIBUTE_NAME);
        domainAttributeName = mapperModel.get(KerberosLDAPAttributeMapper.LDAP_DOMAIN_ATTRIBUTE_NAME);
        name = mapperModel.getName();
    }

    public String getUserAttributeName() {
        return userAttributeName;
    }

    public String getDomainAttributeName() {
        return domainAttributeName;
    }

    public String getName() {
        return name;
    }
}
