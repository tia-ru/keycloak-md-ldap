package ru.intertrust.keycloak.ldap_md;

import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public enum MdLDAPUtils {
;
    public static LDAPQuery createQueryForUserSearch(LDAPStorageProvider ldapProvider, RealmModel realm) {
        LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(ldapProvider, realm);

        LDAPConfig config = ldapProvider.getLdapIdentityStore().getConfig();
        String usernameMappedAttribute = config.getUsernameLdapAttribute();
        ldapQuery.addReturningLdapAttribute(usernameMappedAttribute);
        //ldapQuery.addReturningReadOnlyLdapAttribute(usernameMappedAttribute);

        return ldapQuery;
    }

    public static String getUsername(LDAPObject ldapUser, String usernameAttr) {
        String ldapUsername = ldapUser.getAttributeAsString(usernameAttr);
        if (ldapUsername == null) {
            throw new ModelException("User returned from LDAP has null username! Check configuration of your LDAP mappings. Mapped username LDAP attribute: " +
                    usernameAttr + ", user DN: " + ldapUser.getDn() + ", attributes from LDAP: " + ldapUser.getAttributes());
        }

        return ldapUsername;
    }

    static List<String> getKerberosRealms(CommonKerberosConfig kerberosConfig){
        if (kerberosConfig.getKerberosRealm() == null){
            return Collections.emptyList();
        }
        String[] split = kerberosConfig.getKerberosRealm().split("[,;\\s]");
        List<String> result = new ArrayList<>(split.length);
        for (int i = 0; i < split.length; i++) {
            String s = split[i];
            String aCase = s.trim().toUpperCase();
            if (!aCase.isEmpty()) {
                result.add(aCase);
            }
        }
        return result;
    }
}
