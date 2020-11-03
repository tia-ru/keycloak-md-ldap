package ru.intertrust.keycloak.ldap_md;

import org.jboss.logging.Logger;
import org.keycloak.common.util.reflections.Types;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.idm.model.LDAPObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public enum MdLDAPUtils {
;
    private static final Logger logger = Logger.getLogger(MdLDAPUtils.class);
    private static final Pattern REALMS_SEPARATOR = Pattern.compile("[,;\\s]");

    public static String getRequiredAttributeValue(String attributeName, LDAPObject ldapUser) {
        String ldapUsername = ldapUser.getAttributeAsString(attributeName);
        if (ldapUsername == null) {
            throw new ModelException("User returned from LDAP has null required attribute '" + attributeName + "' value!"
                    + " Check configuration of your LDAP mappings."
                    + " LDAP User DN: " + ldapUser.getDn() + ", attributes from LDAP: " + ldapUser.getAttributes());
        }
        return ldapUsername;
    }

    public static List<String> getKerberosRealms(CommonKerberosConfig kerberosConfig){
        if (kerberosConfig.getKerberosRealm() == null){
            return Collections.emptyList();
        }
        String[] split = REALMS_SEPARATOR.split(kerberosConfig.getKerberosRealm());
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

    public static String extractUsername(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? authenticatedKerberosPrincipal : authenticatedKerberosPrincipal.substring(0, i);
    }

    public static String extractDomain(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? "" : authenticatedKerberosPrincipal.substring(i + 1).toUpperCase();
    }

    static <T> List<T> getEnabledStorageProviders(KeycloakSession session, RealmModel realm, Class<T> type) {
        List<UserStorageProviderModel> userStorageProviders = realm.getUserStorageProviders();
        List<T> list = new ArrayList<>(userStorageProviders.size());
        for (UserStorageProviderModel model : userStorageProviders) {
            if (!model.isEnabled()) continue;
            UserStorageProviderFactory<? extends UserStorageProvider> factory =
                    (UserStorageProviderFactory<? extends UserStorageProvider>)
                            session.getKeycloakSessionFactory().getProviderFactory(UserStorageProvider.class, model.getProviderId());
            if (factory == null) {
                logger.warnv("Configured UserStorageProvider {0} of provider id {1} does not exist in realm {2}", model.getName(), model.getProviderId(), realm.getName());
                continue;
            }
            if (Types.supports(type, factory, UserStorageProviderFactory.class)) {
                list.add(type.cast(getStorageProviderInstance(session, model, factory)));
            }
        }
        return list;
    }

    private static UserStorageProvider getStorageProviderInstance(
            KeycloakSession session,
            UserStorageProviderModel model,
            UserStorageProviderFactory<? extends UserStorageProvider> factory) {

        UserStorageProvider instance = (UserStorageProvider)session.getAttribute(model.getId());
        if (instance != null) return instance;
        instance = factory.create(session, model);
        if (instance == null) {
            throw new IllegalStateException("UserStorageProvideFactory (of type " + factory.getClass().getName() + ") produced a null instance");
        }
        session.enlistForClose(instance);
        session.setAttribute(model.getId(), instance);
        return instance;
    }
}
