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
import org.keycloak.common.util.reflections.Types;
import org.keycloak.component.ComponentModel;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Ilya Tugushev</a>
 */
public class MdLDAPStorageProvider extends LDAPStorageProvider
{
    private static final Logger logger = Logger.getLogger(MdLDAPStorageProvider.class);

    public MdLDAPStorageProvider(MdLDAPStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        super(factory, session, model, ldapIdentityStore);
        //KerberosUsernamePasswordAuthenticator authenticator = factory.createKerberosUsernamePasswordAuthenticator(kerberosConfig);
    }

    /**
     * Called after successful kerberos authentication
     *
     * @param realm realm
     * @param principal username without realm prefix with domain suffix
     * @return finded or newly created user
     */
    @Override
    protected UserModel findOrCreateAuthenticatedUser(RealmModel realm, String principal) {

        UserModel user;
        MdLDAPStorageProvider suitableStorage;

        /*
        username is sAMAccountName in AD
        userDomain:
          - It must be the DNS name of a domain, but does not need to be the name of the domain that contains the user.
          - It must be the name of a domain in the current domain forest, or an alternate name listed in
            the upnSuffixes attribute of the Partitions container within the Configuration container.
         */
        String userDomain = getAuthenticatedUserDomain(principal);
        String username = getAuthenticatedUsername(principal);


        // It's acceptable to have many ldap catalogs for the same domain.
        // E.g. there's connection to Global LDAP Catalog that includes part of another LDAP-Catalog
        // and there's connection to the later LDAP Catalog
        // Global Catalog settings should has highest priority (is checked last)
        // N.B. Kerberos authN performs with lowest priority settings
        List<MdLDAPStorageProvider> kerberosStorages = null;
        suitableStorage = this;
        if (!userDomain.isEmpty()){
            kerberosStorages = getKerberosStorageProviders(realm, userDomain);
            logger.debugf("Storage providers for user's domain [%s]: %s", userDomain, kerberosStorages);
            if (kerberosStorages.size() > 0) {
                suitableStorage = kerberosStorages.get(0);
            }
        }

        user = session.userLocalStorage().getUserByUsername(username, realm);
        if (user != null) {
            logger.debugf("Kerberos authenticated user [%s] found in Keycloak storage", principal);
            if (kerberosStorages != null){
                for (MdLDAPStorageProvider storage : kerberosStorages) {
                    String storageId = storage.getModel().getId();
                    if (storageId.equals(user.getFederationLink())){
                        suitableStorage = storage;
                        break;
                    }
                }
            }
            if (!suitableStorage.getModel().getId().equals(user.getFederationLink())) {
                logger.warnf("User [%s] linked to [%s] already exists, but is not linked to his domain providers %s",
                        principal,
                        user.getFederationLink(),
                        kerberosStorages == null ? "[" + suitableStorage + ']' :  kerberosStorages
                );
                return null;
            }
            LDAPObject ldapObject = suitableStorage.loadAndValidateUser(realm, user);
            if (ldapObject != null) {
                return suitableStorage.proxy(realm, user, ldapObject, false);
            }
            logger.warnf("User with username [%s] aready exists and is linked to provider [%s] but is not valid. Stale LDAP_ID on local user is: %s",
                    username,  suitableStorage.getModel().getName(), user.getFirstAttribute(LDAPConstants.LDAP_ID));
            logger.warn("Will re-create the user");

            UserCache userCache = suitableStorage.getSession().userCache();
            if (userCache != null) {
                userCache.evict(realm, user);
            }
            new UserManager(suitableStorage.getSession()).removeUser(realm, user, suitableStorage.getSession().userLocalStorage());
        }

        // Creating user to local storage
        user = suitableStorage.getUserByUsername(username, realm);
        if (user== null && kerberosStorages != null) {
            for (int i = 0; user== null && i < kerberosStorages.size(); i++) {
                MdLDAPStorageProvider storage = kerberosStorages.get(i);
                if (!storage.equals(suitableStorage)) {
                    user = storage.getUserByUsername(username, realm);
                    suitableStorage = storage;
                }
            }
        }
        if (user != null){
            logger.debugf("Kerberos authenticated user [%s] not in Keycloak storage. Creating him in [%s]", principal, suitableStorage);
        }

        return user;
    }

    private String getAuthenticatedUsername(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? authenticatedKerberosPrincipal : authenticatedKerberosPrincipal.substring(0, i);
    }

    private String getAuthenticatedUserDomain(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? "" : authenticatedKerberosPrincipal.substring(i + 1);
    }

    private List<MdLDAPStorageProvider> getKerberosStorageProviders(RealmModel realm, String userDomain){
        /*UserStorageProvider userStorageProvider;
        UserLookupProvider userLookupProvider;
        UserProvider userProvider;*/
        String userDomainUc = userDomain.toUpperCase();
        List<LDAPStorageProvider> list = getEnabledStorageProviders(session, realm, LDAPStorageProvider.class); //MdLDAPStorageProvider.class is not working
        List<MdLDAPStorageProvider> result = new ArrayList<>(list.size());
        for (LDAPStorageProvider userProvider : list) {
            if (userProvider instanceof MdLDAPStorageProvider) {
                MdLDAPStorageProvider mdUserProvider = (MdLDAPStorageProvider) userProvider;
                List<String> realms = getKerberosRealms(mdUserProvider.kerberosConfig);
                if (realms.contains(userDomainUc)){
                    result.add(mdUserProvider);
                }
            }
        }
        return result;
    }

    private List<String> getKerberosRealms(CommonKerberosConfig kerberosConfig){
        String[] split = kerberosConfig.getKerberosRealm().split(",");
        List<String> result = new ArrayList<>(split.length);
        for (int i = 0; i < split.length; i++) {
            String s = split[i];
            result.add(s.trim().toUpperCase());
        }
        return result;
    }

    private static <T> List<T> getEnabledStorageProviders(KeycloakSession session, RealmModel realm, Class<T> type) {
        List<UserStorageProviderModel> userStorageProviders = realm.getUserStorageProviders();
        List<T> list = new ArrayList<>(userStorageProviders.size());
        for (UserStorageProviderModel model : userStorageProviders) {
            if (!model.isEnabled()) continue;
            UserStorageProviderFactory factory = (UserStorageProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(UserStorageProvider.class, model.getProviderId());
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

    private static UserStorageProvider getStorageProviderInstance(KeycloakSession session, UserStorageProviderModel model, UserStorageProviderFactory factory) {
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

    @Override
    public String toString() {
        return getModel().getName() + " (" + getModel().getId() + ')';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MdLDAPStorageProvider)) return false;
        MdLDAPStorageProvider o = (MdLDAPStorageProvider) obj;
        return getModel().getId().equals(o.getModel().getId());
    }
}
