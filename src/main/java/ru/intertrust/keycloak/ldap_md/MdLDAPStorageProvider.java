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
import org.keycloak.component.ComponentModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import ru.intertrust.keycloak.ldap_md.mappers.KerberosLDAPAttributeMapperConfig;
import ru.intertrust.keycloak.ldap_md.mappers.KerberosLDAPAttributeMapperFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    public LDAPProviderKerberosConfig getLDAPProviderKerberosConfig(){
        return kerberosConfig;
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
        return model.getId().equals(o.getModel().getId());
    }

    /**
     * Called after successful kerberos authentication
     *
     * @param realm realm
     * @param krbPrincipal username without realm prefix with domain suffix
     * @return founded or newly created user
     */
    @Override
    protected UserModel findOrCreateAuthenticatedUser(RealmModel realm, String krbPrincipal) {

        UserModel user = null;
        MdLDAPStorageProvider suitableStorage;

        /*
        username is sAMAccountName in AD
        userDomain:
          - It must be the DNS name of a domain, but does not need to be the name of the domain that contains the user.
          - It must be the name of a domain in the current domain forest, or an alternate name listed in
            the upnSuffixes attribute of the Partitions container within the Configuration container.
         */
        String krbUserDomain = MdLDAPUtils.extractDomain(krbPrincipal);
        String krbUsername = MdLDAPUtils.extractUsername(krbPrincipal);

        if (krbUserDomain.isEmpty()){
            logger.debugf("Kerberos authenticated user [%s] dont'n have domain in the name", krbPrincipal);
            return null;
        }

        /*
         It's acceptable to have many ldap providers for the same domain.
         1) Providers has connect to single LDAP catalog but with different users' subtree DN
         2) There's provider to Global LDAP Catalog that includes part of another LDAP-Catalog
         and there's provider to the later LDAP Catalog.
         Global Catalog settings should has highest priority (is checked last)
         N.B. Kerberos authN performs by provider with lowest priority
        */
        List<MdLDAPStorageProvider> ldapStorages;

        ldapStorages = getLdapStorageProviders(krbUserDomain, realm, session);
        if (ldapStorages.size() > 0) {
            suitableStorage = ldapStorages.get(0);
        } else {
            logger.warnf("There is no LDAP providers for Kerberos authenticated user domain [%s]", krbUserDomain);
            return null;
        }
        logger.debugf("Storage providers for Kerberos authenticated user domain [%s]: %s", krbUserDomain, ldapStorages);

        for (MdLDAPStorageProvider storage : ldapStorages) {
            FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(
                    storage.getModel().getProviderId(),
                    krbPrincipal,
                    krbUsername /* ignored */);

            //Cache is disabled without identity providers
            //user = session.users().getUserByFederatedIdentity(federatedIdentityModel, realm);
            user = session.userLocalStorage().getUserByFederatedIdentity(federatedIdentityModel, realm);
            if (user != null) {
                suitableStorage = storage;
                break;
            }
        }

        if (user != null ){

            if (!suitableStorage.getModel().getId().equals(user.getFederationLink())) {
                logger.warnf("User [%s] linked to [%s] already exists in Keycloak storage, but is not linked to his domain provider %s",
                        krbPrincipal,
                        user.getFederationLink(),
                        ldapStorages.size() <= 1 ? "provider [" + suitableStorage + ']' : "providers " + ldapStorages
                );
                return null;
            }

            logger.debugf("Kerberos authenticated user [%s] found in Keycloak storage [%s]", krbPrincipal, suitableStorage);
            LDAPObject ldapUser = suitableStorage.loadAndValidateUser(realm, user);
            if (ldapUser != null) {
                user = suitableStorage.proxy(realm, user, ldapUser, false);
            } else {
                logger.warnf("User with username [%s] already exists and is linked to provider [%s] but is not valid or absent in LDAP. Stale LDAP_ID on local user is: %s",
                        krbUsername, suitableStorage.getModel().getName(), user.getFirstAttribute(MdLDAPConstants.LDAP_ID));
                logger.warn("Will re-create the user");

                UserCache userCache = suitableStorage.getSession().userCache();
                if (userCache != null) {
                    userCache.evict(realm, user);
                }
                new UserManager(suitableStorage.getSession()).removeUser(realm, user, suitableStorage.getSession().userLocalStorage());
            }
        }

        if (user == null) {
            // Creating user to local storage
            user = suitableStorage.getUserByKerberosPrincipal(krbPrincipal, realm);
            if (user == null) {
                for (int i = 0; user == null && i < ldapStorages.size(); i++) {
                    MdLDAPStorageProvider storage = ldapStorages.get(i);
                    if (!storage.equals(suitableStorage)) {
                        user = storage.getUserByKerberosPrincipal(krbPrincipal, realm);
                        suitableStorage = storage;
                    }
                }
            }
            if (user != null) {
                logger.debugf("Kerberos authenticated user [%s] not in Keycloak storage. Creating him in [%s]", krbPrincipal, suitableStorage);
            }
        }

        return user;
    }

    /**
     * Override just to optimize performance.
     * @param realm
     * @param attributes
     * @param maxResults
     * @return
     */
    @Override
    protected List<LDAPObject> searchLDAP(RealmModel realm, Map<String, String> attributes, int maxResults) {

        List<LDAPObject> results = new ArrayList<>();
        List<Condition> conditions = new ArrayList<>(4);
        LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();
        if (attributes.containsKey(UserModel.USERNAME)) {
            // Mapper should replace "username" in parameter name with correct LDAP mapped attribute
            Condition usernameCondition = conditionsBuilder.equal(UserModel.USERNAME, attributes.get(UserModel.USERNAME), EscapeStrategy.NON_ASCII_CHARS_ONLY);
            conditions.add(usernameCondition);
        }

        if (attributes.containsKey(UserModel.EMAIL)) {
            // Mapper should replace "email" in parameter name with correct LDAP mapped attribute
            Condition emailCondition = conditionsBuilder.equal(UserModel.EMAIL, attributes.get(UserModel.EMAIL), EscapeStrategy.NON_ASCII_CHARS_ONLY);
            conditions.add(emailCondition);
        }

        if (attributes.containsKey(UserModel.FIRST_NAME) || attributes.containsKey(UserModel.LAST_NAME)) {

            // Mapper should replace parameter with correct LDAP mapped attributes
            if (attributes.containsKey(UserModel.FIRST_NAME)) {
                conditions.add(conditionsBuilder.equal(UserModel.FIRST_NAME, attributes.get(UserModel.FIRST_NAME), EscapeStrategy.NON_ASCII_CHARS_ONLY));
            }
            if (attributes.containsKey(UserModel.LAST_NAME)) {
                conditions.add(conditionsBuilder.equal(UserModel.LAST_NAME, attributes.get(UserModel.LAST_NAME), EscapeStrategy.NON_ASCII_CHARS_ONLY));
            }
        }

        if (!conditions.isEmpty()) {
            Condition[] array = conditions.toArray(new Condition[0]);
            Condition condition = conditionsBuilder.orCondition(array);
            try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
                ldapQuery.addWhereCondition(condition);
                List<LDAPObject> ldapObjects = ldapQuery.getResultList();
                results.addAll(ldapObjects);
            }
        }
        return results;
    }

    private UserModel getUserByKerberosPrincipal(String krbPrincipal, RealmModel realm) {
        LDAPObject ldapUser = loadLDAPUserByKerberosPrincipal(realm, krbPrincipal);
        if (ldapUser != null) {
            return importUserFromLDAP(session, realm, ldapUser);
        }
        return null;
    }

    private LDAPObject loadLDAPUserByKerberosPrincipal(RealmModel realm, String krbPrincipal) {

        KerberosLDAPAttributeMapperConfig kerberosMapperModel = getKerberosMapperModel(realm);
        if (kerberosMapperModel == null) {
            logger.warnf("LDAP storage provider [%s] does not has required mapper of type [" +
                    KerberosLDAPAttributeMapperFactory.PROVIDER_ID +
                    "] to complete Kerberos authentication", this);
            return null;
        }
        String userAttr = kerberosMapperModel.getUserAttributeName();
        String domainAttr = kerberosMapperModel.getDomainAttributeName();
        if (userAttr == null || domainAttr == null){
            return null;
        }

        try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(this, realm)) {
            Condition condition;
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            if (userAttr.equals(domainAttr)){
                condition = conditionsBuilder.equal(userAttr, krbPrincipal, EscapeStrategy.DEFAULT);
                ldapQuery.addWhereCondition(condition);
            } else {
                String krbUsername = MdLDAPUtils.extractUsername(krbPrincipal);
                Condition userCondition = conditionsBuilder.equal(userAttr, krbUsername, EscapeStrategy.DEFAULT);
                String krbDomain = MdLDAPUtils.extractDomain(krbPrincipal);
                Condition domainCondition = conditionsBuilder.equal(domainAttr, "*@" + krbDomain, EscapeStrategy.NON_ASCII_CHARS_ONLY);
                ldapQuery.addWhereCondition(userCondition, domainCondition);
            }

            LDAPObject ldapUser = ldapQuery.getFirstResult();
            return ldapUser;
        }
    }

    private KerberosLDAPAttributeMapperConfig getKerberosMapperModel(RealmModel realm) {
        List<ComponentModel> mapperModels = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
        //List<ComponentModel> mapperModels = mapperManager.sortMappersAsc(mapperModels);
        for (ComponentModel mapperModel : mapperModels) {
            if (KerberosLDAPAttributeMapperFactory.PROVIDER_ID.equals(mapperModel.getProviderId())) {
                return new KerberosLDAPAttributeMapperConfig(mapperModel);
            }
        }
        return null;
    }

    private static List<MdLDAPStorageProvider> getLdapStorageProviders(String userDomain, RealmModel realm, KeycloakSession session){
        String userDomainUc = userDomain.toUpperCase();
        List<LDAPStorageProvider> list = MdLDAPUtils.getEnabledStorageProviders(session, realm, LDAPStorageProvider.class); //MdLDAPStorageProvider.class is not working
        List<MdLDAPStorageProvider> result = new ArrayList<>(list.size());
        for (LDAPStorageProvider userProvider : list) {
            if (userProvider instanceof MdLDAPStorageProvider) {
                MdLDAPStorageProvider mdUserProvider = (MdLDAPStorageProvider) userProvider;
                List<String> realms = MdLDAPUtils.getKerberosRealms(mdUserProvider.kerberosConfig);
                if (realms.contains(userDomainUc)){
                    result.add(mdUserProvider);
                }
            }
        }
        return result;
    }
}
