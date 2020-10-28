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
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.reflections.Types;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPDn;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapperFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Ilya Tugushev</a>
 */
public class MdLDAPStorageProvider extends LDAPStorageProvider
{
    private static final Logger logger = Logger.getLogger(MdLDAPStorageProvider.class);
    private static final String LDAP_SEARCH_BY_KRB_USERNAME = "ldap.query.krb-username";

    public MdLDAPStorageProvider(MdLDAPStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        super(factory, session, model, ldapIdentityStore);
        //KerberosUsernamePasswordAuthenticator authenticator = factory.createKerberosUsernamePasswordAuthenticator(kerberosConfig);
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
        String krbUserDomain = extractUserDomain(krbPrincipal);
        String krbUsername = extractUsername(krbPrincipal);

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
        List<MdLDAPStorageProvider> kerberosStorages;

        kerberosStorages = getKerberosStorageProviders(realm, krbUserDomain);
        if (kerberosStorages.size() > 0) {
            suitableStorage = kerberosStorages.get(0);
        } else {
            logger.warnf("There is no providers for Kerberos authenticated user domain [%s]", krbUserDomain);
            return null;
        }
        logger.debugf("Storage providers for Kerberos authenticated user domain [%s]: %s", krbUserDomain, kerberosStorages);

        boolean isMakeFederationLink = true;
        for (MdLDAPStorageProvider storage : kerberosStorages) {
            FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(
                    storage.getModel().getProviderId(),
                    krbPrincipal,
                    krbUsername /* ignored */);
            user = session.userLocalStorage().getUserByFederatedIdentity(federatedIdentityModel, realm);
            if (user != null) {
                suitableStorage = storage;
                isMakeFederationLink = false;
                break;
            }
        }

        LDAPObject ldapUser = null;
        if (user == null) {
            for (MdLDAPStorageProvider storage : kerberosStorages) {
                ldapUser = storage.loadLDAPUserByKerberosPrincipal(realm, krbPrincipal);
                if (ldapUser != null){
                    suitableStorage = storage;
                    String username = MdLDAPUtils.getUsername(ldapUser, storage.getMappedUsernameLdapAttribute(realm));
                    user = storage.getSession().userLocalStorage().getUserByUsername(username, realm);
                    //TODO check if user has same username with another user in different provider

                    break;
                }
            }
        }

        if (user != null ){
            logger.debugf("Kerberos authenticated user [%s] found in Keycloak storage [%s]", krbPrincipal, suitableStorage);
            if (!suitableStorage.getModel().getId().equals(user.getFederationLink())) {
                logger.warnf("User [%s] linked to [%s] already exists in Keycloak storage, but is not linked to his domain provider %s",
                        krbPrincipal,
                        user.getFederationLink(),
                        kerberosStorages.size() <= 1 ? "provider [" + suitableStorage + ']' : "providers " + kerberosStorages
                );
                return null;
            }

            if (ldapUser == null) {
                ldapUser = suitableStorage.loadAndValidateUser(realm, user);
            } else {
                ldapUser = validateUser(user, ldapUser, realm);
            }
            if (ldapUser != null) {
                if (isMakeFederationLink && suitableStorage.getModel().isImportEnabled()){
                    UserStorageProviderModel suitableStorageModel = suitableStorage.getModel();
                    logger.debugf("Kerberos authenticated user [%s] found in Keycloak storage. Link him to federation provider [%s]", krbPrincipal, suitableStorageModel.getName());
                    FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(suitableStorageModel.getProviderId(), krbPrincipal, user.getUsername());
                    suitableStorage.getSession().userLocalStorage().addFederatedIdentity(realm, user, federatedIdentityModel);
                }
                return suitableStorage.proxy(realm, user, ldapUser, false);
            }
            logger.warnf("User with username [%s] already exists and is linked to provider [%s] but is not valid or absent in LDAP. Stale LDAP_ID on local user is: %s",
                    krbUsername,  suitableStorage.getModel().getName(), user.getFirstAttribute(LDAPConstants.LDAP_ID));
            logger.warn("Will re-create the user");

            UserCache userCache = suitableStorage.getSession().userCache();
            if (userCache != null) {
                userCache.evict(realm, user);
            }
            new UserManager(suitableStorage.getSession()).removeUser(realm, user, suitableStorage.getSession().userLocalStorage());
        }

        // Creating user to local storage
        user = suitableStorage.getUserByKerberosPrincipal(krbPrincipal, realm);
        if (user == null) {
            for (int i = 0; user == null && i < kerberosStorages.size(); i++) {
                MdLDAPStorageProvider storage = kerberosStorages.get(i);
                if (!storage.equals(suitableStorage)) {
                    user = storage.getUserByKerberosPrincipal(krbPrincipal, realm);
                    suitableStorage = storage;
                }
            }
        }
        if (user != null){
            logger.debugf("Kerberos authenticated user [%s] not in Keycloak storage. Creating him in [%s]", krbPrincipal, suitableStorage);
        }

        return user;
    }

    @Override
    protected LDAPObject loadAndValidateUser(RealmModel realm, UserModel userModel) {
        LDAPObject existing = userManager.getManagedLDAPUser(userModel.getId());
        if (existing != null) {
            return existing;
        }

        LDAPObject ldapUser = null;
        String userLdapID = userModel.getFirstAttribute(LDAPConstants.LDAP_ID);
        if (userLdapID != null){
            String uuidLDAPAttributeName = getLdapIdentityStore().getConfig().getUuidLDAPAttributeName();
            Map<String, String> params = Collections.singletonMap(uuidLDAPAttributeName, userLdapID);
            List<LDAPObject> ldapObjects = searchLDAP(realm, params, Integer.MAX_VALUE - 1);
            if (ldapObjects.size() == 1) {
                ldapUser = ldapObjects.get(0);
            }
        }
        if (ldapUser == null) {
            String username = userModel.getUsername();
            if (username == null || username.isEmpty()){
                logger.warnf("User in local storage has invalid username. User id: [%s]", userModel.getId());
                return null;
            }
            ldapUser = loadLDAPUserByUsername(realm, username);
        }
        if (ldapUser != null) {
            ldapUser = validateUser(userModel, ldapUser, realm);
        }
        return ldapUser;
    }

    private LDAPObject validateUser(UserModel userModel, LDAPObject ldapUser, RealmModel realm) {
        LDAPUtils.checkUuid(ldapUser, ldapIdentityStore.getConfig());

        if (! ldapUser.getUuid().equals(userModel.getFirstAttribute(LDAPConstants.LDAP_ID))) {
            logger.warnf("LDAP User invalid. ID doesn't match. ID from LDAP [%s], LDAP ID from local DB: [%s]",
                    ldapUser.getUuid(), userModel.getFirstAttribute(LDAPConstants.LDAP_ID));
            return null;
        }

        return validateLdapUser(ldapUser, realm);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        LDAPObject ldapUser = loadLDAPUserByUsername(realm, username);
        if (ldapUser == null) {
            return null;
        }

        return importUserFromLDAP(session, realm, ldapUser);
    }

    @Override
    protected LDAPObject queryByEmail(RealmModel realm, String email) {
        try (LDAPQuery ldapQuery = MdLDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            // Mapper should replace "email" in parameter name with correct LDAP mapped attribute
            Condition emailCondition = conditionsBuilder.equal(UserModel.EMAIL, email, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(emailCondition);

            return ldapQuery.getFirstResult();
        }
    }

    /**
     *
     * @param realm
     * @param username is kerberos user name or mapped user name
     * @return
     */
    @Override
    public LDAPObject loadLDAPUserByUsername(RealmModel realm, String username) {
        try (LDAPQuery ldapQuery = MdLDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            /*
            //UserAttributeLDAPStorageMapper should replace model attribute name to ldap attribute name
            Condition usernameCondition = conditionsBuilder.equal(UserModel.USERNAME, username, EscapeStrategy.DEFAULT);

            //Both username and kerberos user name must be unique this provider's ldap subtree
            String krbNameAttribute = getLdapIdentityStore().getConfig().getUsernameLdapAttribute();
            Condition krbUsernameCondition = conditionsBuilder.equal(krbNameAttribute, username, EscapeStrategy.DEFAULT);
            Condition condition = conditionsBuilder.orCondition(usernameCondition, krbUsernameCondition);
            ldapQuery.addWhereCondition(condition);*/

            Condition condition = conditionsBuilder.equal(getMappedUsernameLdapAttribute(realm), username, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(condition);

            LDAPObject ldapUser = ldapQuery.getFirstResult();

            return ldapUser;
        }
    }

    @Override
    protected UserModel importUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser) {

        String ldapUsername = MdLDAPUtils.getUsername(ldapUser, getMappedUsernameLdapAttribute(realm));
        UserModel user = session.userLocalStorage().getUserByUsername(ldapUsername, realm);
        if (user != null && model.getId().equals(user.getFederationLink())
                && (ldapUser.getUuid().equals(user.getFirstAttribute(LDAPConstants.LDAP_ID)))){
            return user;
        }

        if( null == validateLdapUser(ldapUser, realm)){
            return null;
        }
        UserModel imported = super.importUserFromLDAP(session, realm, ldapUser);
        if (null == validateUser(imported, ldapUser, realm)){
            return null;
        }

        String krbPrincipal = ldapUser2KrbPrincipal(ldapUser);
        String username = imported.getUsername();
        FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(model.getProviderId(), krbPrincipal, username);
        session.userLocalStorage().addFederatedIdentity(realm, imported, federatedIdentityModel);
        return imported;
    }

    private String ldapUser2KrbPrincipal(LDAPObject ldapUser) {
        String krbUserName = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
        List<String> kerberosRealms = MdLDAPUtils.getKerberosRealms(kerberosConfig);
        String domain = extractUserDomain(krbUserName);
        if (!domain.isEmpty()) {

            krbUserName = extractUsername(krbUserName);

        } else if (kerberosRealms.size() == 1){

            domain = kerberosRealms.get(0);

        } else {
            LDAPDn dn = ldapUser.getDn().getParentDn();
            while (dn.getFirstRdn() != null && null == dn.getFirstRdn().getAttrValue("dc")){
                dn = dn.getParentDn();
            }
            if (dn.getFirstRdn() != null){
                domain = dn.toString().replaceAll(",?\\w+=", ".");
                domain = domain.substring(1).toUpperCase();
            }
        }

        if (domain == null || domain.isEmpty()) {
            throw new ModelException("Unable to determinate domain of user returned from LDAP! Check configuration of your LDAP provider '"
                    + model.getName() +  "', user DN: " + ldapUser.getDn());
        }
        return krbUserName + '@' + domain;
    }

    private LDAPObject validateLdapUser(LDAPObject ldapUser, RealmModel realm) {
        String username = ldapUser.getAttributeAsString(getMappedUsernameLdapAttribute(realm));
        if (username == null){
            //logger.debugf("LDAP User invalid. Mapped user name is null");
            throw new ModelException("User returned from LDAP has null username! Check configuration of your LDAP provider '"
                    + model.getName() + "' and mapper 'user-attribute-ldap-mapper' for user model attribute 'username'."
                    + " Mapped username LDAP attribute: " + getMappedUsernameLdapAttribute(realm) + ", user DN: " + ldapUser.getDn());
        }
        return ldapUser;
    }

    private UserModel getUserByKerberosPrincipal(String krbPrincipal, RealmModel realm) {
        LDAPObject ldapUser = loadLDAPUserByKerberosPrincipal(realm, krbPrincipal);
        if (ldapUser == null) {
            return null;
        }
        return importKerberosUserFromLDAP(session, realm, ldapUser, krbPrincipal);
    }

    private LDAPObject loadLDAPUserByKerberosPrincipal(RealmModel realm, String krbPrincipal) {
        try (LDAPQuery ldapQuery = MdLDAPUtils.createQueryForUserSearch(this, realm)) {
            Condition condition;
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            String krbNameAttribute = getLdapIdentityStore().getConfig().getUsernameLdapAttribute();
            Condition principalCondition = conditionsBuilder.equal(krbNameAttribute, krbPrincipal, EscapeStrategy.DEFAULT);

            String krbUsername = extractUsername(krbPrincipal);
            if (krbUsername.equals(krbPrincipal)){
                condition = principalCondition;
            } else {
                Condition userCondition = conditionsBuilder.equal(krbNameAttribute, krbUsername, EscapeStrategy.DEFAULT);
                condition = conditionsBuilder.orCondition(principalCondition, userCondition);
            }
            ldapQuery.addWhereCondition(condition);

            LDAPObject ldapUser = ldapQuery.getFirstResult();

            return ldapUser;
        }
    }

    private UserModel importKerberosUserFromLDAP(KeycloakSession session, RealmModel realm, LDAPObject ldapUser, String krbPrincipal) {
        UserModel imported = super.importUserFromLDAP(session, realm, ldapUser);
        if (model.isImportEnabled()) {
            String username = imported.getUsername();
            /*String ldapUsername = LDAPUtils.getUsername(ldapUser, ldapIdentityStore.getConfig());
            StorageId storageId = new StorageId(model.getProviderId(), ldapUsername);
            imported = session.userLocalStorage().addUser(realm, storageId.getId(), username, true, true);*/
            FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(model.getProviderId(), krbPrincipal, username);
            session.userLocalStorage().addFederatedIdentity(realm, imported, federatedIdentityModel);
        }
        return imported;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        String search = params.get(UserModel.SEARCH);
        if(search != null) {
            search = search.trim();
            int spaceIndex = search.lastIndexOf(' ');
            if (spaceIndex > -1) {
                String firstName = search.substring(0, spaceIndex).trim();
                String lastName = search.substring(spaceIndex).trim();
                params.put(UserModel.FIRST_NAME, firstName);
                params.put(UserModel.LAST_NAME, lastName);
            } else if (search.indexOf('@') > -1) {
                params.put(UserModel.USERNAME, search.toLowerCase());
                params.put(UserModel.EMAIL, search.toLowerCase());
            } else {
                params.put(UserModel.LAST_NAME, search);
                params.put(UserModel.USERNAME, search.toLowerCase());
            }
        }

        List<LDAPObject> ldapUsers = searchLDAP(realm, params, maxResults + firstResult);
        List<UserModel> searchResults = new ArrayList<>(ldapUsers.size());
        int counter = 0;
        for (LDAPObject ldapUser : ldapUsers) {
            if (counter++ < firstResult) continue;
            UserModel imported = importUserFromLDAP(session, realm, ldapUser);
            if (imported != null) {
                searchResults.add(imported);
            }
        }

        return searchResults;
    }

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

        String krbPrincipal = attributes.get(LDAP_SEARCH_BY_KRB_USERNAME);
        if (krbPrincipal != null) {
            String krbNameAttribute = getLdapIdentityStore().getConfig().getUsernameLdapAttribute();
            Condition principalCondition = conditionsBuilder.equal(krbNameAttribute, krbPrincipal, EscapeStrategy.DEFAULT);
            conditions.add(principalCondition);

            String krbUsername = extractUsername(krbPrincipal);
            if (!krbUsername.equals(krbPrincipal)){
                Condition userCondition = conditionsBuilder.equal(krbNameAttribute, krbUsername, EscapeStrategy.DEFAULT);
                conditions.add(userCondition);
            }
        }

        if (!conditions.isEmpty()) {
            Condition[] array = conditions.toArray(new Condition[0]);
            Condition condition = conditionsBuilder.orCondition(array);
            try (LDAPQuery ldapQuery = MdLDAPUtils.createQueryForUserSearch(this, realm)) {
                ldapQuery.addWhereCondition(condition);
                List<LDAPObject> ldapObjects = ldapQuery.getResultList();
                results.addAll(ldapObjects);
            }
        }
        return results;
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        try (LDAPQuery ldapQuery = MdLDAPUtils.createQueryForUserSearch(this, realm)) {
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            Condition attrCondition = conditionsBuilder.equal(attrName, attrValue, EscapeStrategy.DEFAULT);
            ldapQuery.addWhereCondition(attrCondition);

            List<LDAPObject> ldapObjects = ldapQuery.getResultList();

            if (ldapObjects == null || ldapObjects.isEmpty()) {
                return Collections.emptyList();
            }

            List<UserModel> searchResults = new LinkedList<>();

            for (LDAPObject ldapUser : ldapObjects) {
                String username = MdLDAPUtils.getUsername(ldapUser, getMappedUsernameLdapAttribute(realm));
                UserModel localUser = session.userLocalStorage().getUserByUsername(username, realm);
                if (localUser == null) {
                    UserModel imported = importUserFromLDAP(session, realm, ldapUser);
                    if (imported != null) {
                        searchResults.add(imported);
                    }
                } else {
                    searchResults.add(proxy(realm, localUser, ldapUser, false));
                }
            }

            return searchResults;
        }
    }

    @Override
    public List<UserModel> loadUsersByUsernames(List<String> krbUserNames, RealmModel realm) {
        //krbUserNames contains krbUserNames here (sAMAccountName for AD)
        List<UserModel> result = new ArrayList<>();
        List<String> kerberosRealms = MdLDAPUtils.getKerberosRealms(kerberosConfig);
        for (String krbUsername : krbUserNames) {
            //UserModel kcUser = session.users().getUserByUsername(krbUsername, realm);
            String domain = extractUserDomain(krbUsername);
            String username = extractUsername(krbUsername);
            if (domain.isEmpty() && kerberosRealms.size() == 1){
                domain = kerberosRealms.get(0);
            }
            String krpPrincipal = username;
            if (!domain.isEmpty()){
                krpPrincipal = krpPrincipal +'@' + domain;
            }
            UserModel kcUser = null;
            if (model.isImportEnabled() && !domain.isEmpty()) {
                FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(
                        model.getProviderId(),
                        krpPrincipal,
                        "" /* ignored */);
                kcUser = session.users().getUserByFederatedIdentity(federatedIdentityModel, realm);
            }

            if (kcUser == null) {
                //TODO
                Map<String, String> params = Collections.singletonMap(LDAP_SEARCH_BY_KRB_USERNAME, krpPrincipal);
                //List<UserModel> userModels = session.users().searchForUser(params, realm);
                List<UserModel> userModels = searchForUser(params, realm);
                if (userModels.size() == 1) {
                    kcUser = userModels.get(0);
                }
            }

            if (kcUser == null) {
                logger.warnf("User '%s' referenced by membership wasn't found in LDAP", krbUsername);
            } else if (model.isImportEnabled() && !model.getId().equals(kcUser.getFederationLink())) {
                logger.warnf("Incorrect federation provider of user '%s'", kcUser.getUsername());
            } else {
                result.add(kcUser);
            }
        }
        return result;
    }

    public String getMappedUsernameLdapAttribute(RealmModel realm) {

        String ldapAttribute = "";
        List<ComponentModel> mapperModels = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
        //List<ComponentModel> mapperModels = mapperManager.sortMappersAsc(mapperModels);
        for (ComponentModel mapperModel : mapperModels) {
            if (UserAttributeLDAPStorageMapperFactory.PROVIDER_ID.equals(mapperModel.getProviderId())) {
                MultivaluedHashMap<String, String> config = mapperModel.getConfig();
                String modelAttributeName = config.getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
                if (UserModel.USERNAME.equals(modelAttributeName)) {
                    ldapAttribute = config.getFirst(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE);
                    break;
                }
            }
        }
        if (ldapAttribute == null || ldapAttribute.isEmpty()){
            ldapAttribute = getLdapIdentityStore().getConfig().getUsernameLdapAttribute();
        }
        return ldapAttribute;

    }

    private String extractUsername(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? authenticatedKerberosPrincipal : authenticatedKerberosPrincipal.substring(0, i);
    }

    private String extractUserDomain(String authenticatedKerberosPrincipal) {
        int i = authenticatedKerberosPrincipal.indexOf('@');
        return i < 0 ? "" : authenticatedKerberosPrincipal.substring(i + 1).toUpperCase();
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
                List<String> realms = MdLDAPUtils.getKerberosRealms(mdUserProvider.kerberosConfig);
                if (realms.contains(userDomainUc)){
                    result.add(mdUserProvider);
                }
            }
        }
        return result;
    }

    private static <T> List<T> getEnabledStorageProviders(KeycloakSession session, RealmModel realm, Class<T> type) {
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
}
