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
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.federation.kerberos.CommonKerberosConfig;
import org.keycloak.federation.kerberos.impl.KerberosServerSubjectAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPIdentityStoreRegistry;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;
import org.keycloak.storage.ldap.kerberos.LDAPProviderKerberosConfig;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.UserAttributeLDAPStorageMapperFactory;
import org.keycloak.storage.user.SynchronizationResult;

import java.util.Date;
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
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        super.onCreate(session, realm, model);
        LDAPConfig ldapConfig = new LDAPConfig(model.getConfig());
       /* UserStorageProviderModel providerModel = new UserStorageProviderModel(model);
        boolean importEnabled = providerModel.isImportEnabled();*/

        UserStorageProvider.EditMode editMode = ldapConfig.getEditMode();
        String readOnly = String.valueOf(editMode == UserStorageProvider.EditMode.READ_ONLY || editMode == UserStorageProvider.EditMode.UNSYNCED);

        boolean activeDirectory = ldapConfig.isActiveDirectory();
        if (activeDirectory) {
            List<ComponentModel> mapperModels = realm.getComponents(model.getId(), LDAPStorageMapper.class.getName());
            for (ComponentModel mapperModel : mapperModels) {
                if (UserAttributeLDAPStorageMapperFactory.PROVIDER_ID.equals(mapperModel.getProviderId())) {
                    MultivaluedHashMap<String, String> config = mapperModel.getConfig();
                    String modelAttributeName = config.getFirst(UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE);
                    if (UserModel.USERNAME.equals(modelAttributeName)) {
                        //config.putSingle(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, "userPrincipalName");
                        config.putSingle(UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.CN);
                        realm.updateComponent(mapperModel);
                        break;
                    }
                }
            }
            String usernameLdapAttribute = ldapConfig.getUsernameLdapAttribute();
            if (usernameLdapAttribute.equalsIgnoreCase(LDAPConstants.SAM_ACCOUNT_NAME)) {
                // For AD deployments with "sAMAccountName" as username, we will map "givenName" to first name.
                // For AD deployments with "CN" as username the super class do the same.
                String alwaysReadValueFromLDAP = String.valueOf(editMode== UserStorageProvider.EditMode.READ_ONLY || editMode== UserStorageProvider.EditMode.WRITABLE);
                ComponentModel mapperModel = MdKeycloakModelUtils.createComponentModel("first name", model.getId(), UserAttributeLDAPStorageMapperFactory.PROVIDER_ID,LDAPStorageMapper.class.getName(),
                        UserAttributeLDAPStorageMapper.USER_MODEL_ATTRIBUTE, UserModel.FIRST_NAME,
                        UserAttributeLDAPStorageMapper.LDAP_ATTRIBUTE, LDAPConstants.GIVENNAME,
                        UserAttributeLDAPStorageMapper.READ_ONLY, readOnly,
                        UserAttributeLDAPStorageMapper.ALWAYS_READ_VALUE_FROM_LDAP, alwaysReadValueFromLDAP,
                        UserAttributeLDAPStorageMapper.IS_MANDATORY_IN_LDAP, "true");
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

        if (ldapConfig.isActiveDirectory() && kerberosConfig.isAllowKerberosAuthentication()
            && !ldapConfig.getUsernameLdapAttribute().equalsIgnoreCase(LDAPConstants.SAM_ACCOUNT_NAME)){
            throw new ComponentValidationException("User name LDAP attribute has to be 'sAMAccountName' for Active Directory provider and enabled Kerberos integration");
        }
        if (ldapConfig.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
            throw new ComponentValidationException("LDAP WRITE mode is not supported by third party provider \"keycloak-md-ldap-federation\"");
        }

        String editModeString = config.getConfig().getFirst(LDAPConstants.EDIT_MODE);
        if (editModeString == null || editModeString.isEmpty()) {
            config.getConfig().putSingle(LDAPConstants.EDIT_MODE, UserStorageProvider.EditMode.READ_ONLY.name());
        }

        if (ldapConfig.getUsernameLdapAttribute().equalsIgnoreCase(LDAPConstants.SAM_ACCOUNT_NAME)){
            config.getConfig().putSingle(LDAPConstants.USERNAME_LDAP_ATTRIBUTE, LDAPConstants.SAM_ACCOUNT_NAME);
        }

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

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        syncMappers(sessionFactory, realmId, model);

        logger.infof("Sync all users from LDAP to local store: realm: %s, federation provider: %s", realmId, model.getName());

        try (LDAPQuery userQuery = mdCreateQuery(sessionFactory, realmId, model)) {
            SynchronizationResult syncResult = syncImpl(sessionFactory, userQuery, realmId, model);

            // TODO: Remove all existing keycloak users, which have federation links, but are not in LDAP. Perhaps don't check users, which were just added or updated during this sync?

            logger.infof("Sync all users finished: %s", syncResult.getStatus());
            return syncResult;
        }
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        syncMappers(sessionFactory, realmId, model);

        logger.infof("Sync changed users from LDAP to local store: realm: %s, federation provider: %s, last sync time: " + lastSync, realmId, model.getName());

        // Sync newly created and updated users
        LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();
        Condition createCondition = conditionsBuilder.greaterThanOrEqualTo(LDAPConstants.CREATE_TIMESTAMP, lastSync);
        Condition modifyCondition = conditionsBuilder.greaterThanOrEqualTo(LDAPConstants.MODIFY_TIMESTAMP, lastSync);
        Condition orCondition = conditionsBuilder.orCondition(createCondition, modifyCondition);

        try (LDAPQuery userQuery = mdCreateQuery(sessionFactory, realmId, model)) {
            userQuery.addWhereCondition(orCondition);
            SynchronizationResult result = syncImpl(sessionFactory, userQuery, realmId, model);

            logger.infof("Sync changed users finished: %s", result.getStatus());
            return result;
        }
    }

    @Override
    protected SynchronizationResult importLdapUsers(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel fedModel, List<LDAPObject> ldapUsers) {
        final SynchronizationResult syncResult = new SynchronizationResult();

        class BooleanHolder {
            private boolean value = true;
        }
        final BooleanHolder exists = new BooleanHolder();

        for (final LDAPObject ldapUser : ldapUsers) {

            try {

                // Process each user in it's own transaction to avoid global fail
                MdKeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {

                    MdLDAPStorageProvider ldapFedProvider = (MdLDAPStorageProvider)session.getProvider(UserStorageProvider.class, fedModel);
                    RealmModel currentRealm = session.realms().getRealm(realmId);
                    session.getContext().setRealm(currentRealm);

                    //String username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                    String username = MdLDAPUtils.getUsername(ldapUser, ldapFedProvider.getMappedUsernameLdapAttribute(currentRealm));
                    exists.value = true;
                    LDAPUtils.checkUuid(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                    UserModel currentUser = session.userLocalStorage().getUserByUsername(username, currentRealm);

                    if (currentUser == null) {

                        // Add new user to Keycloak
                        exists.value = false;
                        ldapFedProvider.importUserFromLDAP(session, currentRealm, ldapUser);
                        syncResult.increaseAdded();

                    } else {
                        if ((fedModel.getId().equals(currentUser.getFederationLink())) && (ldapUser.getUuid().equals(currentUser.getFirstAttribute(LDAPConstants.LDAP_ID)))) {

                            // Update keycloak user
                            List<ComponentModel> federationMappers = currentRealm.getComponents(fedModel.getId(), LDAPStorageMapper.class.getName());
                            List<ComponentModel> sortedMappers = ldapFedProvider.getMapperManager().sortMappersDesc(federationMappers);
                            for (ComponentModel mapperModel : sortedMappers) {
                                LDAPStorageMapper ldapMapper = ldapFedProvider.getMapperManager().getMapper(mapperModel);
                                ldapMapper.onImportUserFromLDAP(ldapUser, currentUser, currentRealm, false);
                            }
                            UserCache userCache = session.userCache();
                            if (userCache != null) {
                                userCache.evict(currentRealm, currentUser);
                            }
                            logger.debugf("Updated user from LDAP: %s", currentUser.getUsername());
                            syncResult.increaseUpdated();
                        } else {
                            logger.warnf("User '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'", username, fedModel.getName());
                            syncResult.increaseFailed();
                        }
                    }
                });
            } catch (ModelException me) {
                logger.error("Failed during import user from LDAP", me);
                syncResult.increaseFailed();

                // Remove user if we already added him during this transaction
                if (!exists.value) {
                    MdKeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

                        @Override
                        public void run(KeycloakSession session) {
                            MdLDAPStorageProvider ldapFedProvider = (MdLDAPStorageProvider)session.getProvider(UserStorageProvider.class, fedModel);
                            RealmModel currentRealm = session.realms().getRealm(realmId);
                            session.getContext().setRealm(currentRealm);

                            String username = null;
                            try {
                                //username = LDAPUtils.getUsername(ldapUser, ldapFedProvider.getLdapIdentityStore().getConfig());
                                username = MdLDAPUtils.getUsername(ldapUser, ldapFedProvider.getMappedUsernameLdapAttribute(currentRealm));
                            } catch (ModelException ignore) {
                            }

                            if (username != null) {
                                UserModel existing = session.userLocalStorage().getUserByUsername(username, currentRealm);
                                if (existing != null) {
                                    UserCache userCache = session.userCache();
                                    if (userCache != null) {
                                        userCache.evict(currentRealm, existing);
                                    }
                                    session.userLocalStorage().removeUser(currentRealm, existing);
                                }
                            }
                        }

                    });
                }
            }
        }

        return syncResult;
    }


    /**
     *  !! This function must be called from try-with-resources block, otherwise Vault secrets may be leaked !!
     * @param sessionFactory
     * @param realmId
     * @param model
     * @return
     */
    private LDAPQuery mdCreateQuery(KeycloakSessionFactory sessionFactory, final String realmId, final ComponentModel model) {
        class QueryHolder {
            LDAPQuery query;
        }

        final QueryHolder queryHolder = new QueryHolder();
        MdKeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            @Override
            public void run(KeycloakSession session) {
                session.getContext().setRealm(session.realms().getRealm(realmId));

                LDAPStorageProvider ldapFedProvider = (LDAPStorageProvider)session.getProvider(UserStorageProvider.class, model);
                RealmModel realm = session.realms().getRealm(realmId);
                session.getContext().setRealm(realm);
                queryHolder.query = MdLDAPUtils.createQueryForUserSearch(ldapFedProvider, realm);
            }

        });
        return queryHolder.query;
    }
 }
