package ru.intertrust.keycloak.ldap_md;

public enum LDAPConstants {
    ;
    // Custom attributes on UserModel, which is mapped to LDAP
    public static final String LDAP_ID = "LDAP_ID";
    public static final String LDAP_ENTRY_DN = "LDAP_ENTRY_DN";

    public static final String GIVENNAME = "givenName";
    public static final String CN = "cn";
    public static final String SN = "sn";
    public static final String SAM_ACCOUNT_NAME = "sAMAccountName";

    public static final String EDIT_MODE = "editMode";
    public static final String USERNAME_LDAP_ATTRIBUTE = "usernameLDAPAttribute";

    public static final String CREATE_TIMESTAMP = "createTimestamp";
    public static final String MODIFY_TIMESTAMP = "modifyTimestamp";
}
