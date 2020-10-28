Провайдер "keycloak-md-ldap-federation" для Keycloak  
====================================================================================

Штатный провайдер "LDAP User Federation" (LDAPFederationProvider), на практике, позволяет аутентифицировать по Kerberos 
пользователей из разных Kerberos-доменов только в одной конфигурации, когда домены имеют взаимное доверие 
и есть общий Global LDAP-каталог, агрегирующий каталоги всех доменов.
   
Данный провайдер аналогичен "LDAP User Federation", но поддерживает конфигурацию, когда пользователи,
аутентифицирующиеся в Keycloak по Kerberos, находятся в независимых доменах. Global LDAP-каталог также не требуется. 

>**ВНИМАНИЕ**: Данный провайдер замещает штатного LDAPFederationProvider провайдера (с идентификатором 'ldap'). Так что
ранее настроенная интеграция с LDAP через LDAPFederationProvider может изменить своё поведение. 
Поведение KerberosFederationProvider (с идентификатором 'kerberos') останется не изменным.


Настройка 
---------
Следуйте [официальной инструкции](https://www.keycloak.org/docs/latest/server_admin/#setup-and-configuration-of-keycloak-server). 
Для правильной работы данного провайдера есть дополнительные требования:

**1)** Во всех настройках "LDAP Kerberos Integration" должны быть указаны одинаковые значения: 
- `Server Pricipal` = `*` (звезда)
- `KeyTab`=`<file>` (один общий KeyTab файл)

>**Примечание**. В текущей версии Keycloak (11.0.2) на этапе Kerberos-аутентификации применяется только одна настройка
"LDAP Kerberos Integration", имеющая наименьший приоритет. Значения этих 2 полей в других настройках значения не имеют.*

**2)** В настройке "LDAP Kerberos Integration" в поле `Kerberos Realm ` через "`,`" (запятую) перечисляются AD-домены,
 учётные данные пользователей которых будут считываться из данного LDAP-каталога или записываться в него. 
 Один домен может присутствовать в нескольких настройках "LDAP User Federation". Если пользователь отсутствует
 в хранилище Keycloak, то берутся "LDAP User Federation" соответствующие домену пользователя и в порядке приоритета от
 наименьшего до первого успеха производится попытка считывания учётки соответствующих в LDAP-каталогах.
 Если учётка пользователя уже загружена в хранилище Keycloak из одного из LDAP-каталогов ранее, то она актуализируется 
 по LDAP-каталогу из которого была изначально загружена. Первичная загрузка учётки может произойти в результате 
 синхронизации по расписанию, настроенной в "LDAP User Federation" или при запуске синхронизации в ручную по кнопке
 "Synchronize all users" или "Synchronize changed users" в "LDAP User Federation". 

**3)** В настройке "LDAP Kerberos Integration" в поле "Username Attribute in LDAP" должно быть задано имя атрибута в LDAP,
 содержащего значение Kerberos principal name, передаваемого в kerberos-токене без или с именем домена. Для AD
 значением ДОЛЖНО быть sAMAccountName.

**4)** В качестве уникального имени пользователя в Keycloak (значение поле "User name") при импорте из LDAP по-умолчанию
используется значение из атрибута, заданного в поле "Username Attribute in LDAP". Используемый атрибут LDAP можно
переопределить, создав mapper типа "user-attribute-ldap-mapper" в настройке "LDAP Kerberos Integration". 
В настройке mapper в поле "User Model Attribute" указывается значение "username", а в поле "LDAP Attribute"
имя атрибута в LDAP-каталоге содержащего уникальное имя пользователя. Для AD обычно используют атрибут CN или userPrincipalName.
Если при создании настройки "LDAP Kerberos Integration" в качестве провайдера указано "Active Directory",
то такой mapper будет добавлен автоматически под именем "username" и с атрибутом CN в LDAP.   

>**Важно.**
>
>Если "Authentication Flow" допускает, что пользователи могут аутентифицироваться не только через
>Kerberos, то уникальные имена пользователей, импортированные из разных LDAP-каталогов, должны оказаться уникальными
>среди всех учётных записей в Keycloak.
  
**5)** В общем файле KeyTab должны быть ключи для SPN (Service Principal Name) всех доменов.
 
**6)** Обязательно должен быть указан Kerberos реалм по-умолчанию. Либо через системное св-во
 [java.security.krb5.realm](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html),
  либо в файле krb5.conf. В случае Keycloak это имя домена может быть любым.
```
[libdefaults]    
	default_realm = ANY
```
 
 
Установка провайдера в Keycloak
-----------
  Следуйте [официальной инструкции](https://www.keycloak.org/docs/latest/server_development/#registering-provider-implementations).
  Самый простой способ - это  поместить jar-файл провайдера в папку `standalone/deploymens` Keycloak.

> **Важно** Данный провайдер должен запускаться после штатного LDAPFederationProvider. 
 
Примечания
-----------
**1)** Поскольку в токенах Kerberos (TGT, ST), выданном KDC Active Directory, идентификатор пользователя имеет формат
```
sAMAccountName@domain
```     
рекомендуется мэппить Username учётной записи в Keycloak на поле`sAMAccountName` в LDAP-каталоге.
Для этого в настройке `LDAP User Federation` в поле `Username LDAP attribute`  следует указать `sAMAccountName`
и на закладке `Mappers` для мэппера `username` в поле `LDAP Attribute` тоже указать `sAMAccountName`.

Чтобы не импортировать системные учётные записи Active Directory в "Custom LDAP users filter" рекомендуется добавить условие:
``` 
 (!(isCriticalSystemObject=TRUE))
```
**2)** 
[Статья, как выпускать keyTab для нескольких SPN.](https://blog.it-kb.ru/2017/03/24/how-to-create-keytab-file-with-additional-kerberos-service-principal-on-windows-server-and-linux/)
  
Уточнение по KVNO в KeyTab. KVNO (Key Version Number) используется при поиске ключа в KeyTab, соответствующего
предоставленному ST (Service Ticket), тоже содержащему свой KVNO. Обозначим KVNO в KeyTab как kv, а KVNO в ST как stv.
При поиске ключа в KeyTab, по порядку перебираются ключи, соответствующие запрошенному алгоритму шифрования.
Берётся первый ключ, удовлетворяющий нижеследующим условиям в порядке приоритета:
- kv=0 ИЛИ stv=0
- kv=stv
- Наибольшее kv

**3)** Параметры JVM для диагностики проблем при Kerberos-аутентификации:
```
-Dsun.security.krb5.debug=true
-Dsun.security.spnego.debug=true 
-Dsun.security.jgss.debug=true
-Djava.security.debug=gssloginconfig,configfile,configparser,logincontext
```   
**4)** Keycloak под капотом использует Krb5LoginModule [[ссылка RU]](http://spec-zone.ru/RU/Java/Docs/8/jre/api/security/jaas/spec/com/sun/security/auth/module/Krb5LoginModule.html),
[[ссылка EN]](https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/module/Krb5LoginModule.html).
Который конфигурируется файлом krb5.conf [[ссылка EN]](http://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html).
Правило поиска krb5.conf [[ссылка EN]](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html). 
 
**5)** [Описание протокола Kerberos](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/kerberos-for-the-busy-admin/ba-p/395083)