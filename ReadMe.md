# Keycloak configuration helpers

Groovy helpers for Keycloak configuration as code.
Groovy helpers apply OIDC guidelines, nomenclatures.

Flexible, powerful based on [Keycloak Admin REST Client](https://mvnrepository.com/artifact/org.keycloak/keycloak-admin-client).

## Table of Contents
<details><summary>display</summary>

- [Keycloak configuration helpers](#keycloak-configuration-helpers)
  - [Table of Contents](#table-of-contents)
  - [Installing](#installing)
  - [Usage](#usage)
  - [Features](#features)
    - [realmHelpers](#realmhelpers)
    - [clientHelpers](#clienthelpers)
    - [userHelpers](#userhelpers)
    - [federationHelper](#federationhelper)
    - [idpHelper](#idphelper)
    - [ldapHelper](#ldaphelper)
    - [restFederationHelper](#restfederationhelper)
  - [Built With](#built-with)

</details>

## Installing

Use this project like a git module in your Keycloak configuration project

## Usage


```groovy
import org.keycloak.admin.client.Keycloak
import org.keycloak.representations.idm.UserRepresentation

import java.nio.file.Path

/***
 * Example
 */
Keycloak k = kc
String cRealm = currentRealm
String cClient = currentClient
String cUser = currentUser

//load com.lyra.scripts
comH = new commonHelper()
ldapH = new ldapHelper()
fedH = new federationHelper()
realmH = new realmHelper()
restFedH = new restFederationHelper()
clientH = new clientHelper()

def checkResponse(javax.ws.rs.core.Response result) {
    if (result.getStatus() != 201) {
        System.err.println("Couldn't create myUser." + result.getStatus())
        System.exit(0)
    }
}

//======================== Create Realm
def myRealmId = "master"

//======================== Read users
List<UserRepresentation> result = k.realm(myRealmId).users().search("nicko", 0, 1)

if (result != null && result.size() > 0) {
    println("User ${result.get(0).username} detected")
}
```


## Features

* Autocompletion
* Nomenclature / Formatter

| component             | style       | style description                            | example                     |
| --------------------- | ----------- | -------------------------------------------- | --------------------------- |
|                       |             |                                              |                             |
| realm/client/template | kebab       | lower case with dash -                       | test                        |
| business role         | upper snake | uppercase (PREFIX_ROLE with underscore (_) ) | PRE_ADMIN                   |
| platform role         | kebab       | lower case with dash -                       | realm-management, api-admin |
| theme                 | kebab       | lower case with dash -                       | collect                     |
| Valid redirect URL    | url         | domains without ( * ) ended bye "/*"         |                             |
| Web origin            | url         | domain name ONLY                             |                             |
|                       |             |                                              |                             |

* Generate standard clients

### realmHelpers

* Create/Update realm
* Role management

### clientHelpers

* Create Client
* Create Service Account
* Create Client template
* Role management

### userHelpers

* Create user
* Role management
* Scope management
* Group management
* Password change

### federationHelper

* Trigger
* Role management
* Group management

### idpHelper

* Create identity provider

### ldapHelper

* Create LDAP federation

### restFederationHelper

* Create [REST federation](https://github.com/malys/keycloak-rest_federation)

## Built With

* [JAVA >= 1.8](https://www.java.com/fr/) 
* [Groovy >=3](https://groovy-lang.org/)
* [Keycloak >=3.4](https://www.keycloak.org/)