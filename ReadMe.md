# Keycloak Admin Client groovy helpers

Provide helpers to consume Keycloak admin client (**v3.4.x**) in groovy with [Lyra](https://lyra.com) Deployer.

## Example

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
Path p = scriptPath

//load scripts
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
