package helpers

import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.RoleRepresentation
import org.keycloak.representations.idm.UserRepresentation

import javax.ws.rs.core.Response
/**
 * RH-SSO User helpers
 */
def createUser(
        final String userNam,
        final String firstNam,
        final String lastNam,
        final String emai,
        RealmResource realmResource, log, comH) {

    UserRepresentation user

    List<UserRepresentation> result = realmResource.users().search(userNam, firstNam, lastNam, emai, 0,1)


    if (result != null && result.size() > 0) {
        user = result.get(0)
        log.info("User ${userNam}")
    } else {
        user = new UserRepresentation()
        user.with {
            enabled = true
            username = userNam
            firstName = firstNam
            lastName = lastNam
            email = emai
        }
        Response response = realmResource.users().create(user)
        comH.checkResponse(response, "User $userNam created", log)
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)\$", "\$1")

        user.id = userId
    }

    return user
}


def add(
        final String userNam,
        final String firstNam,
        final String lastNam,
        final String emai,
        final String password,
        RealmResource realmResource, log, comH) {

    UserRepresentation user = createUser(userNam,
            firstNam,
            lastNam,
            emai,
            realmResource, log, comH)

    changePassword(password, user, realmResource, log, comH)
}

def addClientRole(String roleName, UserRepresentation user,
                  final String clientName, RealmResource realmResource, log, comH) {

    // Get client
    ClientRepresentation app1Client = realmResource.clients()
            .findByClientId(clientName).get(0)

    // Get client level role (requires view-clients role)
    RoleRepresentation userClientRole = realmResource.clients().get(app1Client.getId())
            .roles().get(roleName).toRepresentation()
    try {
        // Assign client level role to user
        realmResource.users().get(user.id).roles() //
                .clientLevel(app1Client.getId()).add(Arrays.asList(userClientRole))
        log.info("Role $clientName.$roleName added to ${user.username}")
    } catch (Exception e) {
        log.error("Role $roleName added to ${user.username}:" + e.message)
    }

}

def addRealmRole(String roleName, UserRepresentation user, RealmResource realmResource, log, comH) {

    // Get realm role "tester" (requires view-realm role)
    RoleRepresentation role = realmResource.roles()//
            .get(roleName).toRepresentation()

    // Assign realm role to user
    try {
        realmResource.users().get(user.id).roles().realmLevel().add(Arrays.asList(role))
        log.info("Role ${realmResource.toRepresentation().id}.$roleName added to ${user.username}")
    } catch (Exception e) {
        log.error("Role $roleName added to ${user.username}:" + e.message)
    }


}

def changePassword(String pw, UserRepresentation user, RealmResource realmResource, log, comH) {

    // Define password credential
    CredentialRepresentation passwordCred = new CredentialRepresentation()
    passwordCred.setTemporary(false)
    passwordCred.setType(CredentialRepresentation.PASSWORD)
    passwordCred.setValue(pw)

    // Set password credential
    try {
        realmResource.users().get(user.id).resetPassword(passwordCred)
        log.info("Change password for ${user.username}")
    } catch (Exception e) {
        log.error("Change password for ${user.username}")
    }

}
