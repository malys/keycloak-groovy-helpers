package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.admin.client.resource.RolesResource
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.RealmRepresentation
import org.keycloak.representations.idm.RoleRepresentation

/**
 * RH-SSO Realm helpers
 */
def createRealm(final String realmName, final String sslReq, Keycloak k, log, comH) {
    RealmRepresentation real = new RealmRepresentation()
    real.with {
        id = realmName
        realm = realmName
        enabled = true
        bruteForceProtected = true
        failureFactor = 10
        offlineSessionIdleTimeout = 43200 // 12hours
        sslRequired = "all"
        eventsEnabled = true
        eventsExpiration = 43200 // 12hours
        adminEventsEnabled = true
        adminEventsDetailsEnabled = true

    }
    if (sslReq) {
        real.sslRequired = sslReq //external
    }

    RealmResource realmResource = null
    try {
        realmResource = k.realm(realmName)
        realmResource.toRepresentation()
    }
    catch (Exception e) {
        realmResource = null
    }

    if (realmResource == null) {
        k.realms().create(real)
        realmResource = k.realm(realmName)
        if (realmResource) {
            log.info("Realm $realmName created")
        } else {
            log.info("Realm $realmName failed")
        }
    } else {
        log.info("Realm $realmName yet installed")
    }
    return realmResource
}


def add(final String realmName, final String sslReq,
        final String roleName, final String descriptio, Map<String, List<String>> composits,
        Keycloak k, log, comH) {

    RealmResource realmResource = createRealm(realmName, sslReq, k, log, comH)

    addRole(roleName, descriptio, composits, realmResource, log, comH)

    return realmResource
}


def addRole(final String roleName,
            final String descriptio,
            Map<String, List<String>> composits,
            RealmResource realmResource,
            log, comH) {

    RolesResource roleRes = realmResource.roles()

    RoleRepresentation role

    if (roleRes && roleRes.list()) {
        role = roleRes.list().find {
            RoleRepresentation r ->
                r.name == roleName
        }
    }
    if (role == null) {
        role = new RoleRepresentation()
        role.with {
            id = roleName
            name = roleName
            description = descriptio
        }

        if (composits) {
            role.composite = true
        }
        realmResource.roles().create(role)
        role = realmResource.roles().get(roleName).toRepresentation()
        if (composits) {
            realmResource.rolesById().addComposites(role.getId(), getRolesRepresentation(composits, realmResource))
        }
    }

    return role
}

def getRolesRepresentation(final Map<String, List<String>> composits,
                           RealmResource realmResource) {

    List<RoleRepresentation> list = []

    composits.each { String clientName, List<String> roleNames ->
        List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientName)
        if (clients && clients.size() > 0) {
            list.addAll(realmResource.clients().get(clients.get(0).id).roles().list().findAll {
                roleNames.contains(it.name)
            })
        }

    }

    return list
}