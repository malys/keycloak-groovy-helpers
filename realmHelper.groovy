package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.RealmRepresentation
import org.keycloak.representations.idm.RoleRepresentation

/**
 * RH-SSO Realm helpers
 */
def createRealm(final String realmName, final String sslReq, Keycloak k, rp, comH) {
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
            rp.add(new Report("Realm $realmName created", Report.Status.Success)).start().stop()
        } else {
            rp.add(new Report("Realm $realmName failed", Report.Status.Success)).start().stop()
        }
    } else {
        rp.add(new Report("Realm $realmName yet installed", Report.Status.Success)).start().stop()
    }



    return realmResource
}


def add(final String realmName, final String sslReq,
        final String roleName, final String descriptio, RoleRepresentation.Composites composits,
        Keycloak k, rp, comH) {

    RealmResource realmResource = createRealm(realmName, sslReq, k, rp, comH)

    addRole(roleName, descriptio, composits, realmResource, rp, comH)
}


def addRole(final String roleName,
            final String descriptio,
            RoleRepresentation.Composites composits,
            RealmResource realmResource,
            rp, comH) {

    List<RoleRepresentation> roles = realmResource.roles().list().find {
        RoleRepresentation r ->
            r.name == roleName
    }
    RoleRepresentation role
    if (roles.size() > 0) {
        role = roles.get(0)
    } else {
        role = new RoleRepresentation()
        role.with {
            id = roleName
            name = roleName
            description = descriptio
        }

        if (composits) {
            role.composite = true
            role.composites = composits
        }
        realmResource.roles().create(role)
    }

    return role
}
