package helpers

import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.admin.client.resource.RolesResource
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.RealmRepresentation
import org.keycloak.representations.idm.RoleRepresentation

/**
 * RH-SSO Realm helpers
 */
def updateEventsRealm(RealmRepresentation real) {
    updateEventsRealm(real,["eventsListeners":["logDetail"]])
}

def updateEventsRealm(RealmRepresentation real,final Map conf) {
    real.with {
        eventsEnabled = true
        eventsListeners = conf['eventsListeners']
        eventsExpiration = 43200 // 12hours
        adminEventsEnabled = true
        adminEventsDetailsEnabled = true
    }
}


def updateSMTP(noReply,RealmRepresentation real) {
    real.smtpServer = [auth: "", from: noReply, host: "localhost", port: null, ssl: "", starttls: ""]
}

def createRealm(final Map conf, Keycloak k, log, comH) {
    String realmName = comH.applyNomenclature(conf.realm)

    RealmRepresentation real = new RealmRepresentation()
    real.with {
        id = conf.realm
        realm = conf.realm
        enabled = true
        bruteForceProtected = true
        failureFactor = 10
        offlineSessionIdleTimeout = 43200 // 12hours
        internationalizationEnabled = conf.internationalizationEnabled ? conf.internationalizationEnabled : false
        loginWithEmailAllowed = conf.loginWithEmailAllowed ? conf.loginWithEmailAllowed : false
        registrationAllowed = conf.registrationAllowed ? conf.registrationAllowed : false
        registrationEmailAsUsername = conf.registrationEmailAsUsername ? conf.registrationEmailAsUsername : false
        rememberMe = conf.rememberMe ? conf.rememberMe : false
        resetPasswordAllowed = conf.resetPasswordAllowed ? conf.resetPasswordAllowed : false
        verifyEmail = conf.verifyEmail ? conf.verifyEmail : false
        sslRequired = conf.sslRequired ? conf.sslRequired : "all" // for security
    }
    if ("ON" == System.getProperty("MOCK")) real.sslRequired='none'

    updateSMTP(conf.noReply, real)
    updateEventsRealm(real)

    if (conf.loginTheme) real.loginTheme = conf.loginTheme
    if (conf.accountTheme) real.accountTheme = conf.accountTheme
    if (conf.adminTheme) real.adminTheme = conf.adminTheme
    if (conf.emailTheme) real.emailTheme = conf.emailTheme

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


def add(final Map conf,
        final String roleName, final String descriptio, Map<String, List<String>> composits,
        Keycloak k, log, comH) {

    RealmResource realmResource = createRealm(conf, k, log, comH)

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
            list.addAll(realmResource.clients().get(clients.get(0).id).roles().list().findAll { it ->
                roleNames.contains(it.name)
            })
        }

    }

    return list
}
