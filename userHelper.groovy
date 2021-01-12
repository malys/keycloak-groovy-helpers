package helpers

import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.*

import javax.ws.rs.core.Response

/**
 * RH-SSO User helpers
 */
def createUser(final Map config,
               RealmResource realmResource, log, comH) {

    UserRepresentation user
    List<UserRepresentation> result = realmResource.users().search(config.username, config.firstName, config.lastName, config.email, 0, 1)

    if (result != null && result.size() > 0) {
        user = result.get(0)
        log.info("User ${config.username}")
    } else {
        user = new UserRepresentation()
        user.with {
            enabled = true
            username = config.username
            firstName = config.firstName
            lastName = config.lastName
            email = config.email
        }
        if (config.emailVerified != null) user.emailVerified = config.emailVerified

        if (config.groups) user.setGroups(config.groups)

        Response response = realmResource.users().create(user)
        if (comH.checkResponse(response, "User $user.username created", log)) {
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)\$", "\$1")
            user.id = userId
        }
    }

    return user
}


def add(final Map config,
        RealmResource realmResource, log, comH) {

    UserRepresentation user = createUser(config,
            realmResource, log, comH)

    changePassword(config.password, user, realmResource, log, comH)
    return user
}

def addScopeRole(String fullRoleName, UserRepresentation user,
                 final String clientName, RealmResource realmResource, log, comH) {

    String[] splited = fullRoleName.split("\\.")

    if (splited.size() > 1) {
        clientRoleName = splited[0]
        roleName = splited[1]
    } else {
        clientRoleName = clientName
        roleName = splited[0]
    }

    // Get client
    ClientRepresentation app1Client = realmResource.clients()
            .findByClientId(clientName).get(0)

    ClientRepresentation app2Client = realmResource.clients()
            .findByClientId(clientRoleName).get(0)

    // Get client level role (scope)
    RoleRepresentation userClientRole = realmResource.clients().get(app2Client.id)
            .roles().get(roleName).toRepresentation()
    try {
        // Assign client level role to scope
        realmResource.clients().get(app1Client.getId()).scopeMappings.clientLevel(app2Client.getId()).add(Arrays.asList(userClientRole))

        log.info("Role $clientName.$roleName added to scope for ${user.username}")
    } catch (Exception e) {
        log.error("Role $roleName added to scope for ${user.username}:" + e.message)
    }
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

/*
   Assign Role to a user group
 */

def addRoleToGroup(final Map config, GroupRepresentation groupPres, RealmResource realmResource, realmH, clientH, log) {
    if (config.realmRoles) {
        def roleR = config.realmRoles
        if (config.realmRoles instanceof String) {
            roleR = realmH.getRole(config.realmRoles, realmResource, log)
        }
        realmResource.groups().group(groupPres.id)
                .roles()
                .realmLevel()
                .add([roleR])
        log.info("Role ${config.realmRoles} added to ${groupPres.name}.")
    }

    if (config.clientRoles) {
        def roleR = config.clientRoles
        if (config.clientRoles instanceof String) {
            def tab = config.clientRoles.split('\\.')
            def clientName = tab[0]
            def roleName = tab[1]
            roleR = clientH.getRole(clientName, roleName, realmResource, log)
        }
        realmResource.groups().group(groupPres.id)
                .roles()
                .clientLevel(((RoleRepresentation) roleR).containerId)
                .add([roleR])
        log.info("Role ${config.clientRoles} to ${groupPres.name}.")
    }
}

/*
   Unassign Role to a user group
 */

def removeRoleToGroup(final Map config, GroupRepresentation groupPres, RealmResource realmResource, realmH, clientH, log) {
    if (config.realmRoles) {
        def roleR = config.realmRoles
        if (config.realmRoles instanceof String) {
            roleR = realmH.getRole(config.realmRoles, realmResource, log)
        }
        realmResource.groups().group(groupPres.id)
                .roles()
                .realmLevel()
                .remove([roleR])
        log.info("Role ${config.realmRoles} removed to ${groupPres.name}.")
    }

    if (config.clientRoles) {
        def roleR = config.clientRoles
        if (config.clientRoles instanceof String) {
            def tab = config.clientRoles.split('\\.')
            def clientName = tab[0]
            def roleName = tab[1]
            roleR = clientH.getRole(clientName, roleName, realmResource, log)
        }
        realmResource.groups().group(groupPres.id)
                .roles()
                .clientLevel(((RoleRepresentation) roleR).containerId)
                .remove([roleR])
        log.info("Role ${config.clientRoles} removed to ${groupPres.name}.")
    }
}

def addGroup(final Map config,
             RealmResource realmResource, realmH, clientH, log, comH) {
    GroupRepresentation groupPres = new GroupRepresentation()
    groupPres.name = config.name

    List<GroupRepresentation> result = realmResource.groups().groups(config.name, 0, 1)
    if (result != null && result.size() > 0) {
        groupPres = result.get(0)
        log.info("Group yet created ${config.name}")
    } else {
        try {
            comH.checkResponse(realmResource.groups().add(groupPres), "Group ${config.name} created", log)
            result = realmResource.groups().groups(config.name, 0, 1)
            if (result != null && result.size() > 0) {
                groupPres = result.get(0)
                addRoleToGroup(config, groupPres, realmResource, realmH, clientH, log)
                if (config.subGroups) {
                    realmResource.groups().group(groupPres.id).subGroup(config.subGroups)
                    log.info("Subgroup added")
                }
            }
        } catch (Exception e) {
            log.error("Group creation ${config.name} " + e.getMessage())
        }
    }
    return groupPres
}


