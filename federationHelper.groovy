package helpers

import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.GroupRepresentation
import org.keycloak.representations.idm.RoleRepresentation
import org.keycloak.representations.idm.SynchronizationResultRepresentation

/**
 * RH-SSO Federation helpers
 */

/**
 * LDAP group mapper synchronization
 */
def applyGroupMapper(final String compName, groupsLdap, ComponentRepresentation component, RealmResource realmResource, log, comH) {
    if("ON" == System.getProperty("MOCK")) return
    ComponentRepresentation compPres = new ComponentRepresentation()
    //Import groups
    compPres.with {
        name = compName
        providerId = "group-ldap-mapper"
        providerType = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        parentId = component.id
        config = new MultivaluedHashMap<>()
        config['drop.non.existing.groups.during.sync'] = ["false"]
        config['group.name.ldap.attribute'] = ["cn"]
        config['group.object.classes'] = ["groupOfNames"]
        config['groups.dn'] = [groupsLdap] //cn=groups,cn=accounts,...
        config['groups.ldap.filter'] = []
        config['ignore.missing.groups'] = ["true"]
        config['mapped.group.attributes'] = []
        config['memberof.ldap.attribute'] = ["memberOf"]
        config['membership.attribute.type'] = ["DN"]
        config['membership.ldap.attribute'] = ["member"]
        config['membership.user.ldap.attribute'] = ["uid"]
        config['mode'] = ["READ_ONLY"]
        config['preserve.group.inheritance'] = ["false"]
        config['user.roles.retrieve.strategy'] = ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"]
    }

    List<ComponentRepresentation> components = realmResource.components().query(component.id,
            "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            compName)

    if (components.size() > 0) {
        log.info("Component ${components.get(0).name} yet installed")
    } else {
        comH.checkResponse(realmResource.components().add(compPres), "Component $compName created", log)
        components = realmResource.components().query(component.id,
                "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                compName)
    }
    ///Synchronization
    SynchronizationResultRepresentation syncResult = realmResource.userStorage().syncMapperData(component.id, components.get(0).id, "fedToKeycloak")

    if (syncResult && (syncResult.added > 0 || syncResult.updated > 0)) {
        log.info("Group ${component.name} synchronisation: ${syncResult.status}")
    } else {
        log.error("Group ${component.name} synchronisation")
    }
}

/**
 * Set role to group
 */
def applyRoleToGroup(String groupName, String roleName, RealmResource realmResource, log, comH) {
    if("ON" == System.getProperty("MOCK")) return
    try {
        RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation()
        GroupRepresentation groupR = realmResource.groups().groups(groupName, 0, 1)[0]
        realmResource.groups().group(groupR.id).roles().realmLevel().add([role])

        log.info("Set ${roleName} to ${groupName} group")
    } catch (Exception e) {
        log.error("Role $roleName added to ${groupName}:" + e.message)
    }
}

def applyRoles(final String roleCompName, String groupsLdap, Map<String, String> groupRoles, ComponentRepresentation component, RealmResource realmResource, log, comH) {
    if("ON" == System.getProperty("MOCK")) return
    //Import LDAP group
    applyGroupMapper(roleCompName, groupsLdap, component, realmResource, log, comH)

    // Affect ex: [ldapAdmin: "ldap-admin-roles"]
    if (groupRoles) groupRoles.each { k, v -> applyRoleToGroup(k, v, realmResource, log, comH) }
}

def hardRoles(final String compName, roles, ComponentRepresentation component, RealmResource realmResource, log, comH) {
    if("ON" == System.getProperty("MOCK")) return
    ComponentRepresentation compPres = new ComponentRepresentation()
    //Add new ldap component
    compPres.with {
        name = compName
        providerId = "hardcoded-ldap-role-mapper"
        providerType = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
        parentId = component.id
        config = new MultivaluedHashMap<>()
    }

    if (roles) {
        compPres.config.role = roles
        List<ComponentRepresentation> list = realmResource.components().query(component.id, compPres.providerType, compPres.name)

        if (list && list.size() > 0) {
            log.info("Role ${component.name} yet installed")
        } else {
            comm.checkResponse(realmResource.components().add(compPres), "Applying role  ${component.name}", log)
        }
    }
}


def triggerUpdate(ComponentRepresentation component, RealmResource realmResource, log, comH) {
    if("ON" == System.getProperty("MOCK")) return
    SynchronizationResultRepresentation syncResult = realmResource.userStorage().syncUsers(component.id, "triggerFullSync")

    if (syncResult && (syncResult.added > 0 || syncResult.updated > 0)) {
        log.info("Federation ${component.name} synchronisation: ${syncResult.status}")
    } else {
        log.error("Federation ${component.name} synchronisation")
    }
}



