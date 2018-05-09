package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.SynchronizationResultRepresentation

/**
 * RH-SSO Federation helpers
 */
def applyRoles(final String compName, roles, ComponentRepresentation component, RealmResource realmResource, log, comm) {

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
    SynchronizationResultRepresentation syncResult = realmResource.userStorage().syncUsers(component.id, "triggerFullSync")

    if (syncResult && (syncResult.added > 0 || syncResult.updated > 0)) {
        log.info("Federation ${component.name} synchronisation: ${syncResult.status}")
    } else {
        log.error("Federation ${component.name} synchronisation")
    }
}



