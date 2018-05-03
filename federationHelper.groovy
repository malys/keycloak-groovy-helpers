package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.SynchronizationResultRepresentation
/**
 * RH-SSO Federation helpers
 */
def applyRoles(final String compName, roles, ComponentRepresentation component, RealmResource realmResource, rp, comm) {

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
        comm.checkResponse(realmResource.components().add(compPres), "Applying roles", rp)
    }
}


def triggerUpdate(ComponentRepresentation component, RealmResource realmResource, rp, comH) {
    SynchronizationResultRepresentation syncResult = realmResource.userStorage().syncUsers(component.id, "triggerFullSync")

    if (syncResult && (syncResult.added > 0 || syncResult.updated > 0)) {
        rp.add(new Report("Federation ${component.name} synchronisation: ${syncResult.status}", Report.Status.Success)).start().stop()
    } else {
        rp.add(new Report("Federation ${component.name} synchronisation", Report.Status.Fail)).start().stop()
    }
}



