package helpers

/**
 * RH-SSO Rest Federation helpers
 */

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.RealmRepresentation

def createFederation(final String fedName, RealmResource realmResource, log, comm, prop) {
    RealmRepresentation realm = realmResource.toRepresentation()

    //Check component
    List<ComponentRepresentation> components = realmResource.components().query(realm.getId(),
            "org.keycloak.storage.UserStorageProvider",
            fedName)

    if (components.size() == 0) {
        ComponentRepresentation compPres = new ComponentRepresentation()
        //Add new ldap component
        compPres.with {
            name = fedName
            providerId = "Rest User Federation"
            providerType = "org.keycloak.storage.UserStorageProvider"
            parentId = realm.id
            config = new MultivaluedHashMap<>()
        }
        compPres.config.with {
            priority = ["0"]
            fullSyncPeriod = ["-1"]
            changedSyncPeriod = ["-1"]
            cachePolicy = ["DEFAULT"]
            evictionDay = []
            evictionHour = []
            evictionMinute = []
            maxLifespan = []
            url = [prop["FEDERATION_URL"]]
            proxy_enabled = ["false"]
        }
        compPres.config["role-sync"] = ["true"]
        compPres.config["role-prefix"] = [prop["FEDERATION_ROLE_PREFIX"]]
        compPres.config["uppercase-role"] = ["true"]
        compPres.config["attr-sync"] = ["true"]

        comm.checkResponse(realmResource.components().add(compPres), "Component $fedName created", log)
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                fedName)
        component = components.get(0)
    } else {
        component = components.get(0)
        log.info("Component $fedName yet installed")
    }

    return component
}

// one task all step
def add(final String fedName, RealmResource realmResource, log, comm, fedH, prop) {
    comH.debug("add Rest federation $fedName")
    ComponentRepresentation component = createFederation(
            fedName,
            realmResource,
            log,
            comH,
            prop
    )

    fedH.triggerUpdate(component, realmResource, log, comH)

}

