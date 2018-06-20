package helpers

import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap

/**
 * RH-SSO Rest Federation helpers
 */
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.RealmRepresentation

def createFederation(final Map conf, RealmResource realmResource, log, comm) {
    RealmRepresentation realm = realmResource.toRepresentation()

    //Check component
    List<ComponentRepresentation> components = realmResource.components().query(realm.getId(),
            "org.keycloak.storage.UserStorageProvider",
            conf.name)

    if (components.size() == 0) {
        ComponentRepresentation compPres = new ComponentRepresentation()
        //Add new ldap component
        compPres.with {
            name = conf.name
            providerId = "Rest User Federation"
            providerType = "org.keycloak.storage.UserStorageProvider"
            parentId = realm.id
            config = new MultivaluedHashMap<>()
        }
        compPres.config.with {
            uppercase = ["true"]
            fullSyncPeriod = [conf.fullSyncPeriod] //-1 for disabling
            prefix = [conf.prefix]
            cachePolicy = ["DEFAULT"]
            priority = ["0"]
            enabled = ["true"]
            url = [conf.url]
            uncheck_federation = [conf.uncheck_federation]
            changedSyncPeriod = [conf.changedSyncPeriod] // -1 for disabling
            role_sync = [conf.role_sync]
            attr_sync = [conf.attr_sync]
            reset_action = [conf.reset_action]
            evictionDay = []
            evictionHour = []
            evictionMinute = []
            maxLifespan = []
            proxy_enabled = [conf.proxy_enabled]
            not_create_users == [conf.not_create_users]
        }


        comm.checkResponse(realmResource.components().add(compPres), "Component ${conf.name} created", log)
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                conf.name)
        component = components.get(0)
    } else {
        component = components.get(0)
        log.info("Component ${conf.name} yet installed")
    }

    return component
}

// one task all step
def add(final Map conf, RealmResource realmResource, log, comH, fedH, prop) {
    comH.debug("add Rest federation ${conf.name}")
    ComponentRepresentation component = createFederation(
            conf,
            realmResource,
            log,
            comH
    )
    fedH.triggerUpdate(component, realmResource, log, comH)
}