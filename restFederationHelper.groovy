package helpers

import org.keycloak.admin.client.resource.ComponentResource
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.RealmRepresentation

/**
 * RH-SSO Rest Federation helpers
 */
def createFederation(final Map conf, RealmResource realmResource, log, comH) {
    if ("ON" == System.getProperty("MOCK")) return
    RealmRepresentation realm = realmResource.toRepresentation()

    def federationName = comH.format(conf.name)

    //Check component
    List<ComponentRepresentation> components = realmResource.components().query(realm.getId(),
            "org.keycloak.storage.UserStorageProvider",
            federationName)

    if (components.size() == 0) {
        ComponentRepresentation compPres = new ComponentRepresentation()
        //Add new ldap component
        compPres.with {
            name = federationName
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
            role_client_sync = [conf.role_client_sync]
            attr_sync = [conf.attr_sync]
            reset_action = [conf.reset_action]
            evictionDay = []
            evictionHour = []
            evictionMinute = []
            maxLifespan = []
            proxy_enabled = [conf.proxy_enabled]
            not_create_users = [conf.not_create_users]
            by_pass = [conf.by_pass]
            password_sync = [conf.password_sync]
            password_hash_algorithm = [conf.password_hash_algorithm]
            password_hash_iteration = [conf.password_hash_iteration]

        }

        log.info(compPres.config.toMapString())
        comH.checkResponse(realmResource.components().add(compPres), "Component ${federationName} created", log)
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                federationName)
        component = components.get(0)
    } else {
        component = components.get(0)
        log.info("Component ${federationName} yet installed")
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
    if(conf.skipTriggerUpdate==null || !conf.skipTriggerUpdate){
        fedH.triggerUpdate(component, realmResource, log, comH)
    } else {
        log.info("Skip federation trigger update")
    }
}

def updateFederation(final Map conf, RealmResource realmResource, log, comm) {
    if ("ON" == System.getProperty("MOCK")) return
    RealmRepresentation realm = realmResource.toRepresentation()

    List<ComponentRepresentation> components = realmResource.components().query(realm.getId(),
            "org.keycloak.storage.UserStorageProvider",
            conf.name)
    ComponentRepresentation component

    if (components.size() == 1) {
        ComponentRepresentation compPres = components.get(0)
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
            role_client_sync = [conf.role_client_sync]
            attr_sync = [conf.attr_sync]
            reset_action = [conf.reset_action]
            evictionDay = []
            evictionHour = []
            evictionMinute = []
            maxLifespan = []
            proxy_enabled = [conf.proxy_enabled]
            not_create_users = [conf.not_create_users]
            by_pass = [conf.by_pass]
            password_sync = [conf.password_sync]
            password_hash_algorithm = [conf.password_hash_algorithm]
            password_hash_iteration[conf.password_hash_iteration]
        }

        ComponentResource compRes = realmResource.components().component(compPres.getId())
        compRes.update(compPres)

        log.info(compPres.config.toMapString())
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                conf.name)
        component = components.get(0)
    } else {
        component = components.get(0)
        log.info("Component ${conf.name} could be not selected")
    }

    return component
}