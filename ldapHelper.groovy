package helpers


import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.RealmRepresentation

/**
 * LDAP federation helpers
 */

def createFederation(final String fedName, String customFilter, RealmResource realmResource, log, comH, prop) {
    if ("ON" == System.getProperty("MOCK")) return
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
            providerId = "ldap"
            providerType = "org.keycloak.storage.UserStorageProvider"
            parentId = realm.id
            vendor = ["rhds"]
            config = new MultivaluedHashMap<>()
        }
        compPres.config.with {
            priority = ["0"]
            editMode = ["READ_ONLY"]
            syncRegistrations = ["false"]
            vendor = ["other"]
            usernameLDAPAttribute = ["uid"]
            rdnLDAPAttribute = ["uid"]
            uuidLDAPAttribute = [prop["LDAP_USERNAME_ATTRIBUTE"]]
            userObjectClasses = ["inetOrgPerson, organizationalPerson"]
            connectionUrl = ["ldaps://" + prop["LDAP_HOST"]]
            usersDn = ["cn=users,cn=accounts," + prop["LDAP_CONTEXT"]]
            authType = ["simple"]
            bindDn = [prop["LDAP_LOGIN"]]
            bindCredential = [prop["LDAP_PW"]]
            searchScope = ["1"]
            useTruststoreSpi = ["ldapsOnly"]
            connectionPooling = ["true"]
            pagination = ["true"]
            allowKerberosAuthentication = ["false"]
            useKerberosForPasswordAuthentication = ["false"]
            batchSizeForSync = ["1000"]
            fullSyncPeriod = ["-1"]
            changedSyncPeriod = ["-1"]
            cachePolicy = ["DEFAULT"]
            evictionDay = []
            evictionHour = []
            evictionMinute = []
            maxLifespan = []
            serverPrincipal = ["HTTP/localhost@KEYCLOAK.ORG"]
            keyTab = ["http.keytab"]
            kerberosRealm = ["KEYCLOAK.ORG"]
            debug = ["true"]
        }
        if (customFilter) {
            compPres.config.customUserSearchFilter = [customFilter]
        }

        comH.checkResponse(realmResource.components().add(compPres), "Component $fedName created", log)
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                fedName)
        component = components.get(0)
    } else {
        component = components.get(0)
        log.info("Component $fedName yet installed")
    }

    // Configure LDAP Components
    // Update "first name" LDAP attribute
    components = realmResource.components().query(component.id,
            "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            'first name')
    ComponentRepresentation fistNameComponent = components.first()
    if (fistNameComponent != null) {
        fistNameComponent.config["ldap.attribute"] = ["givenName"]
        realmResource.components().component(fistNameComponent.getId()).update(fistNameComponent)
        log.info("Component $fedName updated")
    } else {
        log.error("Component $fedName updated")
    }

    return component
}

// one task all step
def add(String fedName,
        String customFilter,
        String groupsLdap,
        groupRoles,
        RealmResource realmResource,
        log, userH, realmH, clientH, comH, fedH, prop) {
    if ("ON" == System.getProperty("MOCK")) return
    def roleCompName = " ${fedName}-roles"
    comH.debug("add LDAP $fedName $customFilter $roleCompName")
    ComponentRepresentation component = createFederation(
            fedName,
            customFilter,
            realmResource,
            log,
            comH,
            prop
    )

    fedH.applyRoles(roleCompName, groupsLdap, groupRoles, component, realmResource, log, userH, realmH, clientH, comH)

    fedH.triggerUpdate(component, realmResource, log, comH)
}