package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.RealmRepresentation

/**
 * LDAP federation helpers
 */

def createFederation(final String fedName, String customFilter, RealmResource realmResource, rp, comH, prop) {
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
            bindDn = [prop["LDAP_LOGIN"] + prop["LDAP_CONTEXT"]]
            bindCredential = [prop["LDAP_PW"]]
            searchScope = ["1"]
            useTruststoreSpi = ["ldapsOnly"]
            connectionPooling = ["true"]
            pagination = ["true"]
            allowKerberosAuthentication = ["false"]
            useKerberosForPasswordAuthentication = ["false"]
            batchSizeForSync = ["1000"]
            fullSyncPeriod = ["604800"]
            changedSyncPeriod = ["86400"]
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

        comH.checkResponse(realmResource.components().add(compPres), "Component $fedName created", rp)
        components = realmResource.components().query(realm.getId(),
                "org.keycloak.storage.UserStorageProvider",
                fedName)
        component = components.get(0)
    } else {
        component = components.get(0)
        rp.add(new Report("Component $fedName yet installed", Report.Status.Success)).start().stop()
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
        rp.add(new Report("Component $fedName updated", Report.Status.Success)).start().stop()
    } else {
        rp.add(new Report("Component $fedName updated", Report.Status.Fail)).start().stop()
    }

    return component
}

// one task all step
def add(String fedName, String customFilter, String roleCompName, roles, RealmResource realmResource, rp, comH, fedH, prop) {
    comH.debug("add LDAP $fedName $customFilter $roleCompName")
    ComponentRepresentation component = createFederation(
            fedName,
            customFilter,
            realmResource,
            rp,
            comH,
            prop
    )

    fedH.applyRoles(roleCompName, roles, component, realmResource, rp, comH)

    fedH.triggerUpdate(component, realmResource, rp, comH)

}