package helpers

import org.keycloak.admin.client.resource.IdentityProviderResource
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.IdentityProviderRepresentation

import javax.ws.rs.NotFoundException

/**
 * Identity provider helpers
 */

def createIDP(Map conf, RealmResource realmResource, log, comH) {
    //Check component
    IdentityProviderResource idpRes
    IdentityProviderRepresentation idp
    boolean isCreated = false
    try {
        idpRes = realmResource.identityProviders().get(conf.name)
        idp = idpRes.toRepresentation()
    } catch (NotFoundException e) {
        idp = new IdentityProviderRepresentation()
        idp.with {
            alias = conf.name
            displayName = conf.name
            providerId = conf.providerId
            enabled = true
            trustEmail = true
            storeToken = false
            addReadTokenRoleOnCreate = false
            linkOnly = false
            config = new MultivaluedHashMap<>()
        }
        isCreated = true
    }

    idp.config.with {
        hideOnLoginPage = ""
        loginHint = ""
        validateSignature = ""
        clientId = conf.clientId
        tokenUrl = "/realms/${conf.realm}/protocol/openid-connect/token".toString()
        authorizationUrl = "/realms/${conf.realm}/protocol/openid-connect/auth".toString()
        disableUserInfo = ""
        logoutUrl = "/realms/${conf.realm}/protocol/openid-connect/Logout".toString()
        clientSecret = conf.clientSecret
        backchannelSupported = "true"
        useJwksUrl = "true"
    }


    if (isCreated) {
        comH.checkResponse(realmResource.identityProviders().create(idp), "IDP ${conf.name} created", log)

    } else {
        realmResource.identityProviders().get(conf.name).update(idp)
        log.info("IDP ${conf.name} updated")
    }
    return idp
}
