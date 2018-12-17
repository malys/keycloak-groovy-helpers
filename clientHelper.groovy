package helpers

import groovy.json.JsonSlurper
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.ClientRepresentation

/**
 * RH-SSO Client helpers
 */
def createClient(
        final String clientNam,
        final Boolean directAccessGrantsEnab,
        final Boolean publicClien,
        final Boolean bearerOnl,
        final Boolean fullScopeAllowe,
        final List<String> redirectUri,
        final List<String> webOrigin,
        RealmResource realmResource, log, comH) {

    //security
    if (System.getProperty("SECURITY") == "OFF") {
        log.info("SECURITY OFF !!!!!!")
    } else {
        boolean found = (redirectUri.find { uri -> uri == "*" } != null)
        found = found || (webOrigin.find { uri -> uri == "*" } != null)
        if (found) {
            comH.securityAlert("redirectUri or webOrigin have to not contain '*'")
        }
    }

    String clientName = comH.applyNomenclature(clientNam)

    ClientRepresentation client = new ClientRepresentation()
    client.with {
        clientId = clientName
        directAccessGrantsEnabled = false
        fullScopeAllowed = false
        redirectUris = redirectUri
        webOrigins = webOrigin
        publicClient = publicClien
        bearerOnly = bearerOnl
    }

    if (fullScopeAllowe) {
        client.fullScopeAllowed = fullScopeAllowe
    }

    if (directAccessGrantsEnab) {
        client.directAccessGrantsEnabled = directAccessGrantsEnab
    }

    List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientName)

    if (clients.size() > 0) {
        client = clients.get(0)
        log.info("Client $clientName yet installed")
    } else {
        comH.checkResponse(realmResource.clients().create(client), "Client $clientName created", log)
    }

    return client
}

def createClient(
        final String clientName,
        final Boolean directAccessGrantsEnab,
        final Boolean publicClien,
        final Boolean bearerOnl,
        final Boolean fullScopeAllowe,
        final String redirectUri,
        final String webOrigin,
        RealmResource realmResource, log, comH) {

    def jsonSlurper = new JsonSlurper()

    List<String> redirectUriP
    List<String> webOriginP

    if (redirectUri) redirectUriP = jsonSlurper.parseText(redirectUri.replaceAll("'", "\""))
    if (redirectUri) webOriginP = jsonSlurper.parseText(webOrigin.replaceAll("'", "\""))

    return createClient(
            clientName,
            directAccessGrantsEnab,
            publicClien,
            bearerOnl,
            fullScopeAllowe,
            redirectUriP,
            webOriginP,
            realmResource, log, comH)
}

