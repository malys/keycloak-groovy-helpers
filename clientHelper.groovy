package helpers

/**
 * RH-SSO Client helpers
 */

import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.RealmRepresentation

def createClient(
        final String clientName,
        final Boolean directAccessGrantsEnab,
        final List<String> redirectUri,
        final List<String> webOrigin,
        RealmResource realmResource, rp, comH) {


    //security
    boolean found = (redirectUri.find { uri > (uri.indexOf("*") > -1) } != null)
    found = found || (webOrigin.find { uri > (uri.indexOf("*") > -1) } != null)
    if(found){
        comH.securityAlert("redirectUri or webOrigin have to not contain '*'")
    }


    RealmRepresentation realm = realmResource.toRepresentation()
    ClientRepresentation client = new ClientRepresentation()
    client.with {
        clientId = clientName
        directAccessGrantsEnabled = false
        redirectUris = redirectUri
        webOrigins = webOrigin
    }

    if (directAccessGrantsEnab) {
        client.directAccessGrantsEnabled = directAccessGrantsEnab
    }

    comH.checkResponse(realmResource.clients().create(client), "Client $clientName created", rp)
    return client
}

