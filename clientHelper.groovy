package helpers

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.ClientRepresentation

/**
 * RH-SSO Client helpers
 */
def createClient(
        final String clientName,
        final Boolean directAccessGrantsEnab,
        final Boolean publicClien,
        final Boolean bearerOnl,
        final List<String> redirectUri,
        final List<String> webOrigin,
        RealmResource realmResource, rp, comH) {

    //security
    if (System.getProperty("SECURITY") == "OFF") {
        rp.add(new Report("SECURITY OFF", Report.Status.Warn)).start().stop()
    } else {
        boolean found = (redirectUri.find { uri -> (uri.indexOf("*") > -1) } != null)
        found = found || (webOrigin.find { uri -> (uri.indexOf("*") > -1) } != null)
        if (found) {
            comH.securityAlert("redirectUri or webOrigin have to not contain '*'")
        }
    }

    ClientRepresentation client = new ClientRepresentation()
    client.with {
        clientId = clientName
        directAccessGrantsEnabled = false
        redirectUris = redirectUri
        webOrigins = webOrigin
        publicClient = publicClien
        bearerOnly = bearerOnl
    }

    if (directAccessGrantsEnab) {
        client.directAccessGrantsEnabled = directAccessGrantsEnab
    }

    List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientName)

    if (clients.size() > 0) {
        client = clients.get(0)
        rp.add(new Report("Client $clientName yet installed", Report.Status.Success)).start().stop()
    } else {
        comH.checkResponse(realmResource.clients().create(client), "Client $clientName created", rp)
    }

    return client
}

