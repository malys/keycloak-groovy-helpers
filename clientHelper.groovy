package helpers

import groovy.json.JsonSlurper
import org.keycloak.admin.client.resource.ClientTemplateResource
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.ClientTemplateRepresentation
import org.keycloak.representations.idm.ProtocolMapperRepresentation

import javax.ws.rs.NotFoundException

/**
 * RH-SSO Client helpers
 */
def createClient(final Map conf,
                 RealmResource realmResource, log, comH) {
    //security
    if (System.getProperty("SECURITY") == "OFF") {
        log.info("SECURITY OFF !!!!!!")
    } else {
        boolean found = (conf.redirectUri.find { uri -> uri == "*" } != null)
        found = found || (conf.webOrigin.find { uri -> uri == "*" } != null)
        if (found) {
            comH.securityAlert("redirectUri or webOrigin have to not contain '*'")
        }
    }

    String clientName = comH.applyNomenclature(conf.name)

    ClientRepresentation client = new ClientRepresentation()
    client.with {
        clientId = conf.name
        directAccessGrantsEnabled = false
        loginWithEmailAllowed = false
        fullScopeAllowed = false
        redirectUris = conf.redirectUri
        webOrigins = conf.webOrigin
        publicClient = conf.publicClient
        bearerOnly = conf.bearerOnly
        consentRequired = conf.consentRequired
        standardFlowEnabled = conf.standardFlowEnabled
        implicitFlowEnabled = conf.implicitFlowEnabled
        serviceAccountsEnabled = conf.serviceAccountsEnabled
    }

    if (conf.fullScopeAllowed) {
        client.fullScopeAllowed = conf.fullScopeAllowed
    }

    if (conf.directAccessGrantsEnable) {
        client.directAccessGrantsEnabled = conf.directAccessGrantsEnable
    }

    if (conf.clientTemplate) {
        client.clientTemplate = conf.clientTemplate
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
        final Boolean directAccessGrantsEnable,
        final Boolean publicClient,
        final Boolean bearerOnly,
        final Boolean fullScopeAllowed,
        final List<String> redirectUri,
        final List<String> webOrigin,
        RealmResource realmResource, log, comH) {

    return createClient([
            "name"                    : clientName,
            "directAccessGrantsEnable": directAccessGrantsEnable,
            "publicClient"            : publicClient,
            "bearerOnly"              : bearerOnly,
            "fullScopeAllowed"        : fullScopeAllowed,
            "redirectUri"             : redirectUri,
            "webOrigin"               : webOrigin
    ],
            realmResource, log, comH)
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

def createClientTemplate(final Map conf,
                         final List<ProtocolMapperRepresentation> protocolMappers,
                         RealmResource realmResource, log, comH) {

    String clientTemplateName = comH.applyNomenclature(conf.name)

    ClientTemplateRepresentation client = new ClientTemplateRepresentation()
    client.with {
        name = clientTemplateName
        description = conf.description
        protocol = conf.protocol
        fullScopeAllowed = conf.fullScopeAllowed
        bearerOnly = conf.bearerOnly
        consentRequired = conf.consentRequired
        standardFlowEnabled = conf.standardFlowEnabled
        implicitFlowEnabled = conf.implicitFlowEnabled
        directAccessGrantsEnabled = conf.directAccessGrantsEnabled
        serviceAccountsEnabled = conf.serviceAccountsEnabled
        publicClient = conf.publicClient
    }

    if (protocolMappers) {
        client.setProtocolMappers(protocolMappers)
    }

    if (conf.attributes) {
        client.attributes = conf.attributes
    }

    try {
        List<ClientTemplateRepresentation> list = realmResource.clientTemplates().findAll()
        ClientTemplateRepresentation result = list.find { l -> l.name.equals(clientTemplateName) }
        if (result != null) {
            client = result
            log.info("Client $clientTemplateName yet installed")
        } else {
            comH.checkResponse(realmResource.clientTemplates().create(client), "Client template $clientTemplateName created", log)
        }
    } catch (NotFoundException e) {
        comH.checkResponse(realmResource.clientTemplates().create(client), "Client template $clientTemplateName created", log)
    }

    return client
}

def createAPIClientTemplate(redirect, webOrigin, RealmResource realmResource, log, comH) {
    def SERVICE_NAME = "api-service"

    List<ProtocolMapperRepresentation> protocolMappers = new ArrayList<>()
    ProtocolMapperRepresentation userOver = new ProtocolMapperRepresentation()
    userOver.with {
        name = "userOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-usersessionmodel-note-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["user.session.note"] = "clientId"
        config["id.token.claim"] = "true"
        config["access.token.claim"] = "true"
        config["claim.name"] = "preferred_username"
        config["jsonType.label"] = "String"

    }

    ProtocolMapperRepresentation azpOver = new ProtocolMapperRepresentation()
    azpOver.with {
        name = "azpOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-hardcoded-claim-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["claim.value"] = SERVICE_NAME
        config["userinfo.token.claim"] = "true"
        config["id.token.claim"] = "true"
        config["access.token.claim"] = "true"
        config["claim.name"] = "azp"
        config["jsonType.label"] = "String"

    }


    ProtocolMapperRepresentation audOver = new ProtocolMapperRepresentation()
    audOver.with {
        name = "audOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-hardcoded-claim-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["claim.value"] = SERVICE_NAME
        config["userinfo.token.claim"] = "true"
        config["id.token.claim"] = "true"
        config["access.token.claim"] = "true"
        config["claim.name"] = "aud"
        config["jsonType.label"] = "String"
    }

    def CLIENT_TEMPLATE = "api-key"
    ClientTemplateRepresentation clientTemplate = createClientTemplate([
            name                     : CLIENT_TEMPLATE,
            description              : "Template to allowed API use case.",
            protocol                 : "openid-connect",
            fullScopeAllowed         : false,
            bearerOnly               : false,
            consentRequired          : false,
            standardFlowEnabled      : false,
            implicitFlowEnabled      : false,
            directAccessGrantsEnabled: false,
            serviceAccountsEnabled   : true,
            publicClient             : false,

    ],
            Arrays.asList(userOver, azpOver, audOver),
            realmResource, log, comH
    )

    createClient([
            name                     : SERVICE_NAME,
            fullScopeAllowed         : false,
            bearerOnly               : false,
            consentRequired          : false,
            standardFlowEnabled      : false,
            implicitFlowEnabled      : false,
            directAccessGrantsEnabled: false,
            serviceAccountsEnabled   : true,
            publicClient             : false
    ],
            realmResource, log, comH)


    createClient([
            name                     : "monitoring",
            clientTemplate           : CLIENT_TEMPLATE,
            fullScopeAllowed         : false,
            bearerOnly               : false,
            consentRequired          : false,
            standardFlowEnabled      : false,
            implicitFlowEnabled      : false,
            directAccessGrantsEnabled: false,
            serviceAccountsEnabled   : true,
            publicClient             : false
    ],
            realmResource, log, comH)

    return clientTemplate
}