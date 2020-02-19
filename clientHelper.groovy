package helpers

import groovy.json.JsonSlurper
import groovy.transform.Field
import org.keycloak.admin.client.resource.ClientResource
import org.keycloak.admin.client.resource.ClientTemplateResource
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.admin.client.resource.RolesResource
import org.keycloak.admin.client.resource.UserResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.ClientTemplateRepresentation
import org.keycloak.representations.idm.ComponentRepresentation
import org.keycloak.representations.idm.ProtocolMapperRepresentation
import org.keycloak.representations.idm.RoleRepresentation
import org.keycloak.representations.idm.UserRepresentation

import javax.ws.rs.NotFoundException

/**
 * RH-SSO Client helpers
 */
def createClient(final Map conf,
                 RealmResource realmResource, log, comH) {
    //security
    if (System.getProperty("SECURITY") == "OFF") {
        log.info("SECURITY OFF !!!!!!")
        if (conf.redirectUri == null) conf.redirectUri = ['*']
        if (conf.webOrigin == null) conf.webOrigin = ['*']
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
        description = conf.description
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

    List<String> redirectUriP
    List<String> webOriginP

    if (redirectUri) redirectUriP = comH.convertJSONToList(redirectUri)
    if (redirectUri) webOriginP = comH.convertJSONToList(webOrigin)

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

import groovy.transform.Field
import org.keycloak.admin.client.resource.ClientResource
import org.keycloak.representations.idm.ClientRepresentation

// Create
def addRoleToAccountService(RealmResource realmResource,serviceName,roles,prefix, log, realmH, clientH, userH, busH, comH) {
    def rolesList = roles.collect { it-> prefix + "_" + it }

    rolesList.each { it->
        clientH.addRole(it, serviceName + " " + it, null, realmResource, serviceName, false, log, realmH, userH, comH)
    }
}

def addRoleToClientAccountService(final Map config, realmResource, log, userH, comH) {
    List<ClientRepresentation> clients = realmResource.clients().findByClientId(config.clientName)
    ClientResource clientResource = realmResource.clients().get(clients[0].id)
    if (config.roles != null) {
        config.roles.each { it->
            def role = ((String) (config.prefix  + "_" + it)).toUpperCase()
            // Scope
            println(role)
            userH.addScopeRole(config.serviceName + "." + role, clientResource.getServiceAccountUser(), config.clientName, realmResource, log, comH)
            //Assign
            userH.addClientRole(role, clientResource.getServiceAccountUser(), config.serviceName , realmResource, log, comH)
        }
    }
}


def createAPIClientTemplate(RealmResource realmResource, log, realmH, userH, comH) {
    createAPIClientTemplate([
            serviceName   : SERVICE_NAME,
            clientTemplate: CLIENT_TEMPLATE,
            maintainer    : true,
            monitoring    : true
    ], realmResource, log, realmH, userH, comH)
}

def createAPIClientTemplate(final Map conf, RealmResource realmResource, log, realmH, userH, comH) {
    def SERVICE_NAME = conf.serviceName

    ProtocolMapperRepresentation userOver = new ProtocolMapperRepresentation()
    userOver.with {
        name = "userOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-usersessionmodel-note-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["user.session.note"] = "clientId"
        config["userinfo.token.claim"] = "false"
        config["id.token.claim"] = "false"
        config["claim.name"] = "preferred_username"
        config["jsonType.label"] = "String"
        config["access.token.claim"] = "true"

    }

    ProtocolMapperRepresentation azpOver = new ProtocolMapperRepresentation()
    azpOver.with {
        name = "azpOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-hardcoded-claim-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["claim.value"] = SERVICE_NAME
        config["userinfo.token.claim"] = "false"
        config["id.token.claim"] = "false"
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
        config["userinfo.token.claim"] = "false"
        config["id.token.claim"] = "false"
        config["access.token.claim"] = "true"
        config["claim.name"] = "aud"
        config["jsonType.label"] = "String"
    }


    ClientTemplateRepresentation clientTemplate = createClientTemplate([
            name                     : conf.clientTemplate,
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

    //Allow template for remote use
    List<ComponentRepresentation> components = realmResource.components().query(realmResource.toRepresentation().id,
            "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
            "Allowed Client Templates")

    if (components.size() > 0) {
        component = components.find { c -> c.subType == "authenticated" }
        if (component != null) {
            if(component.config["allowed-client-templates"] ==null) component.config["allowed-client-templates"]=[]
            component.config["allowed-client-templates"].push(conf.clientTemplate)
            realmResource.components().component(component.id).update(component);
        }
    }

    createClient([
            name                     : SERVICE_NAME,
            description              : "Generic client for " + SERVICE_NAME,
            fullScopeAllowed         : false,
            bearerOnly               : true,
            consentRequired          : false,
            standardFlowEnabled      : false,
            implicitFlowEnabled      : false,
            directAccessGrantsEnabled: false,
            serviceAccountsEnabled   : false,
            publicClient             : false
    ],
            realmResource, log, comH)

    if (conf.monitoring) {
        createClient([
                name                     : "monitoring",
                description              : "API key for monitoring",
                clientTemplate           : conf.clientTemplate,
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
    }

    if (conf.maintainer) {
        def MAINTAINER = "maintainer"
        ClientRepresentation maintainer = createClient([
                name                     : MAINTAINER,
                description              : "Client to maintain (CRUD) API keys",
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

        //Create client role and add it
        def roleName = "api-admin"
        addRole(roleName, "Manage API key", ["realm-management": [
                "create-client",
                "view-clients",
                "query-clients",
                "manage-clients"
        ]], realmResource, MAINTAINER, true, log, realmH, userH, comH)
    }
    return clientTemplate
}


def addRole(final String roleName,
            final String descriptio,
            Map<String, List<String>> composits,
            RealmResource realmResource,
            String clientName,
            final boolean assigned,
            log, realmH, userH, comH) {

    List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientName)
    ClientResource clientResource = realmResource.clients().get(clients[0].id)
    RolesResource roleRes = clientResource.roles()
    RoleRepresentation role

    if (roleRes && roleRes.list()) {
        role = roleRes.list().find {
            RoleRepresentation r ->
                r.name == roleName
        }
    }
    if (role == null) {
        role = new RoleRepresentation()
        role.with {
            id = roleName
            name = roleName
            description = descriptio
        }

        if (composits) {
            role.composite = true
        }
        clientResource.roles().create(role)
        role = clientResource.roles().get(roleName).toRepresentation()

        if (composits) {
            realmResource.rolesById().addComposites(role.getId(), realmH.getRolesRepresentation(composits, realmResource))
        }

        if (assigned) {
            //Assign role
            userH.addClientRole(roleName, clientResource.getServiceAccountUser(), clientName, realmResource, log, comH)
        }
    }
    return role
}

@Field def CLIENT_TEMPLATE = "api-key"
@Field String SERVICE_NAME = "api-service"

