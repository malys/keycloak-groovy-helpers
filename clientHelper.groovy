package helpers


import groovy.transform.Field
import org.keycloak.admin.client.resource.ClientResource
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.admin.client.resource.RolesResource
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.representations.idm.*

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

    if (conf.directAccessGrantsEnabled) {
        client.directAccessGrantsEnabled = conf.directAccessGrantsEnabled
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
        final Boolean directAccessGrantsEnabled,
        final Boolean publicClient,
        final Boolean bearerOnly,
        final Boolean fullScopeAllowed,
        final List<String> redirectUri,
        final List<String> webOrigin,
        RealmResource realmResource, log, comH) {

    return createClient([
            "name"                     : comH.format(clientName),
            "directAccessGrantsEnabled": directAccessGrantsEnabled,
            "publicClient"             : publicClient,
            "bearerOnly"               : bearerOnly,
            "fullScopeAllowed"         : fullScopeAllowed,
            "redirectUri"              : redirectUri,
            "webOrigin"                : webOrigin
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
        name = comH.format(clientTemplateName)
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
// Create new roles in account services
def addRoleToAccountService(RealmResource realmResource, serviceName, roles, prefix, log, realmH, clientH, userH, busH, comH) {
    def rolesList = roles.collect { it -> comH.formatBusinessRole(prefix, it) }

    rolesList.each { it ->
        clientH.addRole(it, null, null, realmResource, serviceName, false, log, realmH, userH, comH)
    }
}

def addRoleToClientAccountService(final Map config, realmResource, log, userH, comH) {
    List<ClientRepresentation> clients = realmResource.clients().findByClientId(config.clientName)
    ClientResource clientResource = realmResource.clients().get(clients[0].id)
    if (config.roles != null) {
        config.roles.each { it ->
            def role = ((String) (config.prefix + "_" + it)).toUpperCase()
            // Scope
            userH.addScopeRole(config.serviceName + "." + role, clientResource.getServiceAccountUser(), config.clientName, realmResource, log, comH)
            //Assign
            userH.addClientRole(role, clientResource.getServiceAccountUser(), config.serviceName, realmResource, log, comH)
        }
    }
}

/**
 * Service Account with advanced roles
 * @param realmResource
 * @param log
 * @param realmH
 * @param userH
 * @param comH
 * @return client
 */
def addMaintainerClient(RealmResource realmResource, log, realmH, userH, comH) {
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

    return maintainer
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
    //List of mappers for template
    List<ProtocolMapperRepresentation> mapperList = [];

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
        config["access.token.claim"] = "true"
        config["claim.name"] = "preferred_username"
        config["jsonType.label"] = "String"
        config["access.token.claim"] = "true"
    }
    mapperList.add(userOver)

    ProtocolMapperRepresentation fullNameOver = new ProtocolMapperRepresentation()
    fullNameOver.with {
        name = "fullNameOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-full-name-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["userinfo.token.claim"] = "true"
        config["id.token.claim"] = "true"
        config["access.token.claim"] = "true"
    }
    mapperList.add(fullNameOver)

    ProtocolMapperRepresentation emailOver = new ProtocolMapperRepresentation()
    emailOver.with {
        name = "emailOverride"
        protocol = "openid-connect"
        protocolMapper = "oidc-usermodel-property-mapper"
        consentRequired = false
        config = new MultivaluedHashMap<>()
        config["userinfo.token.claim"] = "true"
        config["id.token.claim"] = "true"
        config["access.token.claim"] = "true"
        config["user.attribute"] = "email"
        config["claim.name"] = "email"
        config["jsonType.label"] = "String"
    }
    mapperList.add(emailOver)

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
    mapperList.add(azpOver)

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
    mapperList.add(audOver)

    if (conf.roles != null) {
        conf.roles.each { role ->
            // Force role in template
            ProtocolMapperRepresentation specificRoleOver = new ProtocolMapperRepresentation()
            specificRoleOver.with {
                name = role.toLowerCase() + "RoleAdd"
                protocol = "openid-connect"
                protocolMapper = "oidc-hardcoded-role-mapper"
                consentRequired = false
                config = new MultivaluedHashMap<>()
                config["role"] = SERVICE_NAME + "." + role
            }
            mapperList.add(specificRoleOver);
        }
    }
    ClientTemplateRepresentation clientTemplate = createClientTemplate(
            [
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
            mapperList,
            realmResource, log, comH
    )

    //Allow template for remote use
    List<ComponentRepresentation> components = realmResource.components().query(realmResource.toRepresentation().id,
            "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
            "Allowed Client Templates")

    if (components.size() > 0) {
        component = components.find { c -> c.subType == "authenticated" }
        if (component != null) {
            if (component.config["allowed-client-templates"] == null) component.config["allowed-client-templates"] = []
            component.config["allowed-client-templates"].push(conf.clientTemplate)
            realmResource.components().component(component.id).update(component);
        }
    }

    if (!conf.skipGenericClient) {
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
    }

    if (conf.monitoring) {
        createClient([
                name                     : "monitoring",
                description              : "Service account for monitoring",
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
        addMaintainerClient(realmResource, log, realmH, userH, comH)
    }
    return clientTemplate
}

// Get client ressource from name
def getClientResources(clientName, realmResource) {
    List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientName)
    return realmResource.clients().get(clients[0].id)
}

// Get client role from name
def getRole(clientName, roleName, realmResource, log) {
    RoleRepresentation role
    ClientResource clientResource = getClientResources(clientName, realmResource)
    if (clientResource != null) {
        RolesResource roleRes = clientResource.roles()
        if (roleRes && roleRes.list()) {
            role = roleRes.list().find {
                RoleRepresentation r ->
                    r.name == roleName
            }
        }
    } else {
        log.error("Client  $clientName missing")
    }

    return role
}

def addRole(final String roleName,
            final String descriptio,
            Map<String, List<String>> composits,
            RealmResource realmResource,
            String clientName,
            final boolean assigned,
            log, realmH, userH, comH) {

    RoleRepresentation role = getRole(clientName, roleName, realmResource, log)
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
        ClientResource clientResource = getClientResources(clientName, realmResource)
        clientResource.roles().create(role)
        role = clientResource.roles().get(roleName).toRepresentation()

        if (composits) {
            realmResource.rolesById().addComposites(role.getId(), realmH.getRolesRepresentation(composits, realmResource))
            log.info("Composite role $roleName")
        }

        if (assigned) {
            //Assign role
            userH.addClientRole(roleName, clientResource.getServiceAccountUser(), clientName, realmResource, log, comH)
            log.info("Assign $roleName to $clientName")
        }
    }
    return role
}

def addBanMaintainer(RealmResource realmResource, log, realmH, userH, comH) {
    //Create maintainer client if not exist
    ClientRepresentation maintainer = addMaintainerClient(realmResource, log, realmH, userH, comH)

    //Create client role and add it
    addRole("ban-readonly", "Ban status", ["realm-management": [
            "query-users",
            "view-users"
    ]], realmResource, maintainer.clientId, true, log, realmH, userH, comH)
}

@Field def CLIENT_TEMPLATE = "api-key"
@Field String SERVICE_NAME = "api-service"

