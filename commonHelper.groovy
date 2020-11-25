package helpers

import groovy.json.JsonSlurper

/**
 * RH-SSO Common helpers
 */
def checkResponse(javax.ws.rs.core.Response result, String message, log) {
    if (result.getStatus() != 201) {
        log.error("${message}: status=${result.getStatus()} ${result.entity} ")
        return false
    } else {
        log.info("${message}")
        return true
    }
}

def helloWorld() {
    println "Hello world"

}

def debug(String message) {
    if (System.properties['DEBUG']) {
        println "--> $message"
    }
}


def securityAlert(String message) {
    System.err.println("SECURITY BREACH !!: ${message}")
    System.exit(2)
}

def applyNomenclature(String name) {
    String pattern = /[!$%^&*()_+|~=`{}\[\]:";'<>?,.\/]/
    if (name ==~ pattern) securityAlert("Not allowed character in ${name}")
    return name.toLowerCase()
}

def convertJSONToList(String value) {
    def jsonSlurper = new JsonSlurper()
    return jsonSlurper.parseText(value.replaceAll("'", "\""))
}

/* Apply nomenclature
| component             | style       | style description                            | example                     |
| --------------------- | ----------- | -------------------------------------------- | --------------------------- |
| Web origin            | url         | domain name ONLY                             | see URL example             |
| Valid redirect URL    | url         | domains without ( * ) ended bye "/*"         | see URL example             |
| theme                 | kebab       | lower case with dash -                       | collect                     |
| realm/client/template | kebab       | lower case with dash -                       | collect                     |
| platform role         | kebab       | lower case with dash -                       | realm-management, api-admin |
| business role         | upper snake | uppercase (PREFIX_ROLE with underscore (_) ) | LC_ADMIN                    |
 */

def formatBusinessRole(String prefix, name) {
    return formatBusinessRole(prefix + "_" + name)
}

def formatBusinessRole(name) {
    return toSnakeCase(name).toUpperCase()
}

def format(prefix, name) {
    return toKebabCase(prefix + "-" + name)
}

def format(name) {
    return toKebabCase(name)
}

def String toKebabCase(String text) {
    return text
            .replaceAll(/([a-z0-9])([A-Z])/, '$1-$2')
            .replaceAll(/([A-Z])([A-Z])(?=[a-z])/, '$1-$2')
            .replaceAll(/\_/, '-')
            .toLowerCase();
}

def String toSnakeCase(String text) {
    return text
            .replaceAll(/([a-z0-9])([A-Z])/, '$1_$2')
            .replaceAll(/([A-Z])([A-Z])(?=[a-z])/, '$1_$2')
            .replaceAll(/\-/, '_')
            .toLowerCase()
}




