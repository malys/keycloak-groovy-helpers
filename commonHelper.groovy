package helpers
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


