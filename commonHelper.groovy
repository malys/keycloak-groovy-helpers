package helpers

import com.lyra.deployer.data.Report

/**
 * RH-SSO Common helpers
 */
def checkResponse(javax.ws.rs.core.Response result, String message, log) {
    if (result.getStatus() != 201) {
        log.error("${message}: status=${result.getStatus()}")
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


