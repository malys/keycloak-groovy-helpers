package helpers

import com.lyra.deployer.data.Report

/**
 * RH-SSO Common helpers
 */
def checkResponse(javax.ws.rs.core.Response result, String message, rp) {
    if (result.getStatus() != 201) {
        rp.add(new Report("${message}: status=${result.getStatus()}", Report.Status.Fail)).start().stop()
        return false
    } else {
        rp.add(new Report("${message}", Report.Status.Success)).start().stop()
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


