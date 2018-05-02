package helpers

/**
 * RH-SSO Realm helpers
 */

import com.lyra.deployer.data.Report
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.resource.RealmResource
import org.keycloak.representations.idm.RealmRepresentation

def createRealm(final String realmName, final String sslReq, Keycloak k, rp, comm) {
    RealmRepresentation realm = new RealmRepresentation()
    realm.with {
        name = realmName
        bruteForceProtected = true
        failureFactor = 10
        offlineSessionIdleTimeout = 43200 // 12hours
        sslRequired = "all"
        eventsEnabled = true
        eventsExpiration = 43200 // 12hours
        adminEventsEnabled = true
        adminEventsDetailsEnabled = true

    }
    if (sslReq) {
        realm.sslRequired = sslReq //external
    }

    k.realms().create(realm)

    RealmResource realmResource = k.realm(realmName)
    if(realmResource){
        rp.add(new Report("Realm $realmName created", Report.Status.Success)).start().stop()
    }else{
        rp.add(new Report("Realm $realmName failed", Report.Status.Success)).start().stop()
    }
    return realmResource
}

