# dcm4che-bff — autenticazione Keycloak con struttura BFF

Modulo nuovo del repository `Nmicheli/dcm4che` (branch `feature/keycloak-bff`).
Implementa un **Backend for Frontend** per OpenID Connect / Keycloak: il browser
riceve solo un cookie di sessione opaco, i token restano sul server.

## Stato del lavoro

| Passo | Stato |
|---|---|
| Branch `feature/keycloak-bff` | fatto |
| Modulo `dcm4che-bff` registrato nel `pom.xml` padre | fatto |
| Codice del BFF (11 classi) | fatto, compila |
| Test JUnit 4 con Keycloak simulato | fatti: **89 test, 0 fallimenti** |
| Push + pull request | fatto |

```
Tests run: 89, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### Come eseguire i test

```
mvn -f dcm4che-bff/pom.xml test
```

I test non richiedono un Keycloak reale: `ServletStubs.FakeOpenIdProvider` serve
discovery document, token endpoint, revocation endpoint e un backend protetto su
`com.sun.net.httpserver`, e `ServletStubs.Request/Response` fanno da contenitore
servlet in memoria.

| Classe di test | Test | Copre |
|---|---|---|
| `BffConfigurationTest` | 10 | properties, default, allow-list dei redirect |
| `JsonAndTokenTest` | 14 | parser JSON, Base64URL, PKCE (vettore RFC 7636), claim JWT, ruoli Keycloak |
| `TokenValidatorTest` | 23 | iss/aud/exp/iat/nbf/nonce/azp, access token, discovery |
| `BffSessionStoreTest` | 11 | sessioni, scadenza per inattività, cookie HttpOnly/Secure/SameSite |
| `OpenIdClientTest` | 13 | discovery, authorization URL con PKCE, code exchange, refresh, revoke, logout |
| `BffServletTest` | 18 | login, callback (state errato, audience errata, nonce errato), userinfo, status, logout, proxy con Bearer |

### Scelte da rivedere in review

- Il **nonce** viene verificato solo se il provider lo restituisce nell'ID token
  (Keycloak lo fa); lo stato dell'authorization request resta comunque legato alla
  sessione server side, che è la difesa principale contro login CSRF e code injection.
- La **firma** dell'ID token non è verificata crittograficamente: il token arriva dal
  token endpoint via back channel autenticato. Se serve la verifica JWKS, è il passo
  successivo naturale.
- `maven-surefire-plugin` 2.22.2 è fissato nel pom del modulo, perché la versione di
  default rifiuta JUnit 4.11 (quella gestita dal padre); il padre non è stato toccato.
- Il modulo compila con **Java 8** (override locale del `source/target 1.6` del padre).
- La build in questa shell richiede il wrapper `runmvn.bat` (`JAVA_HOME` esplicito):
  `mvn` lanciato da questa shell POSIX non produce output.

## Struttura

```
dcm4che-bff/
├── pom.xml
└── src/main/
    ├── java/org/dcm4che3/bff/
    │   ├── BffConfiguration.java      configurazione (issuer, client, scope, cookie, backend)
    │   ├── OpenIdClient.java          discovery, authorization URL, token, refresh, revoke, end session
    │   ├── TokenSet.java              token + claims, Base64URL, PKCE S256, random
    │   ├── TokenValidator.java        validazione iss/aud/exp/iat/nbf/nonce/azp
    │   ├── BffSession.java            stato di sessione server side
    │   ├── BffSessionStore.java       store in memoria, scadenza e limite di sessioni
    │   ├── SessionCookie.java         cookie HttpOnly / Secure / SameSite=Lax
    │   ├── BffServlet.java            /login /callback /userinfo /status /logout
    │   ├── BffProxyServlet.java       proxy autenticato verso il backend (Bearer iniettato)
    │   ├── BffBootstrapServlet.java   bootstrap da web.xml + bff.properties
    │   └── Json.java                  parser/serializzatore JSON e HTTP minimale
    └── resources/bff.properties       configurazione di esempio per un realm Keycloak
```

## Flusso

```
browser ──GET /bff/login──▶ BFF ──302 authorization_endpoint (state, nonce, PKCE)──▶ Keycloak
browser ◀──302 /bff/callback?code&state── Keycloak
browser ──GET /bff/callback──▶ BFF ──POST /token (code + code_verifier)──▶ Keycloak
                                    └─ valida ID token (iss, aud, exp, nonce)
                                    └─ Set-Cookie: sessione HttpOnly
browser ──GET /bff/api/...──▶ BFF ──Authorization: Bearer <access token>──▶ backend dcm4che
```

Nessun token arriva a JavaScript: il browser ha solo `DCM4CHE_BFF_SESSION`.

## Configurazione minima (Keycloak)

In `bff.properties` (o come init-param `bff.*` in `web.xml`):

```
bff.issuer-uri=https://keycloak.example.com/realms/dcm4che
bff.client-id=dcm4che-bff
bff.client-secret=          # vuoto = client pubblico con PKCE
bff.redirect-uri=https://dcm4che.example.com/bff/callback
bff.scope=openid profile email
bff.backend-uri=https://dcm4che.example.com/api
```

Sul client Keycloak: *Standard Flow* attivo, redirect URI `/bff/callback`,
post logout redirect URI configurata, web origins del frontend.

## Note di progetto

- **Java 8** per questo modulo (il padre dichiara 1.6, incompatibile con i JDK
  moderni); è l'unico override, isolato nel pom del modulo.
- Nessuna dipendenza esterna oltre `javax.servlet-api` e `slf4j`: niente Spring,
  niente librerie JOSE, coerente con lo stile del repository.
- La firma dell'ID token non è verificata crittograficamente perché arriva dal
  token endpoint via back channel autenticato; i claim usati sono comunque
  validati. Se serve la verifica JWKS è il passo successivo naturale.
- Lo store delle sessioni è in memoria: per un cluster va sostituito
  (Infinispan/DB), l'interfaccia è già isolata in `BffSessionStore`.
