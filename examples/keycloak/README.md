# Rust Keycloak OpenID Connect example

You may run this example using your own already running Keycloak instance or the provided example container.

## Start the example Keycloak container

If you do not have a Keycloak instance for testing, you can use the provided example Keycloak container from `compose.yaml` using Docker/Podman.

```shell
docker compose -f examples/keycloak/compose.yaml up --detach
```

You can then navigate to your Keycloak dev instance at [localhost:8082](http://localhost:8082)   
Login with the user `admin` using the password `admin123456`

## Add a client

The following procedure guides your through creating an example client using the Keycloak web UI.

1. Go to **Manage > Clients**
2. Click the blue button **Create Client**
3. **General settings**: Make sure the client is of type **OpenID Connect**, fill in the **Client ID** and click on **Next**. The Client ID you specify here goes into the environment variable `KEYCLOAK_CLIENT_ID` later.
4. **Capability config**: Select **Client authentication** and **Standard flow** (Authorization Code Flow) and click on **Next**.
5. **Login settings**: Add some dummy login settings and click on **Save**:
   - **Root URL**: http://localhost:8080
   - **Home URL**: http://localhost:8080
   - **Valid redirect URIs**: http://localhost:8080/*
6. In your newly created client, go to the **Credentials** tab and *copy* the **Client Secret**. The secret will go into the environment variable `KEYCLOAK_CLIENT_SECRET`.
7. You can now run this example from the root of this repository:
```shell
KEYCLOAK_CLIENT_ID=xxx KEYCLOAK_CLIENT_SECRET=yyy KEYCLOAK_ISSUER_URL='http://localhost:8082/realms/master' cargo run --example keycloak
```

Note: You may have to change the name of the realm if your ones has another name than `master`.

