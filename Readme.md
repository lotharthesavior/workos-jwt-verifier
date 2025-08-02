# WorkOS JWT Verifier

This is a microservice that verifies access tokens for a given user in [WorkOS](https://workos.com). It checks if the token is valid and not expired. It relies in the WorkOS SSO .

## Usage

Add the following to your `.env` or to the environment variables of your deployment (replacing the `<client_id>` with your actual WorkOS client ID):

```
JWKS_CLIENT_ID=<client_id>
```

> You have to add this url to https://fga.workos.com/configuration. FGA is the WorkOS service that provides the necessary configuration for access token verification.

Now, to use this service, you run this service with the following command (or the binary if you have built it):

```bash
cargo run
# or cargo build --release and then execute the binary
```

You need to send a GET request to the `/verify` endpoint with the access token in the header like in the following example:

```
curl \
  -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:8080/verify
```

You will receive status 200 if ok, or 401 if the token is invalid or expired. If 200, the response payload will be something like this:

```json
{
  "sub": <user_id>,
  "exp": <timestamp>
}
```

This request is crazy fast and should take less than 1ms to respond. It saves the signing key for the given client_id in a local file (when it is not there already) for further requests.
