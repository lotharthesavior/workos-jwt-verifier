# Access Token Verification

This is a microservice that verifies access tokens for a given user in [WorkOS](https://workos.com). It checks if the token is valid and not expired. It relies in the WorkOS SSO .

## Usage

Add the following to your `.env` or to the environment variables of your deployment (replacing the `<client_id>` with your actual WorkOS client ID):

```
GET https://api.workos.com/sso/jwks/<client_id>
```

> You have to add this url to https://fga.workos.com/configuration. FGA is the WorkOS service that provides the necessary configuration for access token verification.

Now, to use this service, you run this service with the following command (or the binary if you have built it):

```bash
cargo run
```

You need to send a GET request to the `/verify` endpoint with the access token in the header like in the following header example:

```
Authorization: Bearer <access_token>
```

You will receive status 200 if ok, or 401 if the token is invalid or expired. If 200, the response payload will be something like this:

```json
{
  "sub": <user_id>,
  "exp": <timestamp>
}
```
