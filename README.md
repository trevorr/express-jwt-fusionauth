# express-jwt-fusionauth

[![npm](https://img.shields.io/npm/v/express-jwt-fusionauth)](https://www.npmjs.com/package/express-jwt-fusionauth)
[![CircleCI](https://img.shields.io/circleci/build/github/trevorr/express-jwt-fusionauth)](https://circleci.com/gh/trevorr/express-jwt-fusionauth)

[Express](https://expressjs.com/) middleware for JSON Web Token ([JWT](https://jwt.io/))-based
authentication against [FusionAuth](https://fusionauth.io/). It provides three main functions:

* Find, parse, and verify a JWT, and attach its claims to the Express request, optionally
  requiring that it be present.\
  As a convenience for browser-based API testing, the client can be optionally redirected
  to a login page when the required JWT is missing or invalid.
* Check that the JWT has at least one of a set of application-defined roles.
* Implement the [redirection endpoint](https://tools.ietf.org/html/rfc6749#section-3.1.2)
  that exchanges an OAuth authorization code for a JWT.

While most of the mechanics of JWT ([RFC 7519](https://tools.ietf.org/html/rfc7519)) and
OAuth 2.0 ([RFC 6749](https://tools.ietf.org/html/rfc6749)) are standard across identity
providers, this implementation focuses on specifics of FusionAuth and its best practices
to make integration as safe and simple as possible. For example, the TypeScript definition
of the JWT claims interface contains only the subset of registered claims used by FusionAuth,
as well as the private claims it adds.

## Installation

```sh
npm install express-jwt-fusionauth
```

## Sample Usage

```ts
import cookieParser from 'cookie-parser';
import express from 'express';
import { ExpressJwtFusionAuth } from 'express-jwt-fusionauth';

// environment-specific settings and secrets
const { FUSIONAUTH_URL = 'http://fusionauth:9011' } = process.env;
const { JWT_ISSUER = 'acme.com' } = process.env;
const { OAUTH_CLIENT_ID = '31d7b8e8-f67e-4fb0-9c0b-872b793cda7a' } = process.env;
const { OAUTH_CLIENT_SECRET = 'VYKsyjndsJ7lTnS2Z5vuz4SM-8Dvy1-4_yvqEoALMfY' } = process.env;
const { OAUTH_REDIRECT_URI = 'http://localhost:3000/oauth' } = process.env;
const { OAUTH_COOKIE_DOMAIN = 'localhost' } = process.env;

const oauthConfig = {
  clientId: OAUTH_CLIENT_ID,
  clientSecret: OAUTH_CLIENT_SECRET,
  redirectUri: OAUTH_REDIRECT_URI,
  cookieDomain: OAUTH_COOKIE_DOMAIN
};

const jwtOptions = {
  oauthConfig,
  required: true,
  alwaysLogin: false,
  browserLogin: true,
  verifyOptions: {
    issuer: JWT_ISSUER,
    audience: OAUTH_CLIENT_ID
  }
};

// create the middleware/handler factory
const auth = new ExpressJwtFusionAuth(FUSIONAUTH_URL);

const app = express();

// add the cookie-parser middleware to extract JWTs from the access_token cookie
app.use(cookieParser());

// add a route corresponding to the OAuth redirect URI,
// used to exchange an authorization code for a JWT/access token
app.get('/oauth', auth.oauthCompletion(oauthConfig));

// sample route requiring JWT authentication and the "root" or "admin" application role;
// for demonstration purposes, it just dumps the JWT claims as JSON
app.get('/authed',
  auth.jwt(jwtOptions),
  auth.jwtRole(['root', 'admin']),
  (req: express.Request, res) => res.json(req.jwt!));

// sample route with optional JWT authentication
app.get('/opt-authed',
  auth.jwt({ ...jwtOptions, required: false }),
  (req: express.Request, res) => res.send(req.jwt ? req.jwt.email : 'nobody'));

app.listen();
```

## API Reference

<a name="ExpressJwtFusionAuth"></a>

### ExpressJwtFusionAuth
<p>Provides factory methods for Express middleware/handlers used to obtain and validate JSON Web Tokens (JWTs).</p>

**Kind**: global class  

* [ExpressJwtFusionAuth](#ExpressJwtFusionAuth)
    * [new ExpressJwtFusionAuth(fusionAuthUrl)](#new_ExpressJwtFusionAuth_new)
    * [.jwt(options)](#ExpressJwtFusionAuth+jwt)
    * [.jwtRole(roleOrRoles)](#ExpressJwtFusionAuth+jwtRole)
    * [.oauthCompletion(config)](#ExpressJwtFusionAuth+oauthCompletion)

<a name="new_ExpressJwtFusionAuth_new"></a>

#### new ExpressJwtFusionAuth(fusionAuthUrl)
<p>Creates a middleware factory that communicates with FusionAuth at the given URL.</p>


| Param | Type | Description |
| --- | --- | --- |
| fusionAuthUrl | <code>string</code> | <p>the base URL of the FusionAuth application (e.g. <code>http://fusionauth:9011</code>)</p> |

<a name="ExpressJwtFusionAuth+jwt"></a>

#### expressJwtFusionAuth.jwt(options)
<p>Returns a middleware/handler that checks whether a request has a JWT attached,
validates the JWT, and associates the JWT contents with the request object.
By default, if the client appears to be a web browser, it will be redirected
to the FusionAuth OAuth 2.0 login URL. However, this behavior can be enabled
or disabled for all clients.</p>

**Kind**: instance method of [<code>ExpressJwtFusionAuth</code>](#ExpressJwtFusionAuth)  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>JwtOptions</code> | <p>the JWT acquisition and verification options</p> |

<a name="ExpressJwtFusionAuth+jwtRole"></a>

#### expressJwtFusionAuth.jwtRole(roleOrRoles)
<p>Returns a middleware/handler that checks whether a request has a valid JWT
attached that has at least one of the given application roles.
The request must have already had the JWT parsed and validated by the
<code>ExpressJwtFusionAuth.jwt</code> middleware. If the JWT is not present or does
not have one of the required roles, the request is failed with HTTP 403 Forbidden.</p>

**Kind**: instance method of [<code>ExpressJwtFusionAuth</code>](#ExpressJwtFusionAuth)  

| Param | Type | Description |
| --- | --- | --- |
| roleOrRoles | <code>string</code> | <p>the role or roles to check for</p> |

<a name="ExpressJwtFusionAuth+oauthCompletion"></a>

#### expressJwtFusionAuth.oauthCompletion(config)
<p>Returns a handler for the OAuth 2.0 redirection endpoint that exchanges an
authorization code for a JWT/access token and optional refresh token.</p>

**Kind**: instance method of [<code>ExpressJwtFusionAuth</code>](#ExpressJwtFusionAuth)  

| Param | Type | Description |
| --- | --- | --- |
| config | <code>OAuthConfig</code> | <p>the OAuth 2.0 configuration settings</p> |


## License

`express-jwt-fusionauth` is available under the [ISC license](LICENSE).
