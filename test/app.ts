import cookieParser from 'cookie-parser';
import express from 'express';
import * as jose from 'jose';
import { ExpressJwtFusionAuth, JwtClaims, JwtOptions, JwtTransform, JwtVerifier, OAuthConfig } from '../src';
import { getDefaultLogger } from '../src/logger';

const {
  APP_COOKIE_DOMAIN,
  APP_ACCESS_TOKEN_COOKIE = 'the_access_token',
  APP_REFRESH_TOKEN_COOKIE = 'the_refresh_token',
  APP_JWT_ISSUER,
  FUSIONAUTH_TENANT_ISSUER,
  PORT = '3000'
} = process.env;

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value == null) throw new Error(`Environment variable missing: ${name}`);
  return value;
}

const oauthConfig: OAuthConfig = {
  clientId: requiredEnv('FUSIONAUTH_APPLICATION_ID'),
  clientSecret: requiredEnv('FUSIONAUTH_APPLICATION_CLIENT_SECRET'),
  redirectUri: requiredEnv('FUSIONAUTH_APPLICATION_REDIRECT_URL'),
  cookieConfig: {
    domain: APP_COOKIE_DOMAIN
  },
  accessTokenCookieConfig: {
    name: APP_ACCESS_TOKEN_COOKIE
  },
  refreshTokenCookieConfig: {
    name: APP_REFRESH_TOKEN_COOKIE
  }
};

const jwtOptions: JwtOptions = {
  oauthConfig,
  required: true,
  alwaysLogin: false,
  browserLogin: true,
  verifyOptions: {
    issuer: FUSIONAUTH_TENANT_ISSUER,
    audience: oauthConfig.clientId
  }
};

const oauthConfigOneTimeRefresh: OAuthConfig = {
  clientId: requiredEnv('ONE_TIME_REFRESH_APPLICATION_ID'),
  clientSecret: requiredEnv('ONE_TIME_REFRESH_APPLICATION_CLIENT_SECRET'),
  redirectUri: requiredEnv('ONE_TIME_REFRESH_APPLICATION_REDIRECT_URL'),
  cookieConfig: {
    domain: APP_COOKIE_DOMAIN
  },
  accessTokenCookieConfig: {
    name: APP_ACCESS_TOKEN_COOKIE
  },
  refreshTokenCookieConfig: {
    name: APP_REFRESH_TOKEN_COOKIE
  }
};

const jwtOptionsOneTimeRefresh: JwtOptions = {
  oauthConfig: oauthConfigOneTimeRefresh,
  required: true,
  alwaysLogin: false,
  browserLogin: true,
  headerConfig: {
    refreshTokenHeader: 'refresh-token',
    refreshedAccessTokenHeader: 'new-access-token',
    refreshedRefreshTokenHeader: 'new-refresh-token'
  },
  verifyOptions: {
    issuer: FUSIONAUTH_TENANT_ISSUER,
    audience: oauthConfigOneTimeRefresh.clientId
  }
};

const jwtTransform: JwtTransform = async ({ token, payload }) => {
  payload = { ...payload, iss: requiredEnv('APP_JWT_ISSUER') };
  token = new jose.UnsecuredJWT(payload).encode();
  return { token, payload };
};

const jwtVerifier: JwtVerifier = async token => {
  if (!token.endsWith('.')) {
    return false;
  }
  // Don't do this in real apps! Use jwtVerify!
  const jwt = jose.UnsecuredJWT.decode(token);
  if (jwt.payload.iss !== APP_JWT_ISSUER) {
    return false;
  }
  return jwt.payload as JwtClaims;
};

const appJwtOptions = { ...jwtOptions, jwtTransform, jwtVerifier, logger: getDefaultLogger() };

const auth = new ExpressJwtFusionAuth(requiredEnv('FUSIONAUTH_URL'));
const app = express();
app.use(cookieParser());
app.get('/', (_, res) => res.send('OK'));
app.get('/oauth', auth.oauthCompletion(oauthConfig));
app.get('/oauth-one-time-refresh', auth.oauthCompletion(oauthConfigOneTimeRefresh));
app.get('/oauth-app-jwt', auth.oauthCompletion({ ...oauthConfig, jwtTransform }));
app.get('/oauth-query', auth.oauthCompletion({ ...oauthConfig, tokenTransport: 'query' }));
app.get('/oauth-no-cookies', auth.oauthCompletion({ ...oauthConfig, cookieConfig: { disabled: true } }));
app.get(
  '/oauth-no-access-token-cookie',
  auth.oauthCompletion({ ...oauthConfig, accessTokenCookieConfig: { name: APP_ACCESS_TOKEN_COOKIE, disabled: true } })
);
app.get(
  '/oauth-no-state',
  auth.oauthCompletion({ ...oauthConfig, tokenTransport: 'cookie', cookieConfig: { disabled: true } })
);
app.post('/oauth', express.urlencoded({ extended: true }), auth.oauthCompletion(oauthConfig));
app.get('/oauth-bad-config', new ExpressJwtFusionAuth('http://localhost:99999').oauthCompletion(oauthConfig));
app.get('/authed', auth.jwt(jwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.post('/authed', auth.jwt(jwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.get(
  '/authed-one-time-refresh',
  auth.jwt(jwtOptionsOneTimeRefresh),
  auth.jwtRole(['root', 'admin']),
  (req: express.Request, res) => {
    const { jwt } = req;
    res.json({ jwt });
  }
);
app.get('/authed-app-jwt', auth.jwt(appJwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.get(
  '/authed-no-cookies',
  auth.jwt({ ...jwtOptions, cookieConfig: { disabled: true }, headerConfig: { refreshTokenHeader: 'refresh-token' } }),
  auth.jwtRole(['root', 'admin']),
  (req: express.Request, res) => {
    const { jwt } = req;
    res.json({ jwt });
  }
);
app.get(
  '/authed-header-refresh',
  auth.jwt({
    ...jwtOptions,
    headerConfig: {
      refreshTokenHeader: 'refresh-token',
      refreshedAccessTokenHeader: 'new-access-token',
      refreshedRefreshTokenHeader: 'new-refresh-token'
    }
  }),
  auth.jwtRole(['root', 'admin']),
  (req: express.Request, res) => {
    const { jwt } = req;
    res.json({ jwt });
  }
);
app.get('/refresh', async (req: express.Request, res) => {
  try {
    const result = await auth.refreshJwt(req.cookies[APP_REFRESH_TOKEN_COOKIE], req.cookies[APP_ACCESS_TOKEN_COOKIE]);
    res.json(result);
  } catch {
    res.sendStatus(400);
  }
});
app.post('/refresh-app-jwt', express.json(), async (req: express.Request, res) => {
  try {
    const authorization = req.header('authorization');
    const token = authorization?.startsWith('Bearer ') ? authorization.substring(7) : undefined;
    const { refreshToken } = req.body;
    const result = await auth.refreshJwt(refreshToken, token, { options: appJwtOptions });
    res.json(result);
  } catch {
    res.sendStatus(400);
  }
});
app.get('/super', auth.jwt(jwtOptions), auth.jwtRole('super'), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.get('/opt-authed', auth.jwt({ ...jwtOptions, required: false }), (req: express.Request, res) =>
  res.send(req.jwt ? req.jwt.email : 'nobody')
);

const port = parseInt(PORT);
app.listen(port);
console.log(`Listening on port ${port}`);

process.on('SIGINT', () => process.exit());
