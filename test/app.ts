import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import express from 'express';
import UnsecuredJWT from 'jose/jwt/unsecured';
import { ExpressJwtFusionAuth, JwtClaims, JwtOptions, JwtTransform, JwtVerifier, OAuthConfig } from '../src';

const {
  APP_COOKIE_DOMAIN,
  APP_JWT_ISSUER,
  FUSIONAUTH_APPLICATION_CLIENT_SECRET,
  FUSIONAUTH_APPLICATION_ID,
  FUSIONAUTH_APPLICATION_REDIRECT_URL,
  FUSIONAUTH_TENANT_ISSUER,
  FUSIONAUTH_URL,
  PORT = '3000'
} = process.env;

const oauthConfig: OAuthConfig = {
  clientId: FUSIONAUTH_APPLICATION_ID!,
  clientSecret: FUSIONAUTH_APPLICATION_CLIENT_SECRET,
  redirectUri: FUSIONAUTH_APPLICATION_REDIRECT_URL!,
  cookieConfig: {
    domain: APP_COOKIE_DOMAIN
  }
};

const jwtOptions: JwtOptions = {
  oauthConfig,
  required: true,
  alwaysLogin: false,
  browserLogin: true,
  verifyOptions: {
    issuer: FUSIONAUTH_TENANT_ISSUER,
    audience: FUSIONAUTH_APPLICATION_ID
  }
};

const jwtTransform: JwtTransform = async ({ token, payload }) => {
  payload = { ...payload, iss: APP_JWT_ISSUER! };
  token = new UnsecuredJWT(payload).encode();
  return { token, payload };
};

const jwtVerifier: JwtVerifier = async token => {
  if (!token.endsWith('.')) {
    return false;
  }
  // Don't do this in real apps! Use jwtVerify!
  const jwt = UnsecuredJWT.decode(token);
  if (jwt.payload.iss !== APP_JWT_ISSUER) {
    return false;
  }
  return jwt.payload as JwtClaims;
};

const appJwtOptions = { ...jwtOptions, jwtTransform, jwtVerifier };

const auth = new ExpressJwtFusionAuth(FUSIONAUTH_URL!);
const app = express();
app.use(cookieParser());
app.get('/', (_, res) => res.send('OK'));
app.get('/oauth', auth.oauthCompletion(oauthConfig));
app.get('/oauth-app-jwt', auth.oauthCompletion({ ...oauthConfig, jwtTransform }));
app.get('/oauth-query', auth.oauthCompletion({ ...oauthConfig, tokenTransport: 'query' }));
app.get('/oauth-no-cookies', auth.oauthCompletion({ ...oauthConfig, cookieConfig: { disabled: true } }));
app.get(
  '/oauth-no-state',
  auth.oauthCompletion({ ...oauthConfig, tokenTransport: 'cookie', cookieConfig: { disabled: true } })
);
app.post('/oauth', bodyParser.urlencoded({ extended: true }), auth.oauthCompletion(oauthConfig));
app.get('/oauth-bad-config', new ExpressJwtFusionAuth('http://localhost:99999').oauthCompletion(oauthConfig));
app.get('/authed', auth.jwt(jwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.get('/authed-app-jwt', auth.jwt(appJwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
  const { jwt } = req;
  res.json({ jwt });
});
app.get(
  '/authed-no-cookies',
  auth.jwt({ ...jwtOptions, cookieConfig: { disabled: true } }),
  auth.jwtRole(['root', 'admin']),
  (req: express.Request, res) => {
    const { jwt } = req;
    res.json({ jwt });
  }
);
app.get('/refresh', async (req: express.Request, res) => {
  try {
    const result = await auth.refreshJwt(req.cookies.refresh_token, req.cookies.access_token);
    res.json(result);
  } catch {
    res.sendStatus(500);
  }
});
app.post('/refresh-app-jwt', bodyParser.json(), async (req: express.Request, res) => {
  try {
    const authorization = req.header('authorization');
    const token = authorization?.startsWith('Bearer ') ? authorization.substring(7) : undefined;
    const { refreshToken } = req.body;
    const result = await auth.refreshJwt(refreshToken, token, { options: appJwtOptions });
    res.json(result);
  } catch {
    res.sendStatus(500);
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
