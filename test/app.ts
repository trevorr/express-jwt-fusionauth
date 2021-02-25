import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import express from 'express';
import { ExpressJwtFusionAuth } from '../src';

const { FUSIONAUTH_URL = 'http://fusionauth:9011' } = process.env;
const { JWT_ISSUER = 'acme.com' } = process.env;
const { OAUTH_CLIENT_ID = '31d7b8e8-f67e-4fb0-9c0b-872b793cda7a' } = process.env;
const { OAUTH_CLIENT_SECRET = 'VYKsyjndsJ7lTnS2Z5vuz4SM-8Dvy1-4_yvqEoALMfY' } = process.env;
const { OAUTH_REDIRECT_URI = 'http://localhost:3000/oauth' } = process.env;
const { OAUTH_COOKIE_DOMAIN = 'app.domain' } = process.env;
const { PORT = '3000' } = process.env;

const oauthConfig = {
  clientId: OAUTH_CLIENT_ID,
  clientSecret: OAUTH_CLIENT_SECRET,
  redirectUri: OAUTH_REDIRECT_URI,
  cookieConfig: {
    domain: OAUTH_COOKIE_DOMAIN
  }
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

const auth = new ExpressJwtFusionAuth(FUSIONAUTH_URL);
const app = express();
app.use(cookieParser());
app.get('/', (_, res) => res.send('OK'));
app.get('/oauth', auth.oauthCompletion(oauthConfig));
app.get('/oauth-no-cookies', auth.oauthCompletion({ ...oauthConfig, cookieConfig: { disabled: true } }));
app.post('/oauth', bodyParser.urlencoded({ extended: true }), auth.oauthCompletion(oauthConfig));
app.get('/oauth-bad-config', new ExpressJwtFusionAuth('http://localhost:99999').oauthCompletion(oauthConfig));
app.get('/authed', auth.jwt(jwtOptions), auth.jwtRole(['root', 'admin']), (req: express.Request, res) => {
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
    const result = await auth.refreshJwt(jwtOptions, req.cookies.refresh_token, req.cookies.access_token);
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
