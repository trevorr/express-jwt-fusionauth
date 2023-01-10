import assert, { fail } from 'assert';
import { expect } from 'chai';
import got, { HTTPError, Response } from 'got';
import * as jose from 'jose';
import qs from 'qs';
import { Cookie, parse as parseCookies } from 'set-cookie-parser';
import { isOAuthErrorResponse } from '../src';

const {
  APP_COOKIE_DOMAIN,
  APP_ACCESS_TOKEN_COOKIE = 'the_access_token',
  APP_REFRESH_TOKEN_COOKIE = 'the_refresh_token',
  APP_ACCESS_TOKEN_QUERY = 'q_access_token',
  APP_REFRESH_TOKEN_QUERY = 'q_refresh_token',
  APP_JWT_ISSUER,
  APP_URL,
  FUSIONAUTH_ADMIN_EMAIL,
  FUSIONAUTH_ADMIN_PASSWORD,
  FUSIONAUTH_APPLICATION_ID,
  FUSIONAUTH_TENANT_ISSUER,
  FUSIONAUTH_URL,
  ONE_TIME_REFRESH_APPLICATION_ID
} = process.env;

const api = got.extend({ prefixUrl: APP_URL });

let code: string | null;
let accessToken: string;
let appAccessToken: string;
let refreshToken: string;

interface AuthorizeOptions {
  client_id?: string;
  scope?: string;
}

function authorize({ client_id = FUSIONAUTH_APPLICATION_ID, ...options }: AuthorizeOptions = {}): Promise<
  Response<string>
> {
  return got.post(`${FUSIONAUTH_URL}/oauth2/authorize`, {
    body: qs.stringify({
      client_id,
      redirect_uri: `${APP_URL}/oauth`,
      response_type: 'code',
      state: '/authed',
      loginId: FUSIONAUTH_ADMIN_EMAIL,
      password: FUSIONAUTH_ADMIN_PASSWORD,
      ...options
    }),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    followRedirect: false
  });
}

async function getAuthorizationCode(options?: AuthorizeOptions): Promise<string> {
  const res = await authorize(options);
  if (res.statusCode !== 302) {
    throw new Error(`Expected 302 from authorization, got ${res.statusCode}`);
  }
  const redirect = new URL(res.headers.location ?? '');
  const code = redirect.searchParams.get('code');
  if (!code) {
    throw new Error('No code returned by authorization');
  }
  return code;
}

function getSetCookieHeader(res: Response): string[] {
  const setCookie: string | string[] | undefined = res.headers['set-cookie'];
  return setCookie ? (Array.isArray(setCookie) ? setCookie : [setCookie]) : [];
}

function getCookies(res: Response): Record<string, Cookie> {
  return parseCookies(getSetCookieHeader(res), { map: true });
}

describe('express-jwt-fusionauth', function () {
  this.timeout(10000);
  this.slow(2000);

  it('health check', async function () {
    const res = await api.get('');
    expect(res.statusCode).to.equal(200);
  });

  it('authenticated endpoint without JWT (non-browser)', async function () {
    try {
      await api.get('authed');
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint without JWT (browser)', async function () {
    const res = await api.get('authed', {
      headers: {
        Accept: 'text/html, */*'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    expect(res.headers.location).to.equal(
      `${FUSIONAUTH_URL}/oauth2/authorize?client_id=${FUSIONAUTH_APPLICATION_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth&response_type=code&state=%2Fauthed`
    );
  });

  it('authenticated endpoint without JWT (no cookies)', async function () {
    try {
      await api.get('authed-no-cookies');
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with invalid JWT (non-browser)', async function () {
    try {
      await api.get('authed', {
        headers: {
          Authorization: 'Bearer xxx'
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion requires code', async function () {
    try {
      await api.get('oauth', { responseType: 'json' });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(400);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('invalid_request');
      expect(err.response.body.error_description).to.equal('Authorization code required');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid POST body', async function () {
    try {
      await api.post('oauth', {
        body: 'meh',
        headers: { 'Content-Type': 'text/plain' },
        responseType: 'json'
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(400);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('invalid_request');
      expect(err.response.body.error_description).to.equal('Authorization code required');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid code', async function () {
    try {
      await api.get('oauth?code=xxx', { responseType: 'json' });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(400);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('invalid_request');
      expect(err.response.body.error_description).to.equal('Invalid Authorization Code');
      return;
    }
    fail('rejection expected');
  });

  it('oauth2/authorize', async function () {
    const res = await authorize();
    expect(res.statusCode).to.equal(302);
    const redirect = new URL(res.headers.location ?? '');
    expect(redirect.host).to.equal('localhost:3000');
    expect(redirect.pathname).to.equal('/oauth');
    expect(redirect.searchParams.get('state')).to.equal('/authed');
    expect(redirect.searchParams.get('userState')).to.equal('Authenticated');
    code = redirect.searchParams.get('code');
    expect(code).to.be.a('string');
  });

  it('oauth completion succeeds with valid code', async function () {
    const res = await api.post<Record<string, unknown>>('oauth', {
      body: qs.stringify({
        code
      }),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.be.a('object');
    expect(res.body.token_type).to.equal('Bearer');
    expect(res.body.access_token).to.be.a('string');
    expect(res.body.expires_in).to.be.a('number');
    assert(typeof res.body.access_token === 'string');
    accessToken = res.body.access_token;
  });

  it('oauth completion fails with invalid state', async function () {
    try {
      await api.get('oauth', {
        search: qs.stringify({
          code,
          state: ['is', 'an', 'array']
        }),
        responseType: 'json'
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(400);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('invalid_request');
      expect(err.response.body.error_description).to.equal('Invalid state value');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with state if cookie transport but cookies are disabled', async function () {
    try {
      await api.get('oauth-no-state', {
        searchParams: {
          code,
          state: '/my-redirect'
        },
        responseType: 'json'
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(400);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('invalid_request');
      expect(err.response.body.error_description).to.equal('Cannot specify redirect state with cookies disabled');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid configuration', async function () {
    try {
      await api.get('oauth-bad-config', {
        searchParams: {
          code
        },
        responseType: 'json'
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(500);
      assert(isOAuthErrorResponse(err.response.body));
      expect(err.response.body.error).to.equal('internal_error');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion redirects to state with cookies', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion redirects to state with cookies using explicit token_transport', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth', {
      searchParams: {
        code,
        state: '/my-redirect?token_transport=cookie'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion redirects to state with query parameters', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth-query', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
  });

  it('oauth completion redirects to state with additional query parameters', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth-query', {
      searchParams: {
        code,
        state: '/my-redirect?q=x'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?q=x&([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
  });

  it('oauth completion redirects to state with query parameters using token_transport override', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth', {
      searchParams: {
        code,
        state: '/my-redirect?token_transport=query'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
  });

  it('oauth completion redirects to state with query parameters if cookies are disabled', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('oauth-no-cookies', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
  });

  it('oauth completion returns refresh token', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get<Record<string, unknown>>('oauth', {
      searchParams: {
        code
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.be.a('object');
    expect(res.body.token_type).to.equal('Bearer');
    expect(res.body.access_token).to.be.a('string');
    expect(res.body.refresh_token).to.be.a('string');
    expect(res.body.expires_in).to.be.a('number');
    assert(typeof res.body.refresh_token === 'string');
    refreshToken = res.body.refresh_token;
  });

  it('oauth completion with refresh token redirects to state with cookies', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('oauth', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).not.to.be.undefined;
    expect(refreshTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(refreshTokenCookie.httpOnly).to.be.true;
    expect(refreshTokenCookie.expires).to.be.instanceOf(Date);
    expect(refreshTokenCookie.maxAge).to.be.a('number');
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion with refresh token redirects to state with query parameters', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('oauth-query', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+&([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
    expect(match?.[2]).to.equal(APP_REFRESH_TOKEN_QUERY);
  });

  it('oauth completion redirects to state with access token query parameter and refresh token cookie', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('oauth-no-access-token-cookie', {
      searchParams: {
        code,
        state: '/my-redirect'
      },
      followRedirect: false
    });
    expect(res.statusCode).to.equal(302);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).not.to.be.undefined;
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location ?? '');
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_QUERY);
  });

  it('oauth completion supports application JWT', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get<Record<string, unknown>>('oauth-app-jwt', {
      searchParams: {
        code
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.be.a('object');
    expect(res.body.token_type).to.equal('Bearer');
    expect(res.body.access_token).to.be.a('string');
    expect(res.body.expires_in).to.be.a('number');
    assert(typeof res.body.access_token === 'string');
    const jwt = jose.UnsecuredJWT.decode(res.body.access_token);
    expect(jwt.payload.iss).to.equal(APP_JWT_ISSUER);
    appAccessToken = res.body.access_token;
  });

  it('authenticated endpoint with Authorization Header Bearer token', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with access token cookie', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with application JWT', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed-app-jwt', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${appAccessToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(APP_JWT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint without required role', async function () {
    try {
      await api.get('super', {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(403);
      return;
    }
    fail('rejection expected');
  });

  it('optionally authenticated endpoint without JWT', async function () {
    const res = await api.get('opt-authed');
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.equal('nobody');
  });

  it('optionally authenticated endpoint with valid JWT', async function () {
    const res = await api.get('opt-authed', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.equal('test@example.com');
  });

  it('optionally authenticated endpoint with invalid JWT', async function () {
    try {
      await api.get('opt-authed', {
        headers: {
          Authorization: 'Bearer xxx'
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('optionally authenticated endpoint with empty JWT', async function () {
    const res = await api.get('opt-authed', {
      headers: {
        Authorization: 'Bearer'
      }
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body).to.equal('nobody');
  });

  it('authenticated endpoint with refresh token cookie', async function () {
    this.timeout(15000);
    await sleep(11000); // JWT timeToLiveInSeconds = 10
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.value).to.not.equal(accessToken);
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).to.be.undefined;
  });

  it('authenticated endpoint supporting refresh headers but using refresh token cookie', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed-header-refresh', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.value).to.not.equal(accessToken);
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).to.be.undefined;
  });

  it('authenticated endpoint with refresh token header', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed-header-refresh', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Refresh-Token': refreshToken
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    expect(res.headers['new-access-token']).to.be.a('string');
    expect(res.headers['new-access-token']).to.not.equal(accessToken);
    expect(res.headers['new-refresh-token']).to.be.undefined;
  });

  it('authenticated endpoint with access token header and refresh token cookie', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed-header-refresh', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Cookie: `${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    expect(res.headers['new-access-token']).to.be.a('string');
    expect(res.headers['new-access-token']).to.not.equal(accessToken);
    expect(res.headers['new-refresh-token']).to.be.undefined;
  });

  it('authenticated endpoint with refresh token cookie and application JWT', async function () {
    const res = await api.get<{ jwt: Record<string, unknown> }>('authed-app-jwt', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${appAccessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.exp).to.be.a('number');
    expect(res.body.jwt.iat).to.be.a('number');
    expect(res.body.jwt.iss).to.equal(APP_JWT_ISSUER);
    expect(res.body.jwt.sub).to.be.a('string');
    expect(res.body.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.jwt.email).to.equal('test@example.com');
    expect(res.body.jwt.email_verified).to.be.true;
    expect(res.body.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.value).to.not.equal(accessToken);
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).to.be.undefined;
  });

  it('authenticated endpoint with refresh cookie and cookies disabled', async function () {
    try {
      await api.get('authed-no-cookies', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Cookie: `${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with refresh header and cookies disabled', async function () {
    try {
      await api.get('authed-no-cookies', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'refresh-token': refreshToken
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('unsafe authenticated endpoint with refresh cookie and expired JWT', async function () {
    try {
      await api.post('authed', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Cookie: `${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with invalid refresh token cookie', async function () {
    try {
      await api.get('authed', {
        headers: {
          Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=junk`
        }
      });
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('explicit refresh', async function () {
    this.timeout(15000);
    await sleep(11000); // JWT timeToLiveInSeconds = 10
    const res = await api.get<Record<string, unknown>>('refresh', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.token).to.be.a('string');
    expect(res.body.token).to.not.equal(accessToken);
    expect(res.body.refreshToken).to.be.a('string');
    assert(isRecord(res.body.payload));
    expect(res.body.payload.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.payload.exp).to.be.a('number');
    expect(res.body.payload.iat).to.be.a('number');
    expect(res.body.payload.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.body.payload.sub).to.be.a('string');
    expect(res.body.payload.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.payload.email).to.equal('test@example.com');
    expect(res.body.payload.email_verified).to.be.true;
    expect(res.body.payload.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.payload.roles).to.eql(['admin']);
    assert(typeof res.body.refreshToken === 'string');
    refreshToken = res.body.refreshToken;
  });

  it('explicit refresh supports application JWT', async function () {
    const res = await api.post<Record<string, unknown>>('refresh-app-jwt', {
      json: { refreshToken: refreshToken },
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.token).to.be.a('string');
    expect(res.body.token).to.not.equal(accessToken);
    expect(res.body.refreshToken).to.be.a('string');
    assert(isRecord(res.body.payload));
    expect(res.body.payload.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.payload.exp).to.be.a('number');
    expect(res.body.payload.iat).to.be.a('number');
    expect(res.body.payload.iss).to.equal(APP_JWT_ISSUER);
    expect(res.body.payload.sub).to.be.a('string');
    expect(res.body.payload.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.body.payload.email).to.equal('test@example.com');
    expect(res.body.payload.email_verified).to.be.true;
    expect(res.body.payload.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.body.payload.roles).to.eql(['admin']);
    assert(typeof res.body.refreshToken === 'string');
    refreshToken = res.body.refreshToken;
  });

  it('supports one-time use refresh tokens', async function () {
    this.timeout(30000);

    const code = await getAuthorizationCode({
      client_id: ONE_TIME_REFRESH_APPLICATION_ID,
      scope: 'offline_access'
    });
    let res = await api.get<Record<string, unknown>>('oauth-one-time-refresh', {
      searchParams: { code },
      followRedirect: false,
      responseType: 'json'
    });
    expect(res.statusCode).to.equal(200);
    expect(res.body.access_token).to.be.a('string');
    expect(res.body.refresh_token).to.be.a('string');
    const accessToken = res.body.access_token;
    const refreshToken = res.body.refresh_token;

    await sleep(11000); // JWT timeToLiveInSeconds = 10

    res = await api.get<Record<string, unknown>>('authed-one-time-refresh', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.statusCode).to.equal(200);
    let cookies = getCookies(res);
    const accessTokenCookie = cookies[APP_ACCESS_TOKEN_COOKIE];
    expect(accessTokenCookie).not.to.be.undefined;
    expect(accessTokenCookie.value).to.not.equal(accessToken);
    expect(accessTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(accessTokenCookie.httpOnly).to.be.true;
    expect(accessTokenCookie.expires).to.be.undefined;
    const refreshTokenCookie = cookies[APP_REFRESH_TOKEN_COOKIE];
    expect(refreshTokenCookie).not.to.be.undefined;
    expect(refreshTokenCookie.domain).to.equal(APP_COOKIE_DOMAIN);
    expect(refreshTokenCookie.httpOnly).to.be.true;
    expect(refreshTokenCookie.expires).to.be.instanceOf(Date);
    expect(refreshTokenCookie.maxAge).to.be.undefined;
    const accessToken2 = accessTokenCookie.value;
    const refreshToken2 = refreshTokenCookie.value;

    await sleep(11000); // JWT timeToLiveInSeconds = 10

    try {
      res = await api.get<Record<string, unknown>>('authed-one-time-refresh', {
        headers: {
          Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
        }
      });
      fail('rejection expected');
    } catch (err) {
      assert(err instanceof HTTPError && err.response);
      expect(err.response.statusCode).to.equal(401);
    }

    res = await api.get<Record<string, unknown>>('authed-one-time-refresh', {
      headers: {
        Authorization: `Bearer ${accessToken2}`,
        'Refresh-Token': refreshToken2
      }
    });
    expect(res.statusCode).to.equal(200);
    cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    expect(res.headers['new-access-token']).to.be.a('string');
    expect(res.headers['new-access-token']).to.not.equal(accessToken2);
    expect(res.headers['new-refresh-token']).to.be.a('string');
    expect(res.headers['new-refresh-token']).to.not.equal(refreshToken2);
  });

  it('handles invalid OAuthError responses', function () {
    expect(isOAuthErrorResponse(undefined)).to.be.false;
    expect(isOAuthErrorResponse({})).to.be.true;
    expect(isOAuthErrorResponse({ error: '' })).to.be.true;
    expect(isOAuthErrorResponse({ error: 0 })).to.be.false;
    expect(isOAuthErrorResponse({ error_description: '' })).to.be.true;
    expect(isOAuthErrorResponse({ error_description: 0 })).to.be.false;
  });
});

function sleep(ms: number): Promise<void> {
  return new Promise<void>(resolve => {
    setTimeout(() => resolve(), ms);
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v != null;
}
