import assert, { fail } from 'assert';
import axios, { AxiosResponse } from 'axios';
import { expect } from 'chai';
import cookie from 'cookie';
import * as jose from 'jose';
import qs from 'qs';
import { isOAuthErrorResponse } from '../src';

const {
  APP_COOKIE_DOMAIN,
  APP_ACCESS_TOKEN_COOKIE = 'the_access_token',
  APP_REFRESH_TOKEN_COOKIE = 'the_refresh_token',
  APP_JWT_ISSUER,
  APP_URL,
  FUSIONAUTH_ADMIN_EMAIL,
  FUSIONAUTH_ADMIN_PASSWORD,
  FUSIONAUTH_APPLICATION_ID,
  FUSIONAUTH_TENANT_ISSUER,
  FUSIONAUTH_URL
} = process.env;

const api = axios.create({ baseURL: APP_URL });

let code: string | null;
let accessToken: string;
let appAccessToken: string;
let refreshToken: string;

interface AuthorizeOptions {
  scope?: string;
}

function authorize(options: AuthorizeOptions = {}): Promise<AxiosResponse<void>> {
  return api.post(
    `${FUSIONAUTH_URL}/oauth2/authorize`,
    qs.stringify({
      client_id: FUSIONAUTH_APPLICATION_ID,
      redirect_uri: `${APP_URL}/oauth`,
      response_type: 'code',
      state: '/authed',
      loginId: FUSIONAUTH_ADMIN_EMAIL,
      password: FUSIONAUTH_ADMIN_PASSWORD,
      ...options
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    }
  );
}

async function getAuthorizationCode(options?: AuthorizeOptions): Promise<string> {
  const res = await authorize(options);
  if (res.status !== 302) {
    throw new Error(`Expected 302 from authorization, got ${res.status}`);
  }
  const redirect = new URL(res.headers.location);
  const code = redirect.searchParams.get('code');
  if (!code) {
    throw new Error('No code returned by authorization');
  }
  return code;
}

function getSetCookieHeader(res: AxiosResponse): string[] {
  const setCookie: string | string[] | undefined = res.headers['set-cookie'];
  return setCookie ? (Array.isArray(setCookie) ? setCookie : [setCookie]) : [];
}

function getCookies(res: AxiosResponse): Record<string, string> {
  return getSetCookieHeader(res).reduce((obj, str) => Object.assign(obj, cookie.parse(str)), {});
}

function hasHttpOnlyCookies(res: AxiosResponse): boolean {
  return getSetCookieHeader(res).reduce<boolean>((acc, str) => acc && str.includes('HttpOnly'), true);
}

describe('express-jwt-fusionauth', function () {
  this.timeout(10000);
  this.slow(2000);

  it('health check', async function () {
    const res = await api.get('/');
    expect(res.status).to.equal(200);
  });

  it('authenticated endpoint without JWT (non-browser)', async function () {
    try {
      await api.get('/authed');
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint without JWT (browser)', async function () {
    try {
      await api.get('/authed', {
        headers: {
          Accept: 'text/html, */*'
        },
        maxRedirects: 0
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(302);
      expect(err.response.headers.location).to.equal(
        `${FUSIONAUTH_URL}/oauth2/authorize?client_id=${FUSIONAUTH_APPLICATION_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth&response_type=code&state=%2Fauthed`
      );
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint without JWT (no cookies)', async function () {
    try {
      await api.get('/authed-no-cookies');
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with invalid JWT (non-browser)', async function () {
    try {
      await api.get('/authed', {
        headers: {
          Authorization: 'Bearer xxx'
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion requires code', async function () {
    try {
      await api.get('/oauth');
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(400);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Authorization code required');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid POST body', async function () {
    try {
      await api.post('/oauth', 'meh', { headers: { 'Content-Type': 'text/plain' } });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(400);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Authorization code required');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid code', async function () {
    try {
      await api.get('/oauth?code=xxx');
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(400);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Invalid Authorization Code');
      return;
    }
    fail('rejection expected');
  });

  it('oauth2/authorize', async function () {
    const res = await authorize();
    expect(res.status).to.equal(302);
    const redirect = new URL(res.headers.location);
    expect(redirect.host).to.equal('localhost:3000');
    expect(redirect.pathname).to.equal('/oauth');
    expect(redirect.searchParams.get('state')).to.equal('/authed');
    expect(redirect.searchParams.get('userState')).to.equal('Authenticated');
    code = redirect.searchParams.get('code');
    expect(code).to.be.a('string');
  });

  it('oauth completion succeeds with valid code', async function () {
    const res = await api.post(
      '/oauth',
      qs.stringify({
        code
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    expect(res.status).to.equal(200);
    expect(res.data).to.be.a('object');
    expect(res.data.token_type).to.equal('Bearer');
    expect(res.data.access_token).to.be.a('string');
    expect(res.data.expires_in).to.be.a('number');
    accessToken = res.data.access_token;
  });

  it('oauth completion fails with invalid state', async function () {
    try {
      await api.get('/oauth', {
        params: {
          code,
          state: ['is', 'an', 'array']
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(400);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Invalid state value');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with state if cookie transport but cookies are disabled', async function () {
    try {
      await api.get('/oauth-no-state', {
        params: {
          code,
          state: '/my-redirect'
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(400);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Cannot specify redirect state with cookies disabled');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid configuration', async function () {
    try {
      await api.get('/oauth-bad-config', {
        params: {
          code
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(500);
      assert(isOAuthErrorResponse(err.response.data));
      expect(err.response.data.error).to.equal('internal_error');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion redirects to state with cookies', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion redirects to state with cookies using explicit token_transport', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth', {
      params: {
        code,
        state: '/my-redirect?token_transport=cookie'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion redirects to state with query parameters', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth-query', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
  });

  it('oauth completion redirects to state with additional query parameters', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth-query', {
      params: {
        code,
        state: '/my-redirect?q=x'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?q=x&([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
  });

  it('oauth completion redirects to state with query parameters using token_transport override', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth', {
      params: {
        code,
        state: '/my-redirect?token_transport=query'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
  });

  it('oauth completion redirects to state with query parameters if cookies are disabled', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth-no-cookies', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
  });

  it('oauth completion returns refresh token', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('/oauth', {
      params: {
        code
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.be.a('object');
    expect(res.data.token_type).to.equal('Bearer');
    expect(res.data.access_token).to.be.a('string');
    expect(res.data.refresh_token).to.be.a('string');
    expect(res.data.expires_in).to.be.a('number');
    refreshToken = res.data.refresh_token;
  });

  it('oauth completion with refresh token redirects to state with cookies', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('/oauth', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion with refresh token redirects to state with query parameters', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('/oauth-query', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    const match = /\/my-redirect\?([^=]+)=[\w.-]+&([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
    expect(match?.[2]).to.equal(APP_REFRESH_TOKEN_COOKIE);
  });

  it('oauth completion redirects to state with access token query parameter and refresh token cookie', async function () {
    const code = await getAuthorizationCode({ scope: 'offline_access' });
    const res = await api.get('/oauth-no-access-token-cookie', {
      params: {
        code,
        state: '/my-redirect'
      },
      maxRedirects: 0,
      validateStatus(status) {
        return status < 400;
      }
    });
    expect(res.status).to.equal(302);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.undefined;
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    const match = /\/my-redirect\?([^=]+)=[\w.-]+/.exec(res.headers.location);
    expect(match).to.not.be.null;
    expect(match?.[1]).to.equal(APP_ACCESS_TOKEN_COOKIE);
  });

  it('oauth completion supports application JWT', async function () {
    const code = await getAuthorizationCode();
    const res = await api.get('/oauth-app-jwt', {
      params: {
        code
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.be.a('object');
    expect(res.data.token_type).to.equal('Bearer');
    expect(res.data.access_token).to.be.a('string');
    expect(res.data.expires_in).to.be.a('number');
    const jwt = jose.UnsecuredJWT.decode(res.data.access_token);
    expect(jwt.payload.iss).to.equal(APP_JWT_ISSUER);
    appAccessToken = res.data.access_token;
  });

  it('authenticated endpoint with Authorization Header Bearer token', async function () {
    const res = await api.get('/authed', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with access token cookie', async function () {
    const res = await api.get('/authed', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with application JWT', async function () {
    const res = await api.get('/authed-app-jwt', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${appAccessToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(APP_JWT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint without required role', async function () {
    try {
      await api.get('/super', {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(403);
      return;
    }
    fail('rejection expected');
  });

  it('optionally authenticated endpoint without JWT', async function () {
    const res = await api.get('/opt-authed');
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('optionally authenticated endpoint with valid JWT', async function () {
    const res = await api.get('/opt-authed', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('test@example.com');
  });

  it('optionally authenticated endpoint with invalid JWT', async function () {
    try {
      await api.get('/opt-authed', {
        headers: {
          Authorization: 'Bearer xxx'
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('optionally authenticated endpoint with empty JWT', async function () {
    const res = await api.get('/opt-authed', {
      headers: {
        Authorization: 'Bearer'
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('authenticated endpoint with refresh token cookie', async function () {
    this.timeout(10000);
    await sleep(6000); // JWT timeToLiveInSeconds = 5
    const res = await api.get('/authed', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.not.equal(accessToken);
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    refreshToken = cookies[APP_REFRESH_TOKEN_COOKIE];
  });

  it('authenticated endpoint supporting refresh headers but using refresh token cookie', async function () {
    const res = await api.get('/authed-header-refresh', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.not.equal(accessToken);
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    refreshToken = cookies[APP_REFRESH_TOKEN_COOKIE];
  });

  it('authenticated endpoint with refresh token header', async function () {
    const res = await api.get('/authed-header-refresh', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Refresh-Token': refreshToken
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(Object.keys(cookies)).to.have.length(0);
    expect(res.headers['new-access-token']).to.be.a('string');
    expect(res.headers['new-access-token']).to.not.equal(accessToken);
    expect(res.headers['new-refresh-token']).to.be.a('string');
    refreshToken = res.headers['new-refresh-token'];
  });

  it('authenticated endpoint with access token header and refresh token cookie', async function () {
    const res = await api.get('/authed-header-refresh', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Cookie: `${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers['new-access-token']).to.be.a('string');
    expect(res.headers['new-access-token']).to.not.equal(accessToken);
    expect(res.headers['new-refresh-token']).to.be.undefined;
    refreshToken = cookies[APP_REFRESH_TOKEN_COOKIE];
  });

  it('authenticated endpoint with refresh token cookie and application JWT', async function () {
    const res = await api.get('/authed-app-jwt', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${appAccessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal(APP_JWT_ISSUER);
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies[APP_ACCESS_TOKEN_COOKIE]).to.not.equal(accessToken);
    expect(cookies[APP_REFRESH_TOKEN_COOKIE]).to.be.a('string');
    expect(cookies.Domain).to.equal(APP_COOKIE_DOMAIN);
    expect(hasHttpOnlyCookies(res)).to.be.true;
    refreshToken = cookies[APP_REFRESH_TOKEN_COOKIE];
  });

  it('authenticated endpoint with expired JWT and cookies disabled', async function () {
    try {
      await api.get('/authed-no-cookies', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Cookie: `${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with invalid refresh token cookie', async function () {
    try {
      await api.get('/authed', {
        headers: {
          Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=junk`
        }
      });
    } catch (err) {
      assert(axios.isAxiosError(err) && err.response);
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('explicit refresh', async function () {
    this.timeout(10000);
    await sleep(6000); // JWT timeToLiveInSeconds = 5
    const res = await api.get('/refresh', {
      headers: {
        Cookie: `${APP_ACCESS_TOKEN_COOKIE}=${accessToken}; ${APP_REFRESH_TOKEN_COOKIE}=${refreshToken}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.token).to.be.a('string');
    expect(res.data.token).to.not.equal(accessToken);
    expect(res.data.refreshToken).to.be.a('string');
    expect(res.data.payload.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.payload.exp).to.be.a('number');
    expect(res.data.payload.iat).to.be.a('number');
    expect(res.data.payload.iss).to.equal(FUSIONAUTH_TENANT_ISSUER);
    expect(res.data.payload.sub).to.be.a('string');
    expect(res.data.payload.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.payload.email).to.equal('test@example.com');
    expect(res.data.payload.email_verified).to.be.true;
    expect(res.data.payload.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.payload.roles).to.eql(['admin']);
    refreshToken = res.data.refreshToken;
  });

  it('explicit refresh supports application JWT', async function () {
    const res = await api.post(
      '/refresh-app-jwt',
      { refreshToken: refreshToken },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );
    expect(res.status).to.equal(200);
    expect(res.data.token).to.be.a('string');
    expect(res.data.token).to.not.equal(accessToken);
    expect(res.data.refreshToken).to.be.a('string');
    expect(res.data.payload.aud).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.payload.exp).to.be.a('number');
    expect(res.data.payload.iat).to.be.a('number');
    expect(res.data.payload.iss).to.equal(APP_JWT_ISSUER);
    expect(res.data.payload.sub).to.be.a('string');
    expect(res.data.payload.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.payload.email).to.equal('test@example.com');
    expect(res.data.payload.email_verified).to.be.true;
    expect(res.data.payload.applicationId).to.equal(FUSIONAUTH_APPLICATION_ID);
    expect(res.data.payload.roles).to.eql(['admin']);
    refreshToken = res.data.refreshToken;
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
