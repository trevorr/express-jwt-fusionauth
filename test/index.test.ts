import { fail } from 'assert';
import axios, { AxiosResponse } from 'axios';
import { expect } from 'chai';
import cookie from 'cookie';
import qs from 'qs';

const applicationId = '31d7b8e8-f67e-4fb0-9c0b-872b793cda7a';
const appUrl = 'http://localhost:3000';
const fusionAuthUrl = 'http://fusionauth:9011';
const api = axios.create({ baseURL: appUrl });

let code: string | null;
let access_token: string;
let refresh_token: string;

interface AuthorizeOptions {
  scope?: string;
}

function authorize(options: AuthorizeOptions = {}): Promise<AxiosResponse<void>> {
  return api.post(
    `${fusionAuthUrl}/oauth2/authorize`,
    qs.stringify({
      client_id: applicationId,
      redirect_uri: `${appUrl}/oauth`,
      response_type: 'code',
      state: '/authed',
      loginId: 'test@example.com',
      password: 'test1234',
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

  it('health check', async () => {
    const res = await api.get('/');
    expect(res.status).to.equal(200);
  });

  it('authenticated endpoint without JWT (non-browser)', async () => {
    try {
      await api.get('/authed');
    } catch (err) {
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint without JWT (browser)', async () => {
    try {
      await api.get('/authed', {
        headers: {
          Accept: 'text/html, */*'
        },
        maxRedirects: 0
      });
    } catch (err) {
      expect(err.response.status).to.equal(302);
      expect(err.response.headers.location).to.equal(
        `${fusionAuthUrl}/oauth2/authorize?client_id=${applicationId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth&response_type=code&state=%2Fauthed`
      );
      return;
    }
    fail('rejection expected');
  });

  it('authenticated endpoint with invalid JWT (non-browser)', async () => {
    try {
      await api.get('/authed', {
        headers: {
          Authorization: 'Bearer xxx'
        }
      });
    } catch (err) {
      expect(err.response.status).to.equal(401);
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion requires code', async () => {
    try {
      await api.get('/oauth');
    } catch (err) {
      expect(err.response.status).to.equal(400);
      expect(err.response.data).to.be.a('object');
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Authorization code required');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid code', async () => {
    try {
      await api.get('/oauth?code=xxx');
    } catch (err) {
      expect(err.response.status).to.equal(400);
      expect(err.response.data).to.be.a('object');
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Invalid Authorization Code');
      return;
    }
    fail('rejection expected');
  });

  it('oauth2/authorize', async () => {
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

  it('oauth completion succeeds with valid code', async () => {
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
    access_token = res.data.access_token;
  });

  it('oauth completion fails with invalid state', async () => {
    try {
      await api.get('/oauth', {
        params: {
          code,
          state: ['is', 'an', 'array']
        }
      });
    } catch (err) {
      expect(err.response.status).to.equal(400);
      expect(err.response.data).to.be.a('object');
      expect(err.response.data.error).to.equal('invalid_request');
      expect(err.response.data.error_description).to.equal('Invalid state value');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion fails with invalid configuration', async () => {
    try {
      await api.get('/oauth-bad-config', {
        params: {
          code
        }
      });
    } catch (err) {
      expect(err.response.status).to.equal(500);
      expect(err.response.data).to.be.a('object');
      expect(err.response.data.error).to.equal('internal_error');
      return;
    }
    fail('rejection expected');
  });

  it('oauth completion redirects to state', async () => {
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
    expect(cookies.access_token).to.be.a('string');
    expect(cookies.Domain).to.equal('app.domain');
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('oauth completion returns refresh token', async () => {
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
    refresh_token = res.data.refresh_token;
  });

  it('oauth completion redirects to state with refresh token', async () => {
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
    expect(cookies.access_token).to.be.a('string');
    expect(cookies.refresh_token).to.be.a('string');
    expect(cookies.Domain).to.equal('app.domain');
    expect(hasHttpOnlyCookies(res)).to.be.true;
    expect(res.headers.location).to.equal('/my-redirect');
  });

  it('authenticated endpoint with Authorization Header Bearer token', async () => {
    const res = await api.get('/authed', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(applicationId);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal('acme.com');
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(applicationId);
    expect(res.data.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with access_token cookie', async () => {
    const res = await api.get('/authed', {
      headers: {
        Cookie: `access_token=${access_token}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(applicationId);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal('acme.com');
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('PASSWORD');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(applicationId);
    expect(res.data.jwt.roles).to.eql(['admin']);
  });

  it('authenticated endpoint without required role', async () => {
    try {
      await api.get('/super', {
        headers: {
          Authorization: `Bearer ${access_token}`
        }
      });
    } catch (err) {
      expect(err.response.status).to.equal(403);
      return;
    }
    fail('rejection expected');
  });

  it('optionally authenticated endpoint without JWT', async () => {
    const res = await api.get('/opt-authed');
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('optionally authenticated endpoint with JWT', async () => {
    const res = await api.get('/opt-authed', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('test@example.com');
  });

  it('optionally authenticated endpoint with invalid JWT', async () => {
    const res = await api.get('/opt-authed', {
      headers: {
        Authorization: 'Bearer xxx'
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('optionally authenticated endpoint with empty JWT', async () => {
    const res = await api.get('/opt-authed', {
      headers: {
        Authorization: 'Bearer'
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('authenticated endpoint with refresh_token cookie', async function () {
    this.timeout(10000);
    await sleep(6000); // JWT timeToLiveInSeconds = 5
    const res = await api.get('/authed', {
      headers: {
        Cookie: `access_token=${access_token}; refresh_token=${refresh_token}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.jwt.aud).to.equal(applicationId);
    expect(res.data.jwt.exp).to.be.a('number');
    expect(res.data.jwt.iat).to.be.a('number');
    expect(res.data.jwt.iss).to.equal('acme.com');
    expect(res.data.jwt.sub).to.be.a('string');
    expect(res.data.jwt.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.jwt.email).to.equal('test@example.com');
    expect(res.data.jwt.email_verified).to.be.true;
    expect(res.data.jwt.applicationId).to.equal(applicationId);
    expect(res.data.jwt.roles).to.eql(['admin']);
    const cookies = getCookies(res);
    expect(cookies.access_token).to.be.a('string');
    expect(cookies.access_token).to.not.equal(access_token);
    expect(cookies.refresh_token).to.be.a('string');
    expect(cookies.Domain).to.equal('app.domain');
    expect(hasHttpOnlyCookies(res)).to.be.true;
    refresh_token = cookies.refresh_token;
  });

  it('authenticated endpoint with invalid refresh_token cookie', async function () {
    try {
      await api.get('/authed', {
        headers: {
          Cookie: `access_token=${access_token}; refresh_token=junk`
        }
      });
    } catch (err) {
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
        Cookie: `access_token=${access_token}; refresh_token=${refresh_token}`
      }
    });
    expect(res.status).to.equal(200);
    expect(res.data.token).to.be.a('string');
    expect(res.data.token).to.not.equal(access_token);
    expect(res.data.refreshToken).to.be.a('string');
    expect(res.data.payload.aud).to.equal(applicationId);
    expect(res.data.payload.exp).to.be.a('number');
    expect(res.data.payload.iat).to.be.a('number');
    expect(res.data.payload.iss).to.equal('acme.com');
    expect(res.data.payload.sub).to.be.a('string');
    expect(res.data.payload.authenticationType).to.equal('REFRESH_TOKEN');
    expect(res.data.payload.email).to.equal('test@example.com');
    expect(res.data.payload.email_verified).to.be.true;
    expect(res.data.payload.applicationId).to.equal(applicationId);
    expect(res.data.payload.roles).to.eql(['admin']);
    refresh_token = res.data.refreshToken;
  });
});

function sleep(ms: number): Promise<void> {
  return new Promise<void>(resolve => {
    setTimeout(() => resolve(), ms);
  });
}
