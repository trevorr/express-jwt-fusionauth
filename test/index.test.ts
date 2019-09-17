import { fail } from 'assert';
import axios from 'axios';
import { expect } from 'chai';
import qs from 'qs';

const applicationId = '31d7b8e8-f67e-4fb0-9c0b-872b793cda7a';
const api = axios.create({ baseURL: 'http://localhost:3000' });

let code: string | null;
let access_token: string;

describe('express-jwt-fusionauth', () => {
  it('health check', async () => {
    const res = await api.get('/');
    expect(res.status).to.equal(200);
  });

  it('authenticated endpoint without JWT (non-browser)', async () => {
    try {
      await api.get('/authed');
      fail('rejection expected');
    } catch (err) {
      expect(err.response.status).to.equal(401);
    }
  });

  it('authenticated endpoint without JWT (browser)', async () => {
    try {
      await api.get('/authed', {
        headers: {
          Accept: 'text/html, */*'
        },
        maxRedirects: 0
      });
      fail('rejection expected');
    } catch (err) {
      expect(err.response.status).to.equal(302);
      expect(err.response.headers.location).to.equal(`http://fusionauth:9011/oauth2/authorize?client_id=${applicationId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth&response_type=code&state=%2Fauthed`);
    }
  });

  it('oauth2/authorize', async () => {
    try {
      await api.post(
        'http://localhost:9011/oauth2/authorize',
        qs.stringify({
          client_id: applicationId,
          redirect_uri: 'http://localhost:3000/oauth',
          response_type: 'code',
          state: '/authed',
          loginId: 'test@example.com',
          password: 'test1234'
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          maxRedirects: 0
        });
      fail('rejection expected');
    } catch (err) {
      expect(err.response.status).to.equal(302);
      const redirect = new URL(err.response.headers.location);
      expect(redirect.host).to.equal('localhost:3000');
      expect(redirect.pathname).to.equal('/oauth');
      expect(redirect.searchParams.get('state')).to.equal('/authed');
      expect(redirect.searchParams.get('userState')).to.equal('Authenticated');
      code = redirect.searchParams.get('code');
      expect(code).to.be.a('string');
    }
  });

  it('oauth2/token', async () => {
    {
      const res = await api.post(
        'http://localhost:9011/oauth2/token',
        qs.stringify({
          client_id: applicationId,
          client_secret: 'VYKsyjndsJ7lTnS2Z5vuz4SM-8Dvy1-4_yvqEoALMfY',
          redirect_uri: 'http://localhost:3000/oauth',
          grant_type: 'authorization_code',
          code
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });
      expect(res.status).to.equal(200);
      expect(res.data.token_type).to.equal('Bearer');
      access_token = res.data.access_token;
      expect(access_token).to.be.a('string');
      expect(res.data.userId).to.be.a('string');
      expect(res.data.expires_in).to.be.a('number');
    }
  });

  it('authenticated endpoint with Authorization Header Bearer token', async () => {
    const res = await api.get(
      '/authed',
      {
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      });
    expect(res.status).to.equal(200);
    expect(res.data.aud).to.equal(applicationId);
    expect(res.data.exp).to.be.a('number');
    expect(res.data.iat).to.be.a('number');
    expect(res.data.iss).to.equal('acme.com');
    expect(res.data.sub).to.be.a('string');
    expect(res.data.authenticationType).to.equal('PASSWORD');
    expect(res.data.email).to.equal('test@example.com');
    expect(res.data.email_verified).to.be.true;
    expect(res.data.applicationId).to.equal(applicationId);
    expect(res.data.roles).to.eql(['admin']);
  });

  it('authenticated endpoint with access_token cookie', async () => {
    const res = await api.get(
      '/authed',
      {
        headers: {
          'Cookie': `access_token=${access_token}`
        }
      });
    expect(res.status).to.equal(200);
    expect(res.data.aud).to.equal(applicationId);
    expect(res.data.exp).to.be.a('number');
    expect(res.data.iat).to.be.a('number');
    expect(res.data.iss).to.equal('acme.com');
    expect(res.data.sub).to.be.a('string');
    expect(res.data.authenticationType).to.equal('PASSWORD');
    expect(res.data.email).to.equal('test@example.com');
    expect(res.data.email_verified).to.be.true;
    expect(res.data.applicationId).to.equal(applicationId);
    expect(res.data.roles).to.eql(['admin']);
  });

  it('optionally authenticated endpoint without JWT', async () => {
    const res = await api.get('/opt-authed');
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('nobody');
  });

  it('optionally authenticated endpoint with JWT', async () => {
    const res = await api.get(
      '/opt-authed',
      {
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      });
    expect(res.status).to.equal(200);
    expect(res.data).to.equal('test@example.com');
  });
});
