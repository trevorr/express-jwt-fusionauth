import axios, { AxiosInstance, AxiosResponse } from 'axios';
import express, { CookieOptions } from 'express';
import createRemoteJWKSet from 'jose/jwks/remote';
import jwtVerify, { JWTPayload, JWTVerifyOptions } from 'jose/jwt/verify';
import { JWTExpired } from 'jose/util/errors';
import qs from 'qs';

const debug = require('debug')('express-jwt-fusionauth');

/**
 * JWT claims as defined by RFC 7519 and FusionAuth.
 *
 * https://tools.ietf.org/html/rfc7519
 * https://fusionauth.io/docs/v1/tech/oauth/tokens/#access-token-claims
 */
export interface JwtClaims extends JWTPayload {
  /** Intended audience of the JWT, which for FusionAuth is the application/client ID. */
  aud: string;
  /** JWT expiration instant in seconds since Unix epoch. */
  exp: number;
  /** JWT issued-at instant in seconds since Unix epoch. */
  iat: number;
  /** Issuer of the JWT, which is defined by the FusionAuth tenant. */
  iss: string;
  /** Subject of the JWT, which is the FusionAuth user ID. */
  sub: string;
  /** The unique identifier for this JWT. */
  jti?: string;

  /** Authentication method used to create the JWT, such as "PASSWORD". */
  authenticationType: string;
  /** The email address of the user represented by the JWT. */
  email?: string;
  /** Indicates whether the user's email address has been verified. */
  email_verified?: boolean;
  /** Preferred username associated with the application, if any. */
  preferred_username?: string;
  /** Application/client ID associated with this JWT, if the user is registered for it. */
  applicationId?: string;
  /** Roles assigned to the user by the application, if the user is registered for it. */
  roles?: string[];
}

declare module 'express' {
  export interface Request {
    /** Claims of the JWT authenticating the request, if present and validated. */
    jwt?: JwtClaims;
  }
}

/** Configuration for setting access and refresh token cookies. */
export interface CookieConfig {
  /** Domain to associate with token cookies. */
  domain?: string;
  /** Whether to require token cookies only be sent in network requests and not be made available to scripts. Defaults to true. */
  httpOnly?: boolean;
  /** Whether to require token cookies only be sent over a secure connection. Defaults to whether `NODE_ENV` is `production`. */
  secure?: boolean;
}

/** Configuration for OAuth 2.0 (RFC 6749) authentication flow. */
export interface OAuthConfig {
  /** Application/client ID attempting to authenticate the user. */
  clientId: string;
  /** Application/client secret, which may or may not be required by the application. */
  clientSecret?: string;
  /** URI of the endpoint that will exchange an authorization code for a JWT. */
  redirectUri: string;
  /** Cookie configuration used for setting access and refresh token cookies after OAuth completion. */
  cookieConfig?: CookieConfig;
}

/** Options controlling how to obtain and verify a JWT. */
export interface JwtOptions {
  /** JWT verification options passed to `jose` `jwtVerify`. */
  verifyOptions?: JWTVerifyOptions;
  /** Indicates whether a JWT is required or the route is optionally authenticated. */
  required?: boolean;
  /** Whether to always redirect to the OAuth login URL if a JWT is required but not present or valid. */
  alwaysLogin?: boolean;
  /** Whether to redirect to the OAuth login URL if a JWT is required but not present or valid and the client seems to be a web browser. */
  browserLogin?: boolean;
  /** OAuth configuration used when redirecting to the OAuth login URL. */
  oauthConfig?: OAuthConfig;
  /** Cookie configuration used for setting access token cookie after refresh. Uses OAuth cookie configuration by default. */
  cookieConfig?: CookieConfig;
}

/** @ignore */
const defaultCookieConfig: CookieConfig = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production'
};

/** @ignore */
const defaultJwtOptions: JwtOptions = {
  required: true,
  alwaysLogin: false,
  browserLogin: true
};

interface TokenResponse {
  access_token: string;
  expires_in: number;
  id_token: string;
  refresh_token: string;
  token_type: string;
  userId: string;
}

interface RefreshResponse {
  token: string;
}

type JWKS = ReturnType<typeof createRemoteJWKSet>;

/** Provides factory methods for Express middleware/handlers used to obtain and validate JSON Web Tokens (JWTs). */
export class ExpressJwtFusionAuth {
  private readonly fusionAuth: AxiosInstance;
  private jwks: JWKS | undefined;

  /**
   * Creates a middleware factory that communicates with FusionAuth at the given URL.
   * @param {string} fusionAuthUrl the base URL of the FusionAuth application (e.g. `http://fusionauth:9011`)
   */
  public constructor(private readonly fusionAuthUrl: string) {
    this.fusionAuth = axios.create({
      baseURL: fusionAuthUrl
    });
  }

  protected getJWKS(): JWKS {
    if (!this.jwks) {
      this.jwks = createRemoteJWKSet(new URL(`${this.fusionAuthUrl}/.well-known/jwks.json`));
    }
    return this.jwks;
  }

  /**
   * Returns a middleware/handler that checks whether a request has a JWT attached,
   * validates the JWT, and associates the JWT contents with the request object.
   * By default, if the client appears to be a web browser, it will be redirected
   * to the FusionAuth OAuth 2.0 login URL. However, this behavior can be enabled
   * or disabled for all clients.
   * @param {JwtOptions} options the JWT acquisition and verification options
   */
  public jwt(options: JwtOptions): express.RequestHandler {
    const effectiveOptions = Object.assign({}, defaultJwtOptions, options);
    return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
      let token;
      let tokenSource;
      const { headers = {}, cookies = {} } = req;
      if (headers.authorization) {
        const [scheme, credentials] = headers.authorization.split(' ');
        if (credentials && /^Bearer$/i.test(scheme)) {
          token = credentials;
          tokenSource = 'Authorization header Bearer token';
        }
      } else if (cookies.access_token) {
        token = cookies.access_token;
        tokenSource = 'access_token cookie';
      }
      if (token) {
        try {
          const keyStore = this.getJWKS();
          try {
            let jwtPayload;
            try {
              jwtPayload = (await jwtVerify(token, keyStore, effectiveOptions.verifyOptions)).payload;
            } catch (err) {
              if (err instanceof JWTExpired && cookies.refresh_token) {
                try {
                  token = await this.refreshJwt(cookies.refresh_token);
                } catch {
                  throw err;
                }

                tokenSource = 'refresh_token cookie';
                jwtPayload = (await jwtVerify(token, keyStore, effectiveOptions.verifyOptions)).payload;

                const cookieOptions: CookieOptions = {
                  domain: req.hostname,
                  ...defaultCookieConfig,
                  ...options.oauthConfig?.cookieConfig,
                  ...options.cookieConfig
                };
                res.cookie('access_token', token, cookieOptions);
              } else {
                throw err;
              }
            }
            const jwt = jwtPayload as JwtClaims;
            req.jwt = jwt;
            debug(`Found valid JWT using ${tokenSource} for ${jwt.email || jwt.preferred_username || jwt.sub}`);
            return next();
          } catch (err) {
            debug(`Invalid JWT provided by ${tokenSource}: ${err.message}`);
          }
        } catch (err) {
          /* istanbul ignore next */
          debug(`Error fetching keys to verify JWT: ${err.message}`);
        }
      } else {
        debug('No JWT provided in Authorization header or access_token cookie');
      }
      if (effectiveOptions.required) {
        if (
          (effectiveOptions.alwaysLogin ||
            (effectiveOptions.browserLogin && headers.accept && /^text\/html,/i.test(headers.accept))) &&
          effectiveOptions.oauthConfig
        ) {
          const params = {
            client_id: effectiveOptions.oauthConfig.clientId,
            redirect_uri: effectiveOptions.oauthConfig.redirectUri,
            response_type: 'code',
            state: req.originalUrl
          };
          const url = `${this.fusionAuthUrl}/oauth2/authorize?${qs.stringify(params)}`;
          debug(`Redirecting to OAuth login: ${url}`);
          res.redirect(url);
        } else {
          debug('Failing unauthenticated request');
          res.setHeader('WWW-Authenticate', 'Bearer');
          this.fail(res, 401, 'Authorization required');
        }
      } else {
        debug('Proceeding with unauthenticated request');
        next();
      }
    };
  }

  private async refreshJwt(refreshToken: string): Promise<string> {
    try {
      const res = await this.fusionAuth.post<RefreshResponse>('/api/jwt/refresh', { refreshToken });
      return res.data.token;
    } catch (err) {
      let { message } = err;
      if (err.response) {
        const res = err.response as AxiosResponse;
        message = `HTTP ${res.status}: ${JSON.stringify(res.data)}`;
      }
      debug(`Failed to refresh token: ${message}`);
      throw err;
    }
  }

  /**
   * Returns a middleware/handler that checks whether a request has a valid JWT
   * attached that has at least one of the given application roles.
   * The request must have already had the JWT parsed and validated by the
   * `ExpressJwtFusionAuth.jwt` middleware. If the JWT is not present or does
   * not have one of the required roles, the request is failed with HTTP 403 Forbidden.
   * @param {string} roleOrRoles the role or roles to check for
   */
  public jwtRole(roleOrRoles: string | string[]): express.RequestHandler {
    const requiredRoles = Array.isArray(roleOrRoles) ? roleOrRoles : [roleOrRoles];
    return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
      const { jwt } = req;
      if (jwt && Array.isArray(jwt.roles)) {
        const jwtRoles = jwt.roles;
        if (requiredRoles.some(role => jwtRoles.includes(role))) {
          next();
          return;
        }
      }
      debug(`Failing request without JWT role(s): ${requiredRoles.join(', ')}`);
      this.fail(res, 403, 'Not authorized');
    };
  }

  /**
   * Returns a handler for the OAuth 2.0 redirection endpoint that exchanges an
   * authorization code for a JWT/access token and optional refresh token.
   * @param {OAuthConfig} config the OAuth 2.0 configuration settings
   */
  public oauthCompletion(config: OAuthConfig): express.RequestHandler {
    return async (req: express.Request, res: express.Response): Promise<void> => {
      const {
        query: { code, state }
      } = req;
      if (!code) {
        this.fail(res, 400, 'Authorization code required');
        return;
      }
      try {
        const tokenRes = await this.fusionAuth.post('/oauth2/token', null, {
          params: {
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code,
            grant_type: 'authorization_code',
            redirect_uri: config.redirectUri
          }
        });
        const data = tokenRes.data as TokenResponse;
        const cookieOptions: CookieOptions = {
          domain: req.hostname,
          ...defaultCookieConfig,
          ...config.cookieConfig
        };
        res.cookie('access_token', data.access_token, cookieOptions);
        if (data.refresh_token) {
          res.cookie('refresh_token', data.refresh_token, cookieOptions);
        }
        if (state) {
          res.redirect(state as string);
        } else {
          res.sendStatus(204);
        }
      } catch (err) {
        debug(`Failed to exchange authorization code for token: ${err.message}`);
        this.fail(res, err.response ? err.response.status : 500, 'Failed to exchange authorization code for token');
      }
    };
  }

  protected fail(res: express.Response, statusCode: number, message: string): void {
    res.status(statusCode).send(message);
  }
}
