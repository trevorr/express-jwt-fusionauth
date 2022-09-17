import axios, { AxiosInstance } from 'axios';
import { asError } from 'catch-unknown';
import express, { CookieOptions } from 'express';
import * as jose from 'jose';
import qs from 'qs';
import { getDefaultLogger, Logger } from './logger';

/**
 * JWT claims as defined by RFC 7519 and FusionAuth.
 *
 * https://tools.ietf.org/html/rfc7519
 * https://fusionauth.io/docs/v1/tech/oauth/tokens/#access-token-claims
 */
export interface JwtClaims extends jose.JWTPayload {
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
export interface CookieConfig extends CookieOptions {
  /** Disables the use of cookies for authentication. Recommended for cross-site use cases to avoid CSRF attacks. */
  disabled?: boolean;
  /** Whether to require token cookies only be sent in network requests and not be made available to scripts. Defaults to true. */
  httpOnly?: boolean;
  /** Whether to require token cookies only be sent over a secure connection. Defaults to whether `NODE_ENV` is `production`. */
  secure?: boolean;
}

/** Context provided to an application JWT verification function. */
export interface JwtVerifierContext {
  /** The JWT options provided to the middleware. */
  options: JwtOptions;
  /** The Express request that provided the JWT being verified. */
  request: express.Request;
  /** The Express response associated with the request of the JWT being verified. */
  response: express.Response;
}

/**
 * Verification function for application-issued JWT tokens.
 * Returns the JWT claims if the token represents a valid application JWT or false if the JWT is
 * not an application JWT, indicating the token should be verified using the FusionAuth key set
 * and configured verification options. If the token is an invalid application JWT, an exception
 * (such as `jose` `JWTInvalid` or `JWTExpired`) should be thrown. If `jose` `JWTExpired` is thrown,
 * cookies are enabled, and a refresh token is provided, an automatic refresh will be attempted.
 * @param {string} token the JWT token to verify
 * @param {JwtVerifierContext} context the verification context, including options, request, and response
 */
export type JwtVerifier = (token: string, context: JwtVerifierContext) => Promise<JwtClaims | false>;

/** A JWT token and its corresponding payload. */
export interface JwtTokenAndPayload {
  /** A verified JWT token. */
  token: string;
  /** The decoded claims contained in the JWT. */
  payload: JwtClaims;
}

/** Context provided to an application JWT transform function. */
export interface JwtTransformContext {
  /** The JWT options provided to the middleware. */
  options?: JwtOptions;
  /** The Express request that provided the JWT being transformed. */
  request?: express.Request;
  /** The Express response associated with the request of the JWT being transformed. */
  response?: express.Response;
}

/**
 * JWT transform function allowing an application to replace the FusionAuth JWT with its own.
 * @param {JwtTokenAndPayload} jwt the verified FusionAuth JWT token and payload
 * @param {JwtVerifierContext} context the transform context, optionally including options, request, and response
 */
export type JwtTransform = (jwt: JwtTokenAndPayload, context: JwtTransformContext) => Promise<JwtTokenAndPayload>;

/** Configuration for OAuth 2.0 (RFC 6749) authentication flow. */
export interface OAuthConfig {
  /** Application/client ID attempting to authenticate the user. */
  clientId: string;
  /** Application/client secret, which may or may not be required by the application. */
  clientSecret?: string;
  /** URI of the endpoint that will exchange an authorization code for a JWT. */
  redirectUri: string;
  /**
   * How to pass tokens during redirect: as cookies or URL query parameters.
   * Defaults to 'auto', which uses cookies if enabled and if state does not contain a `token_transport`
   * query parameter with the value 'query', otherwise uses query parameters.
   */
  tokenTransport?: 'auto' | 'cookie' | 'query';
  /** Cookie configuration used for setting access and refresh token cookies after OAuth completion. */
  cookieConfig?: CookieConfig;
  /** JWT transform function allowing an application to replace the FusionAuth JWT with its own after OAuth completion. */
  jwtTransform?: JwtTransform;
  /** Log message output interface. */
  logger?: Logger;
}

/** Options controlling how to obtain and verify a JWT. */
export interface JwtOptions {
  /** JWT verification options passed to `jose` `jwtVerify`. */
  verifyOptions?: jose.JWTVerifyOptions;
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
  /** JWT transform function allowing an application to replace the FusionAuth JWT with its own. Uses OAuth JWT transform by default. */
  jwtTransform?: JwtTransform;
  /** JWT verification function for application-issued tokens. */
  jwtVerifier?: JwtVerifier;
  /** Log message output interface. */
  logger?: Logger;
}

export interface RefreshJwtResult {
  token: string;
  refreshToken: string;
  payload: JwtClaims;
}

/** @ignore */
const defaultCookieConfig: CookieConfig = {
  disabled: false,
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production'
};

/** @ignore */
const defaultJwtOptions: JwtOptions = {
  required: true,
  alwaysLogin: false,
  browserLogin: true
};

export interface OAuthTokenResponse {
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token: string;
  token_type: string;
  userId: string;
}
export interface OAuthErrorResponse {
  error?: string;
  error_description?: string;
}

interface RefreshResponse {
  token: string;
  refreshToken: string;
}

type JWKS = ReturnType<typeof jose.createRemoteJWKSet>;

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

  private getJWKS(): JWKS {
    if (!this.jwks) {
      this.jwks = jose.createRemoteJWKSet(new URL(`${this.fusionAuthUrl}/.well-known/jwks.json`));
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
    const effectiveOptions = { ...defaultJwtOptions, ...options };
    /* istanbul ignore next */
    const { disabled: cookiesDisabled, ...cookieOptions } = {
      ...defaultCookieConfig,
      ...options.oauthConfig?.cookieConfig,
      ...options.cookieConfig
    };
    return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
      const { logger = getDefaultLogger() } = options;

      let token: string | undefined;
      let tokenSource: string | undefined;
      /* istanbul ignore next */
      const { headers = {}, cookies = {} } = req;
      if (headers.authorization) {
        const [scheme, credentials] = headers.authorization.split(' ');
        if (credentials && /^Bearer$/i.test(scheme)) {
          token = credentials;
          tokenSource = 'Authorization header Bearer token';
        }
      } else if (!cookiesDisabled && cookies.access_token) {
        token = cookies.access_token;
        tokenSource = 'access_token cookie';
      }
      if (token) {
        try {
          const keyStore = this.getJWKS();
          try {
            let payload: JwtClaims | false | undefined;
            try {
              if (effectiveOptions.jwtVerifier) {
                payload = await effectiveOptions.jwtVerifier(token, {
                  options: effectiveOptions,
                  request: req,
                  response: res
                });
              }
              if (!payload) {
                payload = (await jose.jwtVerify(token, keyStore, effectiveOptions.verifyOptions)).payload as JwtClaims;
              }
            } catch (err) {
              if (err instanceof jose.errors.JWTExpired && !cookiesDisabled && cookies.refresh_token) {
                let refresh;
                try {
                  refresh = await this.postRefresh(logger, cookies.refresh_token, token);
                } catch {
                  // rethrow original error if refresh fails
                  throw err;
                }

                token = refresh.token;
                tokenSource = 'refresh_token cookie';
                payload = (await jose.jwtVerify(token, keyStore, effectiveOptions.verifyOptions)).payload as JwtClaims;

                /* istanbul ignore next */
                const jwtTransform = effectiveOptions.jwtTransform || effectiveOptions.oauthConfig?.jwtTransform;
                if (jwtTransform) {
                  ({ token, payload } = await jwtTransform(
                    { token, payload },
                    {
                      options: effectiveOptions,
                      request: req,
                      response: res
                    }
                  ));
                }

                res.cookie('access_token', token, cookieOptions);
                // refresh token will be updated if refreshTokenUsagePolicy is OneTimeUse
                res.cookie('refresh_token', refresh.refreshToken, cookieOptions);
              } else {
                throw err;
              }
            }
            req.jwt = payload;
            logger.debug(`Found valid JWT using ${tokenSource} for ${payload.sub}`);
            return next();
          } catch (err) {
            logger.debug(`Invalid JWT provided by ${tokenSource}: ${asError(err).message}`);
          }
        } catch (err) {
          /* istanbul ignore next */
          logger.error(`Error fetching keys to verify JWT: ${asError(err).message}`);
        }
      } else {
        logger.debug('No JWT provided in Authorization header or access_token cookie');
      }
      if (effectiveOptions.required || !!token) {
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
          logger.debug(`Redirecting to OAuth login: ${url}`);
          res.redirect(url);
        } else {
          logger.debug('Failing unauthenticated request');
          res.setHeader('WWW-Authenticate', 'Bearer');
          res.status(401).send('Authorization required');
        }
      } else {
        logger.verbose('Proceeding with unauthenticated request');
        next();
      }
    };
  }

  /**
   * Requests and parses/validates a new JWT/access token using a refresh token
   * obtained from a prior OAuth login or JWT refresh.
   * Note that the middleware/handler returned by `jwt()` will do this automatically
   * for an expired access token if a refresh token is available.
   * This function is provided for cases where an application needs to refresh explicitly,
   * such as when exchanging a FusionAuth JWT for an application-generated JWT.
   * @param refreshToken the refresh token from the prior login or refresh
   * @param oldToken the original, expired access token (for JWT Refresh webhook event)
   * @param context the refresh context, optionally containing JWT transform options and Express request/response
   */
  public async refreshJwt(
    refreshToken: string,
    oldToken?: string,
    context?: JwtTransformContext
  ): Promise<RefreshJwtResult> {
    const logger = context?.options?.logger ?? getDefaultLogger();
    const refresh = await this.postRefresh(logger, refreshToken, oldToken);
    let token = refresh.token;
    let payload = this.decodeTrustedJwt(token);

    if (context?.options) {
      /* istanbul ignore next */
      const jwtTransform = context.options.jwtTransform || context.options.oauthConfig?.jwtTransform;
      /* istanbul ignore else */
      if (jwtTransform) {
        ({ token, payload } = await jwtTransform({ token, payload }, context));
      }
    }

    return { token, refreshToken: refresh.refreshToken, payload };
  }

  private async postRefresh(logger: Logger, refreshToken: string, token?: string): Promise<RefreshResponse> {
    try {
      const res = await this.fusionAuth.post<RefreshResponse>('/api/jwt/refresh', { refreshToken, token });
      return res.data;
    } catch (err) {
      let message;
      /* istanbul ignore else */
      if (axios.isAxiosError(err) && err.response) {
        const { response } = err;
        message = `HTTP ${response.status}: ${JSON.stringify(response.data)}`;
      } else {
        ({ message } = asError(err));
      }
      logger.debug(`Failed to refresh token: ${message}`);
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
  public jwtRole(roleOrRoles: string | string[], options: JwtOptions = defaultJwtOptions): express.RequestHandler {
    const requiredRoles = Array.isArray(roleOrRoles) ? roleOrRoles : [roleOrRoles];
    return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
      const { logger = getDefaultLogger() } = options;
      const { jwt } = req;
      /* istanbul ignore else */
      if (jwt && Array.isArray(jwt.roles)) {
        const jwtRoles = jwt.roles;
        if (requiredRoles.some(role => jwtRoles.includes(role))) {
          next();
          return;
        }
      }
      logger.debug(`Failing request without JWT role(s): ${requiredRoles.join(', ')}`);
      res.status(403).send('Not authorized');
    };
  }

  /**
   * Returns a handler for the OAuth 2.0 redirection endpoint that exchanges an
   * authorization code for a JWT/access token and optional refresh token.
   * @param {OAuthConfig} config the OAuth 2.0 configuration settings
   */
  public oauthCompletion(config: OAuthConfig): express.RequestHandler {
    const { disabled: cookiesDisabled, ...cookieOptions } = { ...defaultCookieConfig, ...config.cookieConfig };
    return async (req: express.Request, res: express.Response): Promise<void> => {
      const { logger = getDefaultLogger() } = config;

      let code, state;
      if (req.method === 'GET') {
        ({ code, state } = req.query);
      } else {
        /* istanbul ignore else */
        if (req.body && typeof req.body === 'object') {
          ({ code, state } = req.body);
        }
      }

      if (typeof code !== 'string') {
        this.oauthError(res, 'invalid_request', 'Authorization code required');
        return;
      }

      let { tokenTransport = 'auto' } = config;
      let stateParams: URLSearchParams | undefined;
      let baseState: string | undefined;
      let paramsChanged = false;
      if (state) {
        if (typeof state !== 'string') {
          this.oauthError(res, 'invalid_request', 'Invalid state value');
          return;
        }

        const paramsStart = state.indexOf('?');
        stateParams = new URLSearchParams(paramsStart >= 0 ? state.substring(paramsStart + 1) : undefined);
        baseState = paramsStart >= 0 ? state.substring(0, paramsStart) : state;

        const tokenParam = stateParams.get('token_transport');
        if (tokenParam) {
          stateParams.delete('token_transport');
          paramsChanged = true;
        }

        if (tokenTransport === 'auto') {
          if (cookiesDisabled || tokenParam === 'query') {
            tokenTransport = 'query';
          } else {
            tokenTransport = 'cookie';
          }
        } else if (cookiesDisabled && tokenTransport === 'cookie') {
          this.oauthError(res, 'invalid_request', 'Cannot specify redirect state with cookies disabled');
          return;
        }
      }

      logger.verbose(`Exchanging OAuth code "${code}" for token`);

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
        const data = tokenRes.data as OAuthTokenResponse;

        let jwtSource;
        if (config.jwtTransform) {
          let token = data.access_token;
          let payload = this.decodeTrustedJwt(token);
          ({ token, payload } = await config.jwtTransform(
            { token, payload },
            {
              options: { oauthConfig: config },
              request: req,
              response: res
            }
          ));
          data.access_token = token;
          jwtSource = 'application';
        } else {
          jwtSource = 'FusionAuth';
        }

        let jwtVia;
        if (stateParams && typeof state === 'string') {
          switch (tokenTransport) {
            case 'cookie':
              res.cookie('access_token', data.access_token, cookieOptions);
              if (data.refresh_token) {
                res.cookie('refresh_token', data.refresh_token, cookieOptions);
              }
              break;
            case 'query':
              stateParams.set('access_token', data.access_token);
              if (data.refresh_token) {
                stateParams.set('refresh_token', data.refresh_token);
              }
              paramsChanged = true;
              break;
          }
          if (paramsChanged) {
            state = stateParams.entries().next().done ? baseState! : `${baseState}?${stateParams}`;
          }
          res.redirect(state);
          jwtVia = `${tokenTransport} redirect`;
        } else {
          res.header('Cache-Control', 'no-store').header('Pragma', 'no-cache').send(data);
          jwtVia = 'response body';
        }

        logger.verbose(
          `Completed OAuth with ${jwtSource} JWT${data.refresh_token ? ' and refresh token' : ''} via ${jwtVia}`
        );
      } catch (err) {
        if (axios.isAxiosError(err) && err.response && isOAuthErrorResponse(err.response.data)) {
          /* istanbul ignore next */
          const { error = 'unknown_error', error_description } = err.response.data;
          const message = error_description || /* istanbul ignore next */ error;
          logger.debug(`Failed to exchange authorization code for token: ${message}`);
          this.oauthError(res, error, error_description, err.response.status);
        } else {
          logger.debug(`Failed to exchange authorization code for token: ${asError(err).message}`);
          this.oauthError(res, 'internal_error', 'Failed to exchange authorization code for token', 500);
        }
      }
    };
  }

  private decodeTrustedJwt(token: string): JwtClaims {
    // https://github.com/panva/jose/discussions/106#discussioncomment-210262
    const utf8Decoder = new TextDecoder();
    return JSON.parse(utf8Decoder.decode(jose.base64url.decode(token.split('.')[1])));
  }

  private oauthError(res: express.Response, code: string, description?: string, statusCode = 400): void {
    res.header('Cache-Control', 'no-store').header('Pragma', 'no-cache').status(statusCode).send({
      error: code,
      error_description: description
    });
  }
}

export function isOAuthErrorResponse(v: unknown): v is OAuthErrorResponse {
  return (
    isRecord(v) &&
    (!('error' in v) || typeof v.error === 'string') &&
    (!('error_description' in v) || typeof v.error_description === 'string')
  );
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v != null;
}
