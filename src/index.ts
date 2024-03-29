import { asError } from 'catch-unknown';
import express, { CookieOptions } from 'express';
import got, { ExtendOptions, Got, HTTPError } from 'got';
import * as jose from 'jose';
import qs from 'qs';
import { parse as parseCookies } from 'set-cookie-parser';
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
  /** Disables the use of cookies for authentication. Recommended unless CSRF mitigation is used. */
  disabled?: boolean;
  /** Whether to require token cookies only be sent in network requests and not be made available to scripts. Defaults to true. */
  httpOnly?: boolean;
  /** Whether to require token cookies only be sent over a secure connection. Defaults to whether `NODE_ENV` is `production`. */
  secure?: boolean;
}

/** Configuration for setting a specific cookie. */
export interface NamedCookieConfig extends CookieConfig {
  /** The name of the cookie. Defaults to `access_token` or `refresh_token`. */
  name?: string;
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
  /** Default cookie configuration used for setting access and refresh token cookies after OAuth completion. */
  cookieConfig?: CookieConfig;
  /** Cookie configuration used for setting the access token cookie after OAuth completion. */
  accessTokenCookieConfig?: NamedCookieConfig;
  /** Cookie configuration used for setting the refresh token cookie after OAuth completion. */
  refreshTokenCookieConfig?: NamedCookieConfig;
  /** Query parameter used for setting the access token cookie after OAuth completion. Defaults to "access_token". */
  accessTokenQueryParam?: string;
  /** Query parameter used for setting the refresh token cookie after OAuth completion. Defaults to "refresh_token". */
  refreshTokenQueryParam?: string;
  /** JWT transform function allowing an application to replace the FusionAuth JWT with its own after OAuth completion. */
  jwtTransform?: JwtTransform;
  /** Log message output interface. */
  logger?: Logger;
}

/** Configuration for how access and refresh tokens are exchanged via headers. */
export interface TokenHeaderConfig {
  /** Request header used to provide a refresh token used for automatic refresh. */
  refreshTokenHeader?: string;
  /** Response header used to provide an updated access token after automatic refresh. */
  refreshedAccessTokenHeader?: string;
  /** Response header used to provide an updated refresh token after automatic refresh. */
  refreshedRefreshTokenHeader?: string;
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
  /** Default cookie configuration used for setting access and refresh token cookies after refresh. Uses OAuth cookie configuration by default. */
  cookieConfig?: CookieConfig;
  /** Cookie configuration used for setting the access token cookie after refresh. */
  accessTokenCookieConfig?: NamedCookieConfig;
  /** Cookie configuration used for setting the refresh token cookie after refresh. */
  refreshTokenCookieConfig?: NamedCookieConfig;
  /** Request/response header configuration. */
  headerConfig?: TokenHeaderConfig;
  /** JWT transform function allowing an application to replace the FusionAuth JWT with its own. Uses OAuth JWT transform by default. */
  jwtTransform?: JwtTransform;
  /** JWT verification function for application-issued tokens. */
  jwtVerifier?: JwtVerifier;
  /** Log message output interface. */
  logger?: Logger;
}

/** @ignore */
const defaultAccessTokenCookieConfig: NamedCookieConfig & { name: string } = {
  name: 'access_token',
  disabled: false,
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production'
};

/** @ignore */
const defaultRefreshTokenCookieConfig: NamedCookieConfig & { name: string } = {
  name: 'refresh_token',
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
  /** The encoded access token. */
  token: string;
  /** The refresh token. */
  refreshToken: string;
  /**
   * Persistent identifier for this refresh token, which will not change even when using one-time use refresh tokens.
   * Available since FusionAuth 1.37.0.
   */
  refreshTokenId?: string;
}

interface RefreshResponseWithExpiration extends RefreshResponse {
  /**
   * Expiration date for the refresh token (obtained from the `refresh_token` cookie).
   */
  refreshTokenExpires?: Date;
}

export interface RefreshJwtResult extends RefreshResponseWithExpiration {
  payload: JwtClaims;
}

type JWKS = ReturnType<typeof jose.createRemoteJWKSet>;

/** Provides factory methods for Express middleware/handlers used to obtain and validate JSON Web Tokens (JWTs). */
export class ExpressJwtFusionAuth {
  private readonly fusionAuth: Got;
  private jwks: JWKS | undefined;

  /**
   * Creates a middleware factory that communicates with FusionAuth at the given URL.
   * @param {string} fusionAuthUrl the base URL of the FusionAuth application (e.g. `http://fusionauth:9011`)
   */
  public constructor(private readonly fusionAuthUrl: string, instanceOrOptions?: Got | ExtendOptions) {
    this.fusionAuth =
      typeof instanceOrOptions === 'function'
        ? instanceOrOptions
        : got.extend({
            prefixUrl: fusionAuthUrl,
            ...instanceOrOptions
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
    const accessTokenCookieConfig = {
      ...defaultAccessTokenCookieConfig,
      ...options.oauthConfig?.cookieConfig,
      ...options.oauthConfig?.accessTokenCookieConfig,
      ...options.cookieConfig,
      ...options.accessTokenCookieConfig
    };
    /* istanbul ignore next */
    const refreshTokenCookieConfig = {
      ...defaultRefreshTokenCookieConfig,
      ...options.oauthConfig?.cookieConfig,
      ...options.oauthConfig?.refreshTokenCookieConfig,
      ...options.cookieConfig,
      ...options.refreshTokenCookieConfig
    };
    const { name: accessTokenCookieName, disabled: accessTokenCookieDisabled } = accessTokenCookieConfig;
    const { name: refreshTokenCookieName, disabled: refreshTokenCookieDisabled } = refreshTokenCookieConfig;
    return async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
      const { logger = getDefaultLogger() } = options;
      const logContext = getLogContext(req);

      let token: string | undefined;
      let tokenSource: string | undefined;
      let tokenFromHeader = false;
      /* istanbul ignore next */
      const { headers = {}, cookies = {} } = req;
      if (headers.authorization) {
        const [scheme, credentials] = headers.authorization.split(' ');
        if (credentials && /^Bearer$/i.test(scheme)) {
          token = credentials;
          tokenSource = 'Authorization header Bearer token';
          tokenFromHeader = true;
        }
      } else if (!accessTokenCookieDisabled && cookies[accessTokenCookieName]) {
        token = cookies[accessTokenCookieName];
        tokenSource = `${accessTokenCookieName} cookie`;
      }

      let refreshToken: string | undefined;
      let refreshTokenSource: string | undefined;
      let refreshTokenFromHeader = false;
      if (effectiveOptions.headerConfig?.refreshTokenHeader) {
        const headerName = effectiveOptions.headerConfig.refreshTokenHeader;
        const headerValue = headers[headerName];
        if (typeof headerValue === 'string') {
          refreshToken = headerValue;
          refreshTokenSource = `${headerName} header`;
          refreshTokenFromHeader = true;
        }
      }
      if (!refreshToken && !refreshTokenCookieDisabled && cookies[refreshTokenCookieName]) {
        refreshToken = cookies[refreshTokenCookieName];
        refreshTokenSource = `${refreshTokenCookieName} cookie`;
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
              if (!(err instanceof jose.errors.JWTExpired) || !refreshToken) {
                throw err;
              }

              // refresh expired JWT automatically if we have a refresh token from a header, or from a cookie
              // and the HTTP method is safe (to avoid CSRF), and we have a way to return the new tokens
              if (!refreshTokenFromHeader && !isSafeMethod(req.method)) {
                logger.debug(`Cannot auto-refresh from cookie with unsafe method ${req.method}`, logContext);
                throw err;
              }

              const refreshedAccessTokenHeader = effectiveOptions.headerConfig?.refreshedAccessTokenHeader;
              const refreshedRefreshTokenHeader = effectiveOptions.headerConfig?.refreshedRefreshTokenHeader;
              if (
                (!refreshedAccessTokenHeader && accessTokenCookieDisabled) ||
                (!refreshedRefreshTokenHeader && refreshTokenCookieDisabled)
              ) {
                logger.debug('Cannot auto-refresh without cookie or header to return new tokens', logContext);
                throw err;
              }

              let refreshResponse;
              try {
                refreshResponse = await this.postRefresh(logger, logContext, refreshToken, token);
              } catch (refreshErr) {
                logger.debug(`Failed to auto-refresh: ${asError(refreshErr).message}`, logContext);
                // rethrow original error if refresh fails
                throw err;
              }

              token = refreshResponse.token;
              tokenSource = refreshTokenSource;
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

              if (refreshedAccessTokenHeader && tokenFromHeader) {
                res.setHeader(refreshedAccessTokenHeader, token);
              } else {
                /* istanbul ignore else */
                if (!accessTokenCookieDisabled) {
                  res.cookie(accessTokenCookieName, token, accessTokenCookieConfig);
                }
              }

              // refresh token will be updated if refreshTokenUsagePolicy is OneTimeUse
              if (refreshResponse.refreshToken !== refreshToken) {
                if (refreshedRefreshTokenHeader && refreshTokenFromHeader) {
                  res.setHeader(refreshedRefreshTokenHeader, refreshResponse.refreshToken);
                } else {
                  /* istanbul ignore else */
                  if (!refreshTokenCookieDisabled) {
                    res.cookie(refreshTokenCookieName, refreshResponse.refreshToken, {
                      expires: refreshResponse.refreshTokenExpires,
                      ...refreshTokenCookieConfig
                    });
                  }
                }
              }
            }
            req.jwt = payload;
            logger.debug(`Found valid JWT using ${tokenSource} for ${payload.sub}`, logContext);
            return next();
          } catch (err) {
            logger.debug(`Invalid JWT provided by ${tokenSource}: ${asError(err).message}`, logContext);
          }
        } catch (err) {
          /* istanbul ignore next */
          logger.error(`Error fetching keys to verify JWT: ${asError(err).message}`, logContext);
        }
      } else {
        let message = 'No JWT provided in Authorization header';
        if (!accessTokenCookieDisabled) {
          message += ` or ${accessTokenCookieName} cookie`;
        }
        logger.debug(message, logContext);
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
          logger.debug(`Redirecting to OAuth login: ${url}`, logContext);
          res.redirect(url);
        } else {
          logger.debug('Failing unauthenticated request', logContext);
          res.setHeader('WWW-Authenticate', 'Bearer');
          res.status(401).send('Authorization required');
        }
      } else {
        logger.verbose('Proceeding with unauthenticated request', logContext);
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
    const options = context?.options;
    const logger = options?.logger ?? getDefaultLogger();
    /* istanbul ignore else */
    const logContext = context?.request ? getLogContext(context.request) : {};
    const refresh = await this.postRefresh(logger, logContext, refreshToken, oldToken);
    const { token } = refresh;
    const payload = this.decodeTrustedJwt(token);
    const result = { ...refresh, payload };

    if (options) {
      /* istanbul ignore next */
      const jwtTransform = options.jwtTransform || options.oauthConfig?.jwtTransform;
      /* istanbul ignore else */
      if (jwtTransform) {
        Object.assign(result, await jwtTransform({ token, payload }, context));
      }
    }

    return result;
  }

  private async postRefresh(
    logger: Logger,
    logContext: object,
    refreshToken: string,
    token?: string
  ): Promise<RefreshResponseWithExpiration> {
    try {
      const res = await this.fusionAuth.post<RefreshResponse>('api/jwt/refresh', {
        json: { refreshToken, token },
        responseType: 'json'
      });

      const body: RefreshResponseWithExpiration = res.body;

      const cookieMap = parseCookies(res, { map: true });
      const refreshTokenCookie = cookieMap.refresh_token;
      /* istanbul ignore next */
      if (refreshTokenCookie?.expires) {
        body.refreshTokenExpires = refreshTokenCookie.expires;
      } else if (refreshTokenCookie?.maxAge) {
        body.refreshTokenExpires = new Date(Date.now() + refreshTokenCookie.maxAge * 1000);
      }

      return body;
    } catch (err) {
      let message;
      /* istanbul ignore else */
      if (err instanceof HTTPError && err.response) {
        const { response } = err;
        message = `HTTP ${response.statusCode}: ${JSON.stringify(response.body)}`;
      } else {
        ({ message } = asError(err));
      }
      logger.debug(`Failed to refresh token: ${message}`, logContext);
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
      logger.debug(`Failing request without JWT role(s): ${requiredRoles.join(', ')}`, getLogContext(req));
      res.status(403).send('Not authorized');
    };
  }

  /**
   * Returns a handler for the OAuth 2.0 redirection endpoint that exchanges an
   * authorization code for a JWT/access token and optional refresh token.
   * @param {OAuthConfig} config the OAuth 2.0 configuration settings
   */
  public oauthCompletion(config: OAuthConfig): express.RequestHandler {
    /* istanbul ignore next */
    const { accessTokenQueryParam = 'access_token', refreshTokenQueryParam = 'refresh_token' } = config;
    /* istanbul ignore next */
    const accessTokenCookieConfig = {
      ...defaultAccessTokenCookieConfig,
      ...config.cookieConfig,
      ...config.accessTokenCookieConfig
    };
    /* istanbul ignore next */
    const refreshTokenCookieConfig = {
      ...defaultRefreshTokenCookieConfig,
      ...config.cookieConfig,
      ...config.refreshTokenCookieConfig
    };
    const { name: accessTokenCookieName, disabled: accessTokenCookieDisabled } = accessTokenCookieConfig;
    const { name: refreshTokenCookieName, disabled: refreshTokenCookieDisabled } = refreshTokenCookieConfig;
    return async (req: express.Request, res: express.Response): Promise<void> => {
      const { logger = getDefaultLogger() } = config;
      const logContext = getLogContext(req);

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

      const { tokenTransport = 'auto' } = config;
      let accessTokenTransport = tokenTransport;
      let refreshTokenTransport = tokenTransport;
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

        const tokenParamName = 'token_transport';
        const tokenParam = stateParams.get(tokenParamName);
        if (tokenParam) {
          stateParams.delete(tokenParamName);
          paramsChanged = true;
        }

        if (tokenTransport === 'auto') {
          if (accessTokenCookieDisabled || tokenParam === 'query') {
            accessTokenTransport = 'query';
          } else {
            accessTokenTransport = 'cookie';
          }
          if (refreshTokenCookieDisabled || tokenParam === 'query') {
            refreshTokenTransport = 'query';
          } else {
            refreshTokenTransport = 'cookie';
          }
        } else if (tokenTransport === 'cookie' && accessTokenCookieDisabled && refreshTokenCookieDisabled) {
          this.oauthError(res, 'invalid_request', 'Cannot specify redirect state with cookies disabled');
          return;
        }
      }

      logger.verbose(`Exchanging OAuth code "${code}" for token`, logContext);

      try {
        const tokenRes = await this.fusionAuth.post<OAuthTokenResponse>('oauth2/token', {
          searchParams: {
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code,
            grant_type: 'authorization_code',
            redirect_uri: config.redirectUri
          },
          responseType: 'json'
        });
        const data = tokenRes.body;

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
          switch (accessTokenTransport) {
            case 'cookie':
              res.cookie(accessTokenCookieName, data.access_token, accessTokenCookieConfig);
              break;
            case 'query':
              stateParams.set(accessTokenQueryParam, data.access_token);
              paramsChanged = true;
              break;
          }
          if (data.refresh_token) {
            switch (refreshTokenTransport) {
              case 'cookie':
                res.cookie(refreshTokenCookieName, data.refresh_token, refreshTokenCookieConfig);
                break;
              case 'query':
                stateParams.set(refreshTokenQueryParam, data.refresh_token);
                paramsChanged = true;
                break;
            }
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
          `Completed OAuth with ${jwtSource} JWT${data.refresh_token ? ' and refresh token' : ''} via ${jwtVia}`,
          logContext
        );
      } catch (err) {
        if (err instanceof HTTPError && err.response && isOAuthErrorResponse(err.response.body)) {
          /* istanbul ignore next */
          const { error = 'unknown_error', error_description } = err.response.body;
          const message = error_description || /* istanbul ignore next */ error;
          logger.debug(`Failed to exchange authorization code for token: ${message}`, logContext);
          this.oauthError(res, error, error_description, err.response.statusCode);
        } else {
          logger.debug(`Failed to exchange authorization code for token: ${asError(err).message}`, logContext);
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

function isSafeMethod(s: string): boolean {
  return ['GET', 'HEAD', 'OPTIONS'].includes(s);
}

function getLogContext(req: express.Request): object {
  const { ip, method, url } = req;
  return { ip, method, url };
}
