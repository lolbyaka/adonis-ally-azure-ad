/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| This is a dummy implementation of the Oauth driver. Make sure you
|
| - Got through every line of code
| - Read every comment
|
*/

import type {
  AllyUserContract,
  ApiRequestContract,
  LiteralStringUnion,
} from '@ioc:Adonis/Addons/Ally'
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { Oauth2Driver, ApiRequest, RedirectRequest } from '@adonisjs/ally/build/standalone'
import AllyUser, { UserFields } from '../helpers/AllyUser'
import _ from 'lodash'

/**
 * Define the access token object properties in this type. It
 * must have "token" and "type" and you are free to add
 * more properties.
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export type AADAccessToken = {
  token: string
  type: string
  token_type: string
  scope: string
  expires_in: number
  ext_expires_in: number
  access_token: string
  refresh_token: string
  id_token: string
}

/**
 * Define a union of scopes your driver accepts. Here's an example of same
 * https://github.com/adonisjs/ally/blob/develop/adonis-typings/ally.ts#L236-L268
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export type AADScopes = string

/**
 * Define the configuration options accepted by your driver. It must have the following
 * properties and you are free add more.
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export type AADConfig = {
  driver: 'AzureAD'
  clientId: string
  clientSecret: string
  callbackUrl: string
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
  scopes?: LiteralStringUnion<AADScopes>[]
}

export type UserInfo = {
  '@odata.context': string
  '@odata.id': string
  'businessPhones': string[]
  'displayName': string
  'givenName': string
  'jobTitle': string
  'mail': string
  'mobilePhone': string
  'officeLocation': string
  'preferredLanguage'?: any
  'surname': string
  'userPrincipalName': string
  'id': string
}

/**
 * Driver implementation. It is mostly configuration driven except the user calls
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export class AAD extends Oauth2Driver<AADAccessToken, AADScopes> {
  /**
   * The URL for the authority data
   *
   * Do not define query strings in this URL.
   */
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   *
   * Do not define query strings in this URL.
   */
  protected authorizeUrl = 'https://graph.microsoft.com/v1.0'

  /**
   * The URL to hit to exchange the authorization code for the access token
   *
   * Do not define query strings in this URL.
   */
  protected accessTokenUrl = 'https://graph.microsoft.com/v1.0'

  /**
   * The URL to hit to get the user details
   *
   * Do not define query strings in this URL.
   */
  protected userInfoUrl = 'https://graph.microsoft.com/v1.0/me'

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'accessToken'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error_description'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'azuread_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(ctx: HttpContextContract, public config: AADConfig) {
    super(ctx, config)

    config.scopes = config.scopes || ['openid', 'profile', 'email', 'offline_access']

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()
  }

  /**
   * Configuring the redirect request with defaults
   */
  protected configureRedirectRequest(request: RedirectRequest<AADScopes>) {
    /**
     * Define user defined scopes or the default one's
     */
    request.scopes(this.config.scopes || ['openid', 'profile', 'email', 'offline_access'])

    request.param('client_id', this.config.clientId)
    request.param('response_type', 'id_token')
    request.param('response_mode', 'query')
  }

  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  public accessDenied() {
    return this.ctx.request.input('error') === 'invalid_grant'
  }

  /**
   * Returns the HTTP request with the authorization header set
   */
  protected getAuthenticatedRequest(url: string, token: string) {
    const request = this.httpClient(url)
    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')
    return request
  }

  private buildAllyUser(userProfile, accessTokenResponse) {
    const allyUserBuilder = new AllyUser()
    const expires = _.get(accessTokenResponse, 'expires')
    const name = userProfile.givenName || userProfile.displayName
    const emailVerificationState = _.get(userProfile, 'emailVerificationState', 'unverified')

    allyUserBuilder
      .setOriginal(userProfile)
      .setFields(
        userProfile.id,
        name,
        userProfile.surname,
        userProfile.userPrincipalName,
        null,
        emailVerificationState
      )
      .setToken(accessTokenResponse.accessToken, null, null, expires ? Number(expires) : null)
      .toJSON()

    const user: UserFields = allyUserBuilder.toJSON()

    return user
  }

  /**
   * Fetches the user info from the Google API
   */
  protected async getUserInfo(
    token: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<UserFields> {
    // User Info
    const userRequest = this.getAuthenticatedRequest(
      this.config.userInfoUrl || this.userInfoUrl,
      token
    )

    const accessTokenResponse = {
      accessToken: token,
    }

    if (typeof callback === 'function') {
      callback(userRequest)
    }

    const userBody: UserInfo = await userRequest.get()

    this.validateUserProfile(userBody)

    return this.buildAllyUser(userBody, accessTokenResponse)
  }

  /**
   * Processing the API client response. The child class can overwrite it
   * for more control
   */
  protected processClientResponse(client: ApiRequest, response: any): any {
    /**
     * Return json as it is when parsed response as json
     */
    if (client.responseType === 'json') {
      return response
    }
  }

  // Not every MS account has email
  protected validateUserProfile(userProfile) {
    const email = userProfile.userPrincipalName
    const re =
      /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    const errorMessage =
      'Unfortunately, we support logins via email only. Please enter your email and try again.'
    if (!re.test(email)) throw new Error(errorMessage)
  }

  public getCode(): string | null {
    return this.ctx.request.input(this.codeParamName, null)
  }

  /**
   * Get the user details by query the provider API. This method must return
   * the access token and the user details both. Checkout the google
   * implementation for same.
   *
   * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
   */
  public async user(
    callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<AADAccessToken>> {
    const accessToken = this.getCode()

    if (!accessToken) throw new Error('No access token found')
    /**
     * Allow end user to configure the request. This should be called after your custom
     * configuration, so that the user can override them (if required)
     */
    const user = await this.getUserInfo(accessToken, callback)

    /**
     * Write your implementation details here
     */
    return {
      ...user,
      // @ts-ignore
      token: accessToken,
    }
  }

  /**
   * Finds the user by the access token
   */
  public async userFromToken(token: string) {
    const user: UserFields = await this.getUserInfo(token)

    return {
      ...user,
      token: { token, type: 'bearer' as const },
    }
  }
}
