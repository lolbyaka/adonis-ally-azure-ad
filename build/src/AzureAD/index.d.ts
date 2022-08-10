import type { AllyUserContract, ApiRequestContract, LiteralStringUnion } from '@ioc:Adonis/Addons/Ally';
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext';
import { Oauth2Driver, ApiRequest, RedirectRequest } from '@adonisjs/ally/build/standalone';
import { UserFields } from '../helpers/AllyUser';
/**
 * Define the access token object properties in this type. It
 * must have "token" and "type" and you are free to add
 * more properties.
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export declare type AADAccessToken = {
    token: string;
    type: string;
    token_type: string;
    scope: string;
    expires_in: number;
    ext_expires_in: number;
    access_token: string;
    refresh_token: string;
    id_token: string;
};
/**
 * Define a union of scopes your driver accepts. Here's an example of same
 * https://github.com/adonisjs/ally/blob/develop/adonis-typings/ally.ts#L236-L268
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export declare type AADScopes = string;
/**
 * Define the configuration options accepted by your driver. It must have the following
 * properties and you are free add more.
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export declare type AADConfig = {
    driver: 'AzureAD';
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    authorizeUrl?: string;
    accessTokenUrl?: string;
    userInfoUrl?: string;
    scopes?: LiteralStringUnion<AADScopes>[];
};
export declare type UserInfo = {
    '@odata.context': string;
    '@odata.id': string;
    'businessPhones': string[];
    'displayName': string;
    'givenName': string;
    'jobTitle': string;
    'mail': string;
    'mobilePhone': string;
    'officeLocation': string;
    'preferredLanguage'?: any;
    'surname': string;
    'userPrincipalName': string;
    'id': string;
};
/**
 * Driver implementation. It is mostly configuration driven except the user calls
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
export declare class AAD extends Oauth2Driver<AADAccessToken, AADScopes> {
    config: AADConfig;
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
    protected authorizeUrl: string;
    /**
     * The URL to hit to exchange the authorization code for the access token
     *
     * Do not define query strings in this URL.
     */
    protected accessTokenUrl: string;
    /**
     * The URL to hit to get the user details
     *
     * Do not define query strings in this URL.
     */
    protected userInfoUrl: string;
    /**
     * The param name for the authorization code. Read the documentation of your oauth
     * provider and update the param name to match the query string field name in
     * which the oauth provider sends the authorization_code post redirect.
     */
    protected codeParamName: string;
    /**
     * The param name for the error. Read the documentation of your oauth provider and update
     * the param name to match the query string field name in which the oauth provider sends
     * the error post redirect
     */
    protected errorParamName: string;
    /**
     * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
     * approach is to prefix the oauth provider name to `oauth_state` value. For example:
     * For example: "facebook_oauth_state"
     */
    protected stateCookieName: string;
    /**
     * Parameter name to be used for sending and receiving the state from.
     * Read the documentation of your oauth provider and update the param
     * name to match the query string used by the provider for exchanging
     * the state.
     */
    protected stateParamName: string;
    /**
     * Parameter name for sending the scopes to the oauth provider.
     */
    protected scopeParamName: string;
    /**
     * The separator indentifier for defining multiple scopes
     */
    protected scopesSeparator: string;
    constructor(ctx: HttpContextContract, config: AADConfig);
    /**
     * Configuring the redirect request with defaults
     */
    protected configureRedirectRequest(request: RedirectRequest<AADScopes>): void;
    /**
     * Update the implementation to tell if the error received during redirect
     * means "ACCESS DENIED".
     */
    accessDenied(): boolean;
    /**
     * Returns the HTTP request with the authorization header set
     */
    protected getAuthenticatedRequest(url: string, token: string): ApiRequest;
    private buildAllyUser;
    /**
     * Fetches the user info from the Google API
     */
    protected getUserInfo(token: string, callback?: (request: ApiRequestContract) => void): Promise<UserFields>;
    /**
     * Processing the API client response. The child class can overwrite it
     * for more control
     */
    protected processClientResponse(client: ApiRequest, response: any): any;
    protected validateUserProfile(userProfile: any): void;
    getCode(): string | null;
    /**
     * Get the user details by query the provider API. This method must return
     * the access token and the user details both. Checkout the google
     * implementation for same.
     *
     * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
     */
    user(callback?: (request: ApiRequest) => void): Promise<AllyUserContract<AADAccessToken>>;
    /**
     * Finds the user by the access token
     */
    userFromToken(token: string): Promise<{
        token: {
            token: string;
            type: "bearer";
        };
        id: string;
        avatarUrl: string | null;
        nickName: string;
        displayName?: string | undefined;
        name: string;
        email: string | null;
        emailVerificationState: "verified" | "unverified" | "unsupported";
        original: UserInfo | null;
    }>;
}
