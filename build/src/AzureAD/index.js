"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AAD = void 0;
const standalone_1 = require("@adonisjs/ally/build/standalone");
const AllyUser_1 = __importDefault(require("../helpers/AllyUser"));
const lodash_1 = __importDefault(require("lodash"));
/**
 * Driver implementation. It is mostly configuration driven except the user calls
 *
 * ------------------------------------------------
 * Change "AAD" to something more relevant
 * ------------------------------------------------
 */
class AAD extends standalone_1.Oauth2Driver {
    constructor(ctx, config) {
        super(ctx, config);
        this.config = config;
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
        this.authorizeUrl = 'https://graph.microsoft.com/v1.0';
        /**
         * The URL to hit to exchange the authorization code for the access token
         *
         * Do not define query strings in this URL.
         */
        this.accessTokenUrl = 'https://graph.microsoft.com/v1.0';
        /**
         * The URL to hit to get the user details
         *
         * Do not define query strings in this URL.
         */
        this.userInfoUrl = 'https://graph.microsoft.com/v1.0/me';
        /**
         * The param name for the authorization code. Read the documentation of your oauth
         * provider and update the param name to match the query string field name in
         * which the oauth provider sends the authorization_code post redirect.
         */
        this.codeParamName = 'accessToken';
        /**
         * The param name for the error. Read the documentation of your oauth provider and update
         * the param name to match the query string field name in which the oauth provider sends
         * the error post redirect
         */
        this.errorParamName = 'error_description';
        /**
         * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
         * approach is to prefix the oauth provider name to `oauth_state` value. For example:
         * For example: "facebook_oauth_state"
         */
        this.stateCookieName = 'azuread_oauth_state';
        /**
         * Parameter name to be used for sending and receiving the state from.
         * Read the documentation of your oauth provider and update the param
         * name to match the query string used by the provider for exchanging
         * the state.
         */
        this.stateParamName = 'state';
        /**
         * Parameter name for sending the scopes to the oauth provider.
         */
        this.scopeParamName = 'scope';
        /**
         * The separator indentifier for defining multiple scopes
         */
        this.scopesSeparator = ' ';
        config.scopes = config.scopes || ['openid', 'profile', 'email', 'offline_access'];
        /**
         * Extremely important to call the following method to clear the
         * state set by the redirect request.
         *
         * DO NOT REMOVE THE FOLLOWING LINE
         */
        this.loadState();
    }
    /**
     * Configuring the redirect request with defaults
     */
    configureRedirectRequest(request) {
        /**
         * Define user defined scopes or the default one's
         */
        request.scopes(this.config.scopes || ['openid', 'profile', 'email', 'offline_access']);
        request.param('client_id', this.config.clientId);
        request.param('response_type', 'id_token');
        request.param('response_mode', 'query');
    }
    /**
     * Update the implementation to tell if the error received during redirect
     * means "ACCESS DENIED".
     */
    accessDenied() {
        return this.ctx.request.input('error') === 'invalid_grant';
    }
    /**
     * Returns the HTTP request with the authorization header set
     */
    getAuthenticatedRequest(url, token) {
        const request = this.httpClient(url);
        request.header('Authorization', `Bearer ${token}`);
        request.header('Accept', 'application/json');
        request.parseAs('json');
        return request;
    }
    buildAllyUser(userProfile, accessTokenResponse) {
        const allyUserBuilder = new AllyUser_1.default();
        const expires = lodash_1.default.get(accessTokenResponse, 'expires');
        const name = userProfile.givenName || userProfile.displayName;
        const emailVerificationState = lodash_1.default.get(userProfile, 'emailVerificationState', 'unverified');
        allyUserBuilder
            .setOriginal(userProfile)
            .setFields(userProfile.id, name, userProfile.surname, userProfile.userPrincipalName, null, emailVerificationState)
            .setToken(accessTokenResponse.accessToken, null, null, expires ? Number(expires) : null)
            .toJSON();
        const user = allyUserBuilder.toJSON();
        return user;
    }
    /**
     * Fetches the user info from the Google API
     */
    async getUserInfo(token, callback) {
        // User Info
        const userRequest = this.getAuthenticatedRequest(this.config.userInfoUrl || this.userInfoUrl, token);
        const accessTokenResponse = {
            accessToken: token,
        };
        if (typeof callback === 'function') {
            callback(userRequest);
        }
        const userBody = await userRequest.get();
        this.validateUserProfile(userBody);
        return this.buildAllyUser(userBody, accessTokenResponse);
    }
    /**
     * Processing the API client response. The child class can overwrite it
     * for more control
     */
    processClientResponse(client, response) {
        /**
         * Return json as it is when parsed response as json
         */
        if (client.responseType === 'json') {
            return response;
        }
    }
    // Not every MS account has email
    validateUserProfile(userProfile) {
        const email = userProfile.userPrincipalName;
        const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        const errorMessage = 'Unfortunately, we support logins via email only. Please enter your email and try again.';
        if (!re.test(email))
            throw new Error(errorMessage);
    }
    getCode() {
        return this.ctx.request.input(this.codeParamName, null);
    }
    /**
     * Get the user details by query the provider API. This method must return
     * the access token and the user details both. Checkout the google
     * implementation for same.
     *
     * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
     */
    async user(callback) {
        const accessToken = this.getCode();
        if (!accessToken)
            throw new Error('No access token found');
        /**
         * Allow end user to configure the request. This should be called after your custom
         * configuration, so that the user can override them (if required)
         */
        const user = await this.getUserInfo(accessToken, callback);
        /**
         * Write your implementation details here
         */
        return {
            ...user,
            // @ts-ignore
            token: accessToken,
        };
    }
    /**
     * Finds the user by the access token
     */
    async userFromToken(token) {
        const user = await this.getUserInfo(token);
        return {
            ...user,
            token: { token, type: 'bearer' },
        };
    }
}
exports.AAD = AAD;
