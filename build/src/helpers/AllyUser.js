"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class AllyUser {
    constructor() {
        this._userFields = {
            id: '',
            name: '',
            email: '',
            avatarUrl: '',
            nickName: '',
            emailVerificationState: 'unverified',
            original: null,
        };
        this._tokenFields = {
            accessToken: '',
            refreshToken: '',
            tokenSecret: '',
            expires: null,
        };
        this._original = {};
    }
    setFields(id, firstName, lastName, email, avatarUrl, emailVerificationState) {
        let name = firstName;
        if (lastName)
            name += ` ${lastName}`;
        this._userFields = {
            id,
            name,
            email,
            avatarUrl,
            nickName: name,
            emailVerificationState,
            original: null,
        };
        return this;
    }
    setToken(accessToken, refreshToken, tokenSecret, expires = null) {
        this._tokenFields = { accessToken, refreshToken, tokenSecret, expires };
        return this;
    }
    /**
     * Sets the original payload received from the
     * provider, helpful for debugging.
     *
     * @method setOriginal
     */
    setOriginal(response) {
        this._original = response;
        return this;
    }
    /**
     * Returns original payload received from the
     * provider.
     */
    getOriginal() {
        return this._original;
    }
    /**
     * Returns the user id
     */
    getId() {
        return this._userFields.id;
    }
    /**
     * Returns the user name
     */
    getName() {
        return this._userFields.name;
    }
    /**
     * Returns the user email
     */
    getEmail() {
        return this._userFields.email;
    }
    /**
     * Returns the user avatar
     */
    getAvatar() {
        return this._userFields.avatarUrl;
    }
    /**
     * Returns the user access token
     */
    getAccessToken() {
        return this._tokenFields.accessToken;
    }
    /**
     * Returns the user refresh token
     */
    getRefreshToken() {
        return this._tokenFields.refreshToken;
    }
    /**
     * Returns the users token expiry
     */
    getExpires() {
        return this._tokenFields.expires;
    }
    /**
     * Returns the users token secret
     */
    getTokenSecret() {
        return this._tokenFields.tokenSecret;
    }
    /**
     * Returns a json representation of the user fields
     * and the token fields merged into a single
     * object.
     */
    toJSON() {
        return {
            ...this._userFields,
            ...this._tokenFields,
        };
    }
}
exports.default = AllyUser;
