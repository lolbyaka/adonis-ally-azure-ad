import { UserInfo } from '../AzureAD';
export declare type TokenFields = {
    accessToken: string;
    refreshToken: string | null;
    expires: number | null;
    tokenSecret: string | null;
};
export declare type UserFields = {
    id: string;
    avatarUrl: string | null;
    nickName: string;
    displayName?: string | undefined;
    name: string;
    email: string | null;
    emailVerificationState: 'verified' | 'unverified' | 'unsupported';
    original: UserInfo | null;
};
export default class AllyUser {
    private _userFields;
    private _tokenFields;
    private _original;
    constructor();
    setFields(id: string, firstName: string, lastName: string, email: string, avatarUrl: string | null, emailVerificationState: 'verified' | 'unverified' | 'unsupported'): this;
    setToken(accessToken: string, refreshToken: string | null, tokenSecret: string | null, expires?: number | null): this;
    /**
     * Sets the original payload received from the
     * provider, helpful for debugging.
     *
     * @method setOriginal
     */
    setOriginal(response: any): this;
    /**
     * Returns original payload received from the
     * provider.
     */
    getOriginal(): unknown;
    /**
     * Returns the user id
     */
    getId(): string;
    /**
     * Returns the user name
     */
    getName(): string;
    /**
     * Returns the user email
     */
    getEmail(): string | null;
    /**
     * Returns the user avatar
     */
    getAvatar(): string | null;
    /**
     * Returns the user access token
     */
    getAccessToken(): string;
    /**
     * Returns the user refresh token
     */
    getRefreshToken(): string | null;
    /**
     * Returns the users token expiry
     */
    getExpires(): number | null;
    /**
     * Returns the users token secret
     */
    getTokenSecret(): string | null;
    /**
     * Returns a json representation of the user fields
     * and the token fields merged into a single
     * object.
     */
    toJSON(): UserFields & TokenFields;
}
