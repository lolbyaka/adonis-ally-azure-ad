import { UserInfo } from '../AzureAD'

export type TokenFields = {
  accessToken: string
  refreshToken: string | null
  expires: number | null
  tokenSecret: string | null
}

export type UserFields = {
  id: string
  avatarUrl: string | null
  nickName: string
  displayName?: string | undefined
  name: string
  email: string | null
  emailVerificationState: 'verified' | 'unverified' | 'unsupported'
  original: UserInfo | null
}

export default class AllyUser {
  private _userFields: UserFields = {
    id: '',
    name: '',
    email: '',
    avatarUrl: '',
    nickName: '',
    emailVerificationState: 'unverified',
    original: null,
  }

  private _tokenFields: TokenFields = {
    accessToken: '',
    refreshToken: '',
    tokenSecret: '',
    expires: null,
  }

  private _original: unknown = {}

  constructor() {}

  public setFields(
    id: string,
    firstName: string,
    lastName: string,
    email: string,
    avatarUrl: string | null,
    emailVerificationState: 'verified' | 'unverified' | 'unsupported'
  ) {
    let name = firstName
    if (lastName) name += ` ${lastName}`
    this._userFields = {
      id,
      name,
      email,
      avatarUrl,
      nickName: name,
      emailVerificationState,
      original: null,
    }
    return this
  }

  public setToken(
    accessToken: string,
    refreshToken: string | null,
    tokenSecret: string | null,
    expires: number | null = null
  ) {
    this._tokenFields = { accessToken, refreshToken, tokenSecret, expires }
    return this
  }

  /**
   * Sets the original payload received from the
   * provider, helpful for debugging.
   *
   * @method setOriginal
   */
  public setOriginal(response) {
    this._original = response
    return this
  }

  /**
   * Returns original payload received from the
   * provider.
   */
  public getOriginal() {
    return this._original
  }

  /**
   * Returns the user id
   */
  public getId() {
    return this._userFields.id
  }

  /**
   * Returns the user name
   */
  public getName() {
    return this._userFields.name
  }

  /**
   * Returns the user email
   */
  public getEmail() {
    return this._userFields.email
  }

  /**
   * Returns the user avatar
   */
  public getAvatar() {
    return this._userFields.avatarUrl
  }

  /**
   * Returns the user access token
   */
  public getAccessToken() {
    return this._tokenFields.accessToken
  }

  /**
   * Returns the user refresh token
   */
  public getRefreshToken() {
    return this._tokenFields.refreshToken
  }

  /**
   * Returns the users token expiry
   */
  public getExpires() {
    return this._tokenFields.expires
  }

  /**
   * Returns the users token secret
   */
  public getTokenSecret() {
    return this._tokenFields.tokenSecret
  }

  /**
   * Returns a json representation of the user fields
   * and the token fields merged into a single
   * object.
   */
  public toJSON(): UserFields & TokenFields {
    return {
      ...this._userFields,
      ...this._tokenFields,
    }
  }
}
