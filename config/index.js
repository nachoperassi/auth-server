'use strict';

// Configuration options of the server

/**
 * Configuration of access tokens.
 * expiresIn - The time in minutes before the access token expires. Default is 60 minutes
 * calculateExpirationDate - A simple function to calculate the absolute time that the token is going to expire in.
 */
exports.token = {
  expiresIn: 60 * 60,
  calculateExpirationDate: () => new Date(Date.now() + (this.token.expiresIn * 1000)),
}

/**
 * Configuration of code token.
 * expiresIn - The time in minutes before the code token expires.  Default is 5 minutes.
 */
exports.codeToken = {
  expiresIn: 5 * 60,
};

/**
 * Configuration of refresh token.
 * expiresIn - The time in minutes before the code token expires. Default is 100 years.
 */
exports.refreshToken = {
  expiresIn: 52560000,
};

/**
 * Database configuration for access and refresh tokens.
 * timeToCheckExpiredTokens - The time in seconds to check the database for expired access tokens.
 */
exports.db = {
  timeToCheckExpiredTokens: 3600,
};

/**
 * Session configuration
 * maxAge - The maximum age in milliseconds of the session. Default is 1 year.
 * secret - The session secret
 */
exports.session = {
  maxAge: 3600000 * 24 * 7 * 52,
  secret: 'asdsdgkjshgdkjgdgdjgd', // TODO implementar como variable de entorno
};
