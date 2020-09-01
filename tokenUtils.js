'use strict';

const fs = require('fs');
const path = require('path');
const uuid = require('uuid/v4');
const jwt = require('jsonwebtoken');
const db = require('./db');
const config = require('./config');

/** Private certificate used to sign JSON WebTokens */
const privateKey = fs.readFileSync(path.join(__dirname, 'certs/privatekey.pem'));

/** Public certificate used for verification */
const publicKey = fs.readFileSync(path.join(__dirname, 'certs/certificate.pem'));

/**
 * Creates a signed JSON WebToken. Utilizes the private certificate to create
 * the signed JWT. More options:
 * https://github.com/auth0/node-jsonwebtoken
 *
 * @param {Number} expiresIn - The number of seconds for this token to expire. By default it will be 60
 *  minutes (3600 seconds) if nothing is passed in
 * @param {String} subject - The subject or identity of the token
 * @return {String} - The JWT Token
 */
const createToken = ({ expiresIn = 3600, subject = '' } = {}) => {
  const token = jwt.sign({
    jti: uuid(),
    sub: subject,
    exp: Math.floor(Date.now() / 1000) + expiresIn,
  }, privateKey, {
    algorithm: 'RS256',
  });

  return token;
};

/**
 * Verifies the token through the JWT library using the public certificate.
 * @param {String} token - The token to verify
 * @throws {Error} - Error if the token could not be verified
 * @returns {Object} - The token decoded and verified
 */
const verifyToken = token => jwt.verify(token, publicKey);

/**
 * Mimic openid connect's offline scope
 * @param {Array} scope - The scope to check if a refresh token should be returned
 * @returns {Boolean} true if the scope is offline_access, otherwise false
 */
const asksForRefreshToken = ({ scope }) =>
  scope != null && scope.indexOf("offline_access") === 0;

/**
 * Given a userId, clientID, and scope this will generate a refresh token, save it, and return it
 * @param   {Object}  userId   - The user profile
 * @throws  {Object}  clientID - the client profile
 * @throws  {Object}  scope    - the scope
 * @returns {Promise} The resolved refresh token after saved
 */
const generateRefreshToken = ({ userId, clientID, scope }) => {
  const refreshToken = createToken({
    subject: userId,
    expiresIn: config.refreshToken.expiresIn,
  });
  return db.refreshTokens
    .save(refreshToken, userId, clientID, scope)
    .then(() => refreshToken);
};

/**
 * Given an auth code this will generate a access token, save that token and then return it.
 * @param   {userID}   userID   - The user profile
 * @param   {clientID} clientID - The client profile
 * @param   {scope}    scope    - The scope
 * @returns {Promise}  The resolved refresh token after saved
 */
const generateToken = ({ userID, clientID, scope }) => {
  const token = createToken({
    subject: userID,
    expiresIn: config.token.expiresIn,
  });
  const expiration = config.token.calculateExpirationDate();
  return db.accessTokens
    .save(token, expiration, userID, clientID, scope)
    .then(() => token);
};

/**
 * Given an auth code this will generate a access and refresh token, save both of those and return
 * them if the auth code indicates to return both.  Otherwise only an access token will be returned.
 * @param   {Object}  authCode - The auth code
 * @throws  {Error}   If the auth code does not exist or is zero
 * @returns {Promise} The resolved refresh and access tokens as an array
 */
const generateTokens = (authCode) => {
  const tokensGenerationPromises = [generateToken(authCode)];

  if (asksForRefreshToken(authCode)) {
    tokensGenerationPromises.push(generateRefreshToken(authCode));
  }

  return Promise.all(tokensGenerationPromises);
};

module.exports = {
  createToken,
  verifyToken,
  generateToken,
  generateTokens,
};
