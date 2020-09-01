'use strict';

const db = require('../db');
const validate = require('../validate');

/**
 * This endpoint is used to verify a token. It has the same signature as
 * Google's token verification system from:
 * https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
 *
 * It can be called like
 * https://localhost:3000/api/tokeninfo?access_token=someToken
 *
 * If the token is valid it returns
 * {
 *   "audience": some client id
 *   "expires_in": remaining token lifetime in seconds
 * }
 *
 * If the token is not valid it returns a 400 status with
 * {
 *   "error": "invalid_token"
 * }
 * @param   {Object}  req - The request
 * @param   {Object}  res - The response
 */
exports.info = (req, res) =>
  validate.tokenForHttp(req.query.access_token)
  .then(() => db.accessTokens.find(req.query.access_token))
  .then(token => validate.tokenExistsForHttp(token))
  .then(token =>
    db.clients.find(token.clientID)
    .then(client => validate.clientExistsForHttp(client))
    .then(client => ({ client, token })))
  .then(({ client, token }) => {
    const expirationLeft = Math.floor((token.expirationDate.getTime() - Date.now()) / 1000);
    res.json({ audience: client.clientId, expires_in: expirationLeft });
  })
  .catch((err) => {
    res.status(err.status);
    res.json({ error: err.message });
  });

/**
 * This endpoint is used to revoke a token. It has the same signature as
 * Google's token revocation system from:
 * https://developers.google.com/identity/protocols/OAuth2WebServer
 *
 * It can be called like
 * https://localhost:3000/api/revoke?token=someToken
 *
 * If the token is valid it returns an empty object
 * {}
 *
 * If the token is not valid it returns a 400 status with
 * {
 *   "error": "invalid_token"
 * }
 * This will first try to delete the token as an access token. If no one is found it will try and
 * delete the token as a refresh token. If both fail then an error is returned.
 * @param   {Object}  req - The request
 * @param   {Object}  res - The response
 */
exports.revoke = (req, res) =>
  validate.tokenForHttp(req.query.token)
  .then(() => db.accessTokens.delete(req.query.token))
  .then((token) => {
    if (token == null) {
      return db.refreshTokens.delete(req.query.token);
    }
    return token;
  })
  .then(tokenDeleted => validate.tokenExistsForHttp(tokenDeleted))
  .then(() => {
    res.json({});
  })
  .catch((err) => {
    res.status(err.status);
    res.json({ error: err.message });
  });
