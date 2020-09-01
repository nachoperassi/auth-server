'use strict';

const config = require('../config');
const db = require('../db');
const login = require('connect-ensure-login');
const oauth2orize = require('oauth2orize');
const passport = require('passport');
const tokenUtils = require('../tokenUtils');
const validate = require('../validate');

// create OAuth 2.0 server
const server = oauth2orize.createServer();

// Configured expiresIn
const expiresIn = { expires_in: config.token.expiresIn };

/**
 * Authorization code:
 *
 * Issue an authorization code bound to the values recieved in
 * the request (user, client, redirectUri and scope).
 */
server.grant(oauth2orize.grant.code((client, redirectURI, user, ares, done) => {
  const code = tokenUtils.createToken({ subject: user.id, expiresIn: config.codeToken.expiresIn });
  db.authorizationCodes.save(code, client.id, redirectURI, user.id, client.scope)
  .then(() => done(null, code))
  .catch(err => done(err));
}));

/**
 * Access token:
 *
 * Exchange an authorization code for an access token and (optionally) a refresh token.
 */
server.exchange(oauth2orize.exchange.code((client, authCode, redirectURI, done) => {
  db.authorizationCodes.delete(authCode)
  .then(code => validate.authCode(authCode, code, client, redirectURI))
  .then(code => tokenUtils.generateTokens(code))
  .then((tokens) => {
    if (tokens.length === 1) {
      return done(null, tokens[0], null, expiresIn);
    }
    if (tokens.length === 2) {
      return done(null, tokens[0], tokens[1], expiresIn);
    }
    throw new Error('Error exchanging auth code for tokens');
  })
  .catch(() => done(null, false));
}));

/**
 * Refresh token:
 *
 * Exchange a refresh token for an access token.
 */
server.exchange(oauth2orize.exchange.refreshToken((client, refreshToken, scope, done) => {
  db.refreshTokens.find(refreshToken)
  .then(foundRefreshToken => validate.refreshToken(foundRefreshToken, refreshToken, client))
  .then(foundRefreshToken => tokenUtils.generateToken(foundRefreshToken))
  .then(token => done(null, token, null, expiresIn))
  .catch(() => done(null, false));
}));

/*
 * Authorization code endpoint
 *
 * Initialize a new authorization transaction.
 * Redirect to the redirectUri with the authorization code
 * Return a 401 error if the client is not authorized
 */
exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization((clientID, redirectURI, scope, done) => {
    db.clients.findByClientId(clientID)
    .then((client) => {
      if (client) {
        // received scope is being assigned directly
        // TODO implement restricted scopes
        client.scope = scope; // eslint-disable-line no-param-reassign
      }

      // TODO validate redirectURI against client.redirectUri

      return done(null, client, redirectURI);
    })
    .catch(err => done(err));
  }), (req, res, next) => {
    // TODO join this with the logic in the middleware above
    // see if it is better to handle everything in the previous callback or in a custom middleware
    db.clients.findByClientId(req.query.client_id)
    .then((client) => {
      if (client != null) {
        // Redirect to the redirectUri with the authorization code
        server.decision({ loadTransaction: false }, (serverReq, callback) => {
          callback(null, { allow: true });
        })(req, res, next);
      } else {
        res.status(401).send({ error: 'Client not autorized' });
      }
    })
    .catch((err) =>
      res.status(500).send({ error: err })
    )
  }];

/**
 * Token endpoint
 *
 * Receive the authorization code and the client credentials
 * The authorization code is obtained from the request body
 * The client credentials may be obtained from the request body or the Authorization header
 * Return an object containing the access token, the refresh token, an expiration time
 * and token type
 */
exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler(),
];

server.serializeClient((client, done) => done(null, client.id));

server.deserializeClient((id, done) => {
  db.clients.find(id)
  .then(client => done(null, client))
  .catch(err => done(err));
});

