'use strict';

const passport = require('passport');
const { Strategy: LocalStrategy } = require('passport-local');
const { BasicStrategy } = require('passport-http');
const { Strategy: ClientPasswordStrategy } = require('passport-oauth2-client-password');
const { Strategy: BearerStrategy } = require('passport-http-bearer');
const db = require('../db');
const validate = require('../validate');

/**
 * Local Strategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */
passport.use(new LocalStrategy((username, password, done) => {
  db.users.findByUsername(username)
  .then(user => {
    return validate.user(user, password)
  })
  .then(user => done(null, user))
  .catch(() => {
    return done(null, false)
  });
}));

/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients. They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens. The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate. Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).
 */
passport.use(new BasicStrategy((clientId, clientSecret, done) => {
  db.clients.findByClientId(clientId)
  .then(client => validate.client(client, clientSecret))
  .then(client => done(null, client))
  .catch(() => done(null, false));
}));

passport.use(new ClientPasswordStrategy((clientId, clientSecret, done) => {
  db.clients.findByClientId(clientId)
  .then(client => validate.client(client, clientSecret))
  .then(client => done(null, client))
  .catch(() => done(null, false));
}));

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an access token
 * (aka a bearer token). If it is a user, they must have previously authorized a client
 * application, which received an access token to make requests on behalf of
 * the authorizing user.
 *
 * // TODO implement restricted scopes
 */
passport.use(new BearerStrategy((accessToken, done) => {
  db.accessTokens.find(accessToken)
  .then(token => validate.token(token, accessToken))
  .then(token => done(null, token, { scope: '*' }))
  .catch(() => done(null, false));
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.users.find(id)
  .then(user => done(null, user))
  .catch(err => done(err));
});
