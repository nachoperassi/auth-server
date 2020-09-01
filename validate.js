/* eslint-disable no-console */
"use strict";

const db = require("./db");
const tokenUtils = require("./tokenUtils");
const process = require("process");

/** Validate object to attach all functions to  */
const validate = Object.create(null);

/** Suppress tracing for testing purposes */
const suppressTrace = process.env.SURPRESS_TRACE === "true";

/**
 * Log the message and throw it as an Error
 * @param {String} msg - Message to log and throw
 * @throws {Error} - The given message as an error
 * @returns {undefined}
 */
validate.logAndThrow = (msg) => {
  if (!suppressTrace) {
    console.trace(msg);
  }

  throw new Error(msg);
};

/**
 * Given a user and a password it will return the user if it exists and the password matches,
 * otherwise it will throw an error
 * @param {Object} user - The user profile
 * @param {String} password - The user's password
 * @throws {Error} If the user does not exist or the password does not match
 * @returns {Object} The user if valid
 */
validate.user = (user, password) => {
  validate.userExists(user);
  if (user.password !== password) {
    validate.logAndThrow("User password does not match");
  }
  return user;
};

/**
 * Given a user it will return the user if it exists otherwise it will throw an error
 * @param {Object} user - The user profile
 * @throws {Error} If the user does not exist
 * @returns {Object} The user if valid
 */
validate.userExists = (user) => {
  if (user == null) {
    validate.logAndThrow("User does not exist");
  }
  return user;
};

/**
 * Given a client and a client secret it will return the client if it exists and its clientSecret
 * matches, otherwise it will throw an error
 * @param {Object} client - The client profile
 * @param {String} clientSecret - The client's secret
 * @throws {Error} If the client or the client secret does not match
 * @returns {Object} The client if valid
 */
validate.client = (client, clientSecret) => {
  validate.clientExists(client);
  if (client.clientSecret !== clientSecret) {
    validate.logAndThrow("Client secret does not match");
  }
  return client;
};

/**
 * Given a client it will return the client if it exists, otherwise it will throw an error
 * @param {Object} client - The client profile
 * @throws {Error} If the client does not exist
 * @returns {Object} The client if valid
 */
validate.clientExists = (client) => {
  if (client == null) {
    validate.logAndThrow("Client does not exist");
  }
  return client;
};

/**
 * Given a token and accessToken this will return either the user or the client associated with
 * the token if valid. Otherwise this will throw.
 * @param {Object} token - The token entity as it is stored in the db
 * @param {Object} accessToken - The raw saccess token
 * @throws {Error} If the token is not valid
 * @returns {Promise} Resolved with the user or client associated with the token if valid
 */
validate.token = (token, accessToken) => {
  tokenUtils.verifyToken(accessToken);

  // token is a user token
  if (token.userID != null) {
    return db.users
      .find(token.userID)
      .then((user) => validate.userExists(user))
      .then((user) => user);
  }
  // token is a client token
  return db.clients
    .find(token.clientID)
    .then((client) => validate.clientExists(client))
    .then((client) => client);
};

/**
 * Given a refresh token and a client this will return the refresh token if it exists and the client
 * id's match otherwise this will throw an error
 * throw an error
 * @param {Object} token - The token entity as it is stored in the db
 * @param {Object} refreshToken - The raw refresh token
 * @param {Object} client - The client profile
 * @throws {Error} If the refresh token does not exist or the client id's don't match
 * @returns {Object} The refresh token if valid
 */
validate.refreshToken = (token, refreshToken, client) => {
  tokenUtils.verifyToken(refreshToken);
  if (client.id !== token.clientID) {
    validate.logAndThrow(
      "RefreshToken clientID does not match client id given"
    );
  }
  return token;
};

/**
 * Given an auth code, a client, and a redirectURI this will return the auth code if it exists, the client id matches it, and the redirectURI matches it, otherwise this will throw an
 * error.
 * @param {Object} authCode - The raw auth code
 * @param {Object} code - The code entity as it is stored in the db
 * @param {Object} client - The client profile
 * @param {Object} redirectURI - The redirectURI to check against
 * @throws {Error} If the auth code does not exist or is zero or does not match the client or the redirectURI
 * @returns {Object} The auth code token if valid
 */
validate.authCode = (authCode, code, client, redirectURI) => {
  tokenUtils.verifyToken(authCode);
  if (client.id !== code.clientID) {
    validate.logAndThrow("AuthCode clientID does not match client id given");
  }
  if (redirectURI !== code.redirectURI) {
    validate.logAndThrow(
      "AuthCode redirectURI does not match redirectURI given"
    );
  }
  return code;
};

/**
 * Given a token it will resolve a promise with the token if it is not null and the expiration
 * date has not been exceeded, otherwise this will throw a HTTP error.
 * @param {Object} token - The token to check
 * @returns {Promise} Resolved with the token if it is a valid token otherwise rejected with error
 */
validate.tokenForHttp = (token) =>
  new Promise((resolve, reject) => {
    try {
      tokenUtils.verifyToken(token);
    } catch (err) {
      const error = new Error("invalid_token");
      error.status = 400;
      reject(error);
    }
    resolve(token);
  });

/**
 * Given a token it will return the token if it is not null, otherwise it will throw an
 * HTTP error.
 * @param {Object} token - The token to check
 * @throws {Error} If the token is null
 * @returns {Object} The token if it is valid
 */
validate.tokenExistsForHttp = (token) => {
  if (token == null) {
    const error = new Error("invalid_token");
    error.status = 400;
    throw error;
  }
  return token;
};

/**
 * Given a client it will return the client if it is not null, otherwise it will throw an
 * HTTP error.
 * @param {Object} client - The client to check
 * @throws {Error} If the client is null
 * @returns {Object} The client if it is valid
 */
validate.clientExistsForHttp = (client) => {
  if (client == null) {
    const error = new Error("invalid_token");
    error.status = 400;
    throw error;
  }
  return client;
};

module.exports = validate;
