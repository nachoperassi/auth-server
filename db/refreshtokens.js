"use strict";

const jwt = require("jsonwebtoken");

/**
 * Tokens in-memory data structure which stores all of the refresh tokens
 * TODO replace with DB
 */
let refreshTokens = Object.create(null);

/**
 * Returns a refresh token if it finds one, otherwise returns null
 * @param {String} refreshToken - The token to decode to get the id of the refresh token to find.
 * @returns {Promise} resolved with the token
 */
exports.find = (refreshToken) => {
  try {
    const id = jwt.decode(refreshToken).jti;
    return Promise.resolve(refreshTokens[id]);
  } catch (error) {
    return Promise.resolve(undefined);
  }
};

/**
 * Saves a refresh token.
 * Note: The actual full refresh token is never saved. Instead just the ID of the token is saved. In case of a database breach this
 * prevents anyone from stealing the live tokens.
 * @param {Object} refreshToken - The refresh token (required)
 * @param {String} userID - The user ID (required)
 * @param {String} clientID - The client ID (required)
 * @param {String} scope - The scope (optional)
 * @returns {Promise} resolved with the saved token
 */
exports.save = (refreshToken, userID, clientID, scope) => {
  const id = jwt.decode(refreshToken).jti;
  refreshTokens[id] = { userID, clientID, scope };
  return Promise.resolve(refreshTokens[id]);
};

/**
 * Deletes a refresh token
 * @param {String} refreshToken - The token to decode to get the id of the refresh token to delete.
 * @returns {Promise} resolved with the deleted token
 */
exports.delete = (refreshToken) => {
  try {
    const id = jwt.decode(refreshToken).jti;
    const deletedToken = refreshTokens[id];
    delete refreshTokens[id];
    return Promise.resolve(deletedToken);
  } catch (error) {
    return Promise.resolve(undefined);
  }
};

/**
 * Removes all refresh tokens
 * @returns {Promise} resolved with all removed tokens returned
 */
exports.removeAll = () => {
  const deletedTokens = refreshTokens;
  refreshTokens = Object.create(null);
  return Promise.resolve(deletedTokens);
};
