'use strict';

const jwt = require('jsonwebtoken');

/**
 * Authorization codes in-memory data structure which stores all of the authorization codes
 * // TODO replace with DB
 */
let codes = Object.create(null);

/**
 * Returns an authorization code if it finds one, otherwise returns null
 * @param {String} code - The code used to get the id of the authorization code to find
 * @returns {Promise} resolved with the authorization code if found, otherwise undefined
 */
exports.find = (code) => {
  try {
    const id = jwt.decode(code).jti;
    return Promise.resolve(codes[id]);
  } catch (error) {
    return Promise.resolve(undefined);
  }
};

/**
 * Saves a authorization code, client id, redirect uri, user id, and scope.
 * Note: The actual full authorization code is never saved. Instead just the ID of the code is saved. In case of a
 * database breach this prevents anyone from stealing the live codes.
 * @param {String} code - The authorization code (required)
 * @param {String} clientID - The client ID (required)
 * @param {String} redirectURI - The redirect URI of where to send access tokens once exchanged
 * @param {String} userID - The user ID (required)
 * @param {String} scope - The scope (optional)
 * @returns {Promise} resolved with the saved token
 */
exports.save = (code, clientID, redirectURI, userID, scope) => {
  const id = jwt.decode(code).jti;
  codes[id] = { clientID, redirectURI, userID, scope };
  return Promise.resolve(codes[id]);
};

/**
 * Deletes an authorization code
 * @param  {String} code - The authorization code to delete
 * @returns {Promise} resolved with the deleted value
 */
exports.delete = (code) => {
  try {
    const id = jwt.decode(code).jti;
    const deletedCode = codes[id];
    delete codes[id];
    return Promise.resolve(deletedCode);
  } catch (error) {
    return Promise.resolve(undefined);
  }
};

/**
 * Removes all authorization codes.
 * @returns {Promise} resolved with all removed authorization codes returned
 */
exports.removeAll = () => {
  const deletedCodes = codes;
  codes = Object.create(null);
  return Promise.resolve(deletedCodes);
};
