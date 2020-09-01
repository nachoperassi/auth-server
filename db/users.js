'use strict';

/**
 * Users allowed to connected to the authorization server.
 * // TODO replace with DB
 *
 * id: a unique numeric id of the user
 * username: the user name of the user
 * password: the password of the user
 * name: the name of your user
 */

const users = [{
  id: '1',
  username: 'nachoperassi',
  password: 'asdasd',
  name: 'Nacho Perassi',
}];

/**
 * Returns a user if it finds one, otherwise returns null
 * @param {String} id - The unique id of the user to find
 * @returns {Promise} resolved user if found, otherwise resolves undefined
 */
exports.find = id => Promise.resolve(users.find(user => user.id === id));

/**
 * Returns a user if it finds one, otherwise returns null
 * @param {String} username - The unique user name to find
 * @param {Function} done - The user if found, otherwise returns undefined
 * @returns {Promise} resolved user if found, otherwise resolves undefined
 */
exports.findByUsername = username =>
  Promise.resolve(users.find(user => user.username === username));
