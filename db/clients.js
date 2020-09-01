'use strict';

/**
 * Client applications allowed to connected to the authorization server.
 * // TODO replace with DB
 *
 * id: a unique numeric id of the client application
 * name: the name of the client application
 * clientId: a unique id of the client application
 * clientSecret: a unique password(ish) secret
 * redirectUrl: the trusted url where the authorization server should redirect the client requests
 */
const clients = [{
  id: '1',
  name: 'ucse-erm',
  clientId: 'abc123',
  clientSecret: 'ssh-secret',
  redirectUrl: 'ucse-erm.com'
}];

/**
 * Returns a client if it finds one, otherwise returns null
 * @param {String} id - The unique id of the client to find
 * @returns {Promise} resolved promise with the client if found, otherwise undefined
 */
exports.find = id => Promise.resolve(clients.find(client => client.id === id));

/**
 * Returns a client if it finds one, otherwise returns null
 * @param {String} clientId - The unique client id of the client to find
 * @returns {Promise} resolved promise with the client if found, otherwise undefined
 */
exports.findByClientId = clientId =>
  Promise.resolve(clients.find(client => client.clientId === clientId));
