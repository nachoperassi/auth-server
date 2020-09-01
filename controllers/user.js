'use strict';

const passport = require('passport');

/*
 * Simple informational end point about a particular user.
 * According to OAuth 2.0 standards, it should be called with an access token in the request Authorization header
 * http://tools.ietf.org/html/rfc6750#section-2.1
 *
 */

exports.info = [
  passport.authenticate('bearer', { session: false }),
  (req, res) => {
    // TODO Review if scope will be used
    res.json({ user_id: req.user.id, name: req.user.name, scope: req.authInfo.scope });
  },
];
