'use strict';

const OAuth2Strategy = require('passport-oauth2');
const util = require('util');
const querystring = require('querystring')
const randomNickname = require('./randomNickname')


/**
 * `Strategy` constructor.
 *
 * Feishu's OAuth strategy. Please refer to:
 *   Chinese: https://open.baiteda.cn/document/ukTMukTMukTM/ukzN4UjL5cDO14SO3gTN
 *   English: https://open.baiteda.cn/document/uQTO24CN5YjL0kjN/uEzN44SM3gjLxcDO
 *
 * Options:
 *   - `clientID`      your Feishu application's app id
 *   - `clientSecret`  your Feishu application's app secret
 *   - `callbackURL`   URL to which Feishu will redirect the user after granting authorization
 *   - `appType`       application type, 'public'(default) or 'internal'
 *   - `appTicket`     application ticket, required if `appType` is 'public'
 *
 * Examples:
 *
 *     passport.use(new FeishuStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.net/auth/baiteda/callback',
 *         appType: 'public',
 *         appTicket: 'an-app-ticket'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         cb(null, profile);
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
	options = options || {};
	options.authorizationURL = 'https://user-center-test.baiteda.com:8443/user_center/api/public/sso/oauth/authorize';
	options.tokenURL = 'https://user-center-test.baiteda.com:8443/user_center/api/public/sso/oauth/token';
	options.scopeSeparator = options.scopeSeparator || ',';
	options.customHeaders = options.customHeaders || {};
	// options.appType = options.appType || 'public';
	// options.redisKey = options.redisKey || ('baiteda:appTicketKey:' + options.clientID);
	// if (options.appType === 'public' && !options.appTicket && !options.redis) {
	// 	throw new TypeError('A public Feishu app requires a `appTicket` option');
	// }

	OAuth2Strategy.call(this, options, verify);

	this.name = 'baiteda';
	this._oauth2.useAuthorizationHeaderforGET(true);

	this._userProfileURL = options.userProfileURL || 'https://user-center-test.baiteda.com:8443/user_center/api/private/user/detail';

	// Override OAuth2's `getOAuthAccessToken` in accordance to Feishu's OAuth protocol
	const self = this;
	self._oauth2.getOAuthAccessToken = function (code, params, callback) {
		var params = params || {};
		params['client_id'] = this._clientId;
		params['client_secret'] = this._clientSecret;
		params['scope'] = 'all'
		var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
		params[codeParam] = code;

		var post_data = querystring.stringify(params);
		var post_headers = {
			'Content-Type': 'application/x-www-form-urlencoded'
		};
		this._request("POST", this._getAccessTokenUrl() + '?' + post_data, post_headers, null, null, function (error, data, response) {
			if (error) callback(error);
			else {
				var results;
				try {
					// As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
					// responses should be in JSON
					results = JSON.parse(data);
				} catch (e) {
					// .... However both Facebook + Github currently use rev05 of the spec
					// and neither seem to specify a content-type correctly in their response headers :(
					// clients of these services will suffer a *minor* performance cost of the exception
					// being thrown
					results = querystring.parse(data);
				}
				var access_token = results["access_token"];
				var refresh_token = results["refresh_token"];
				delete results["refresh_token"];
				callback(null, access_token, refresh_token, results); // callback results =-=
			}
		});
	}

}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
 * Return extra Feishu-specific parameters to be included in the authorization
 * request.
 *
 * @param {object} options
 * @return {string}
 * @access protected
 */

/**
 * Get `app_access_token` required by Feishu's authentication.
 *
 * @param {function} callback
 * @access protected
 */

/**
 * Retrieve user profile from Feishu.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `baiteda`
 *   - `id`               the user's Feishu ID
 *   - `name`             the user's Feishu name
 *   - `email`            the email address of the user if authorized
 *   - `mobile`           the mobile number of the user if authorized
 *   - `avatar.icon`      the URL of the user's avatar - icon size
 *   - `avatar.thumb`     the URL of the user's avatar - thumb size
 *   - `avatar.middle`    the URL of the user's avatar - middle size
 *   - `avatar.big`       the URL of the user's avatar - big size
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function (
	accessToken, done) {
	this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
		var json;

		if (err) {
			return done(new InternalOAuthError('Failed to fetch user profile', err));
		}

		try {
			json = JSON.parse(body);
		} catch (ex) {
			return done(new Error('Failed to parse user profile'));
		}

		var profile = parse(json);
		profile.provider = 'baiteda';
		profile._raw = body;
		profile._json = json;

		done(null, profile);
	});

	function parse(json) {
		if ('string' == typeof json) {
			json = JSON.parse(json);
		}
		var profile = {};
		profile.id = json.data.user_base_info.user_id;
		profile.mobile = json.data.mobile;
		profile.name = randomNickname()
		profile.tenant = json.data.tenant_list.reduce((prev, cur, index) => {
			return prev + cur.tenant_name + (index === json.data.tenant_list.length - 1 ? '' : '，')
		}, '')
		if (profile.tenant) {
			profile.email = '@' + profile.tenant;
		}


		return profile;
	};

};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;