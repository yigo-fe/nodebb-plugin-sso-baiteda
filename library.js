(function (module) {
	'use strict'

	var User = require.main.require('./src/user')
	var db = require.main.require('./src/database')
	var meta = require.main.require('./src/meta')
	var nconf = require.main.require('nconf')
	var async = require.main.require('async')
	var passport = require.main.require('passport')
	var BaitedaStrategy = require('nodebb-plugin-sso-baiteda/passport-baiteda2').Strategy

	var winston = require.main.require('winston')

	var constants = Object.freeze({
		'name': 'baiteda',
		'admin': {
			'icon': 'fa-telegram',
			'route': '/plugins/sso-baiteda'
		}
	})

	var baiteda = {}
	const domain = nconf.get('url')

	baiteda.getStrategy = function (strategies, callback) {
		meta.settings.get('sso-baiteda', function (err, settings) {
			baiteda.settings = settings

			if (!err && settings.id && settings.secret) {
				passport.use(new BaitedaStrategy({
						clientID: settings.id,
						clientSecret: settings.secret,
						callbackURL: domain + '/auth/baiteda/callback',
						checkState: false,
						scope: 'all'
					},
					function (token, tokenSecret, profile, done) {
						var email = profile.email
						var displayName = profile.name
						var userName = profile.name
						baiteda.login(profile.id, displayName, userName, email, function (err, user) {
							if (err) return done(err)
							done(null, user)
						})
					}
				))

				strategies.push({
					name: 'baiteda',
					url: '/auth/baiteda',
					callbackURL: '/auth/baiteda/callback',
					checkState: false,
					icon: constants.admin.icon,
					logo: settings.ssoLogo,
					scope: 'all'
				})
			}

			callback(null, strategies)
		})
	}

	baiteda.appendUserHashWhitelist = function (data, callback) {
		data.whitelist.push('baitedaid')
		setImmediate(callback, null, data)
	}

	baiteda.getAssociation = function (data, callback) {
		User.getUserField(data.uid, 'baitedaid', function (err, baitedaid) {
			if (err) {
				return callback(err, data)
			}

			if (baitedaid) {
				data.associations.push({
					associated: true,
					name: constants.name,
					icon: constants.admin.icon,
					deauthUrl: domain + '/deauth/baiteda',
				})
			} else {
				data.associations.push({
					associated: false,
					url: domain + '/auth/baiteda',
					name: constants.name,
					icon: constants.admin.icon
				})
			}

			callback(null, data)
		})
	}

	baiteda.login = function (baitedaID, displayName, username, email, callback) {
		if (!email) {
			email = username + '@users.noreply.baiteda.com'
		}

		baiteda.getUidBybaitedaID(baitedaID, function (err, uid) {
			if (err) {
				return callback(err)
			}

			if (uid) {
				// Existing User
				User.setUserField(uid, 'email', email)
				callback(null, {
					uid: uid
				})
			} else {
				// New User
				var success = function (uid) {
					function checkEmail(next) {
						if (baiteda.settings.needToVerifyEmail === 'on') {
							return next()
						}
						User.email.confirmByUid(uid, next)
					}

					function mergeUserData(next) {
						async.waterfall([
							async.apply(User.getUserFields, uid, ['firstName', 'lastName', 'fullname']),
								function (info, next) {
									if (!info.fullname && displayName) {
										User.setUserField(uid, 'fullname', displayName)
									}
									next()
								}
						], next)
					}

					// trust the email.
					async.series([
						async.apply(User.setUserField, uid, 'baitedaid', baitedaID),
							async.apply(db.setObjectField, 'baitedaid:uid', baitedaID, uid),
								checkEmail,
								mergeUserData
					], function (err) {
						callback(err, {
							uid: uid
						})
					})
				}

				User.getUidByEmail(email, function (err, uid) {
					console.log(email);
					if (!uid) {
						// Abort user creation if registration via SSO is restricted
						if (baiteda.settings.disableRegistration === 'on') {
							return callback(new Error('[[error:sso-registration-disabled, baiteda]]'))
						}

						User.create({
							username: username,
							email: email
						}, function (err, uid) {
							if (err !== null) {
								callback(err)
							} else {
								console.log(uid);
								success(uid)
							}
						})
					} else {
						success(uid) // Existing account -- merge
					}
				})
			}
		})
	}

	baiteda.getUidBybaitedaID = function (baitedaID, callback) {
		console.log(baitedaID);
		db.getObjectField('baitedaid:uid', baitedaID, function (err, uid) {
			if (err) {
				callback(err)
			} else {
				callback(null, uid)
			}
		})
	}

	baiteda.addMenuItem = function (custom_header, callback) {
		custom_header.authentication.push({
			'route': constants.admin.route,
			'icon': constants.admin.icon,
			'name': constants.name
		})

		callback(null, custom_header)
	}

	baiteda.init = function (data, callback) {
		var hostHelpers = require.main.require('./src/routes/helpers')

		function renderAdmin(req, res) {
			res.render('admin/plugins/sso-baiteda', {
				callbackURL: domain + '/auth/baiteda/callback'
			})
		}

		data.router.get('/admin/plugins/sso-baiteda', data.middleware.admin.buildHeader, renderAdmin)
		data.router.get('/api/admin/plugins/sso-baiteda', renderAdmin)

		hostHelpers.setupPageRoute(data.router, '/deauth/baiteda', data.middleware, [data.middleware.requireUser], function (req, res) {
			res.render('plugins/sso-baiteda/deauth', {
				service: 'baiteda',
			})
		})
		data.router.post('/deauth/baiteda', [data.middleware.requireUser, data.middleware.applyCSRF], function (req, res, next) {
			baiteda.deleteUserData({
				uid: req.user.uid,
			}, function (err) {
				if (err) {
					return next(err)
				}

				res.redirect(nconf.get('relative_path') + '/me/edit')
			})
		})

		callback()
	}

	baiteda.deleteUserData = function (data, callback) {
		var uid = data.uid

		async.waterfall([
			async.apply(User.getUserField, uid, 'baitedaid'),
				function (oAuthIdToDelete, next) {
					db.deleteObjectField('baitedaid:uid', oAuthIdToDelete, next)
				},
				async.apply(db.deleteObjectField, 'user:' + uid, 'baitedaid'),
		], function (err) {
			if (err) {
				winston.error('[sso-baiteda] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err)
				return callback(err)
			}
			callback(null, uid)
		})
	}

	module.exports = baiteda
}(module))