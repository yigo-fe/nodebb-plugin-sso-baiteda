define('admin/plugins/sso-baiteda', ['settings'], function (Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function () {
		Settings.load('sso-baiteda', $('.sso-baiteda-settings'));

		$('#save').on('click', function () {
			Settings.save('sso-baiteda', $('.sso-baiteda-settings'), function () {
				app.alert({
					type: 'success',
					alert_id: 'sso-baiteda-saved',
					title: 'Settings Saved',
					message: 'Please reload your NodeBB to apply these settings',
					clickfn: function () {
						socket.emit('admin.reload');
					}
				});
			});
		});
	};

	return ACP;
});