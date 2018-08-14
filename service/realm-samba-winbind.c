/* realmd -- Realm configuration service
 *
 * Copyright 2012 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "realm-command.h"
#include "realm-daemon.h"
#include "realm-diagnostics.h"
#include "realm-errors.h"
#include "realm-options.h"
#include "realm-samba-config.h"
#include "realm-samba-winbind.h"
#include "realm-samba-enroll.h"
#include "realm-settings.h"
#include "realm-service.h"
#include "dbus/realm-dbus-constants.h"

#include <glib/gstdio.h>

#include <errno.h>

static void
on_nss_complete (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	gint status;

	status = realm_command_run_finish (result, NULL, &error);
	if (error == NULL && status != 0)
		g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             "Enabling winbind in nsswitch.conf and pam failed");
	if (error != NULL)
		g_task_return_error (task, error);
	else
		g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_enable_do_nss (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GDBusMethodInvocation *invocation = g_task_get_task_data (task);
	GError *error = NULL;

	realm_service_enable_and_restart_finish (result, &error);
	if (error == NULL) {
		realm_command_run_known_async ("winbind-enable-logins", NULL, invocation,
		                               on_nss_complete, g_object_ref (task));

	} else {
		g_task_return_error (task, error);
	}

	g_object_unref (task);
}

void
realm_samba_winbind_configure_async (RealmIniConfig *config,
                                     const gchar *domain_name,
                                     GVariant *options,
                                     GDBusMethodInvocation *invocation,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	RealmIniConfig *pwc;
	GTask *task;
	GError *error = NULL;
	gchar *workgroup = NULL;
	gchar *idmap_config_backend = NULL;
	gchar *idmap_config_range = NULL;
	gchar *idmap_config_schema_mode = NULL;

	g_return_if_fail (config != NULL);
	g_return_if_fail (invocation != NULL || G_IS_DBUS_METHOD_INVOCATION (invocation));

	task = g_task_new (NULL, NULL, callback, user_data);
	if (invocation != NULL)
		g_task_set_task_data (task, g_object_ref (invocation), g_object_unref);

	/* TODO: need to use autorid mapping */

	if (realm_ini_config_begin_change(config, &error)) {
		realm_ini_config_set (config, REALM_SAMBA_CONFIG_GLOBAL,
		                      "winbind enum users", "no",
		                      "winbind enum groups", "no",
		                      "winbind offline logon", "yes",
		                      "winbind refresh tickets", "yes",
		                      "winbind use default domain", realm_options_qualify_names (domain_name, TRUE )? "no" : "yes",
		                      "template shell", realm_settings_string ("users", "default-shell"),
		                      NULL);

		if (realm_settings_boolean ("service", REALM_DBUS_OPTION_LEGACY_SMB_CONF, FALSE)) {
			if (realm_options_automatic_mapping (options, domain_name)) {
				realm_ini_config_set (config, REALM_SAMBA_CONFIG_GLOBAL,
						      "idmap uid", "10000-2000000",
						      "idmap gid", "10000-2000000",
						      "idmap backend", "tdb",
						      "idmap schema", NULL,
						      NULL);
			} else {
				realm_ini_config_set (config, REALM_SAMBA_CONFIG_GLOBAL,
						      "idmap uid", "500-4294967296",
						      "idmap gid", "500-4294967296",
						      "idmap backend", "ad",
						      "idmap schema", "rfc2307",
						      NULL);
			}
		} else {
			workgroup = realm_ini_config_get (config, REALM_SAMBA_CONFIG_GLOBAL, "workgroup");
			if (workgroup == NULL) {
				workgroup = fallback_workgroup (domain_name);
			}
			idmap_config_backend = g_strdup_printf ("idmap config %s : backend", workgroup != NULL ? workgroup : "PLEASE_REPLACE");
			idmap_config_range = g_strdup_printf ("idmap config %s : range", workgroup != NULL ? workgroup : "PLEASE_REPLACE");
			idmap_config_schema_mode = g_strdup_printf ("idmap config %s : schema_mode", workgroup != NULL ? workgroup : "PLEASE_REPLACE");
			g_free (workgroup);

			if (realm_options_automatic_mapping (options, domain_name)) {
				realm_ini_config_set (config, REALM_SAMBA_CONFIG_GLOBAL,
						      "idmap config * : backend", "tdb",
						      "idmap config * : range", "10000-999999",
						      idmap_config_backend != NULL ? idmap_config_backend : "idmap config PLEASE_REPLACE : backend", "rid",
						      idmap_config_range != NULL ? idmap_config_range: "idmap config PLEASE_REPLACE : range", "2000000-2999999",
						      idmap_config_schema_mode != NULL ? idmap_config_schema_mode: "idmap config PLEASE_REPLACE : schema_mode", NULL,
						      NULL);
			} else {
				realm_ini_config_set (config, REALM_SAMBA_CONFIG_GLOBAL,
						      "idmap config * : backend", "tdb",
						      "idmap config * : range", "10000000-10999999",
						      idmap_config_backend != NULL ? idmap_config_backend : "idmap config PLEASE_REPLACE : backend", "ad",
						      idmap_config_range != NULL ? idmap_config_range: "idmap config PLEASE_REPLACE : range", "500-999999",
						      idmap_config_schema_mode != NULL ? idmap_config_schema_mode: "idmap config PLEASE_REPLACE : schema_mode", "rfc2307",
						      NULL);
			}
		}

		realm_ini_config_finish_change (config, &error);
		g_free (idmap_config_backend);
		g_free (idmap_config_range);
	}

	/* Setup pam_winbind.conf with decent defaults matching our expectations */
	if (error == NULL) {
		pwc = realm_ini_config_new (REALM_INI_NO_WATCH);
		realm_ini_config_set_filename (pwc, realm_settings_path ("pam_winbind.conf"));
		realm_ini_config_change (pwc, "global", &error,
		                         "krb5_auth", "yes",
		                         "krb5_ccache_type", "FILE",
		                         "cached_login", "yes",
		                         NULL);
		g_object_unref (pwc);
	}

	if (error == NULL) {
		realm_service_enable_and_restart ("winbind", invocation,
		                                  on_enable_do_nss, g_object_ref (task));
	} else {
		g_task_return_error (task, error);
	}

	g_object_unref (task);
}

gboolean
realm_samba_winbind_configure_finish (GAsyncResult *result,
                                      GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, NULL), FALSE);
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
on_disable_complete (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	realm_service_disable_and_stop_finish (result, &error);
	if (error != NULL)
		g_task_return_error (task, error);
	else
		g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_nss_do_disable (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GDBusMethodInvocation *invocation = g_task_get_task_data (task);
	GError *error = NULL;
	gint status;

	status = realm_command_run_finish (result, NULL, &error);
	if (error == NULL && status != 0)
		g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             "Disabling winbind in /etc/nsswitch.conf failed");
	if (error == NULL) {
		realm_service_disable_and_stop ("winbind", invocation,
		                                on_disable_complete, g_object_ref (task));
	} else {
		g_task_return_error (task, error);
	}

	g_object_unref (task);
}

void
realm_samba_winbind_deconfigure_async (RealmIniConfig *config,
                                       GDBusMethodInvocation *invocation,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GTask *task;

	g_return_if_fail (config != NULL);
	g_return_if_fail (invocation != NULL || G_IS_DBUS_METHOD_INVOCATION (invocation));

	task = g_task_new (NULL, NULL, callback, user_data);
	if (invocation != NULL)
		g_task_set_task_data (task, g_object_ref (invocation), g_object_unref);

	realm_command_run_known_async ("winbind-disable-logins", NULL, invocation,
	                               on_nss_do_disable, g_object_ref (task));

	g_object_unref (task);
}

gboolean
realm_samba_winbind_deconfigure_finish (GAsyncResult *result,
                                        GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, NULL), FALSE);
	return g_task_propagate_boolean (G_TASK (result), error);

}
