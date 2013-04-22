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

#include "egg-task.h"
#include "realm-command.h"
#include "realm-daemon.h"
#include "realm-dbus-constants.h"
#include "realm-diagnostics.h"
#include "realm-discovery.h"
#include "realm-errors.h"
#include "realm-kerberos-discover.h"
#include "realm-options.h"
#include "realm-samba-config.h"
#include "realm-samba-enroll.h"
#include "realm-samba-provider.h"
#include "realm-samba-util.h"
#include "realm-settings.h"

#include <glib/gstdio.h>

#include <ldap.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>

typedef struct {
	GDBusMethodInvocation *invocation;
	gchar *join_args[5];
	gchar *realm;
	gchar *user_name;
	GBytes *password_input;
	RealmIniConfig *config;
	gchar *custom_smb_conf;
	gchar *envvar;
} JoinClosure;

static void
join_closure_free (gpointer data)
{
	JoinClosure *join = data;
	int i;

	g_bytes_unref (join->password_input);
	g_free (join->user_name);
	for (i = 0; i < G_N_ELEMENTS (join->join_args); i++)
		g_free (join->join_args[i]);
	g_free (join->realm);
	g_free (join->envvar);
	g_clear_object (&join->invocation);
	g_clear_object (&join->config);

	if (join->custom_smb_conf) {
		g_unlink (join->custom_smb_conf);
		g_free (join->custom_smb_conf);
	}

	g_slice_free (JoinClosure, join);
}

static JoinClosure *
join_closure_init (EggTask *task,
                   const gchar *realm,
                   GDBusMethodInvocation *invocation)
{
	JoinClosure *join;
	GError *error = NULL;
	int temp_fd;

	join = g_slice_new0 (JoinClosure);
	join->realm = g_strdup (realm);
	join->invocation = invocation ? g_object_ref (invocation) : NULL;
	egg_task_set_task_data (task, join, join_closure_free);

	join->config = realm_ini_config_new (REALM_INI_NO_WATCH | REALM_INI_PRIVATE);
	realm_ini_config_set (join->config, REALM_SAMBA_CONFIG_GLOBAL,
	                      "security", "ads",
	                      "kerberos method", "system keytab",
	                      "realm", join->realm,
	                      NULL);

	/* Write out the config file for use by various net commands */
	join->custom_smb_conf = g_build_filename (g_get_tmp_dir (), "realmd-smb-conf.XXXXXX", NULL);
	temp_fd = g_mkstemp_full (join->custom_smb_conf, O_WRONLY, S_IRUSR | S_IWUSR);
	if (temp_fd != -1) {
		if (realm_ini_config_write_fd (join->config, temp_fd, &error)) {
			realm_ini_config_set_filename (join->config, join->custom_smb_conf);

		} else {
			g_warning ("couldn't write to a temp file: %s: %s", join->custom_smb_conf, error->message);
			g_error_free (error);
		}

		close (temp_fd);
	}

	return join;
}

static void
begin_net_process (JoinClosure *join,
                   GBytes *input,
                   GAsyncReadyCallback callback,
                   gpointer user_data,
                   ...) G_GNUC_NULL_TERMINATED;

static void
begin_net_process (JoinClosure *join,
                   GBytes *input,
                   GAsyncReadyCallback callback,
                   gpointer user_data,
                   ...)
{
	char *env[] = { "LANG=C", join->envvar, NULL };
	GPtrArray *args;
	gchar *arg;
	va_list va;

	args = g_ptr_array_new ();

	/* Use our custom smb.conf */
	g_ptr_array_add (args, (gpointer)realm_settings_path ("net"));
	if (join->custom_smb_conf) {
		g_ptr_array_add (args, "-s");
		g_ptr_array_add (args, join->custom_smb_conf);
	}

	va_start (va, user_data);
	do {
		arg = va_arg (va, gchar *);
		g_ptr_array_add (args, arg);
	} while (arg != NULL);
	va_end (va);

	realm_command_runv_async ((gchar **)args->pdata, env, input,
	                          join->invocation, callback, user_data);

	g_ptr_array_free (args, TRUE);
}

static void
on_keytab_do_finish (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	GError *error = NULL;
	gint status;

	status = realm_command_run_finish (result, NULL, &error);
	if (error == NULL && status != 0)
		g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             "Extracting host keytab failed");

	if (error != NULL)
		egg_task_return_error (task, error);
	else
		egg_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_join_do_keytab (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	JoinClosure *join = egg_task_get_task_data (task);
	GError *error = NULL;
	GString *output = NULL;
	gint status;

	status = realm_command_run_finish (result, &output, &error);
	if (error == NULL && status != 0) {

		/*
		 * This is bad and ugly. We run the process with LC_ALL=C so
		 * at least we know these messages will be in english.
		 *
		 * At first I thought this was a deficiency in samba's 'net'
		 * command. It's true that 'net' could be better at returning
		 * different error codes for different types of failures.
		 *
		 * But in the end this is a deficiency in Windows. When you use
		 * LDAP to do enrollment, and the permissions aren't correct
		 * it often returns stupid errors such as 'Constraint violation'
		 * or 'Object class invalid' instead of 'Insufficient access'.
		 */
		if (g_pattern_match_simple ("*NT_STATUS_ACCESS_DENIED*", output->str) ||
		    g_pattern_match_simple ("*failed*: Constraint violation*", output->str) ||
		    g_pattern_match_simple ("*failed*: Object class violation*", output->str) ||
		    g_pattern_match_simple ("*failed*: Insufficient access*", output->str) ||
		    g_pattern_match_simple ("*: Access denied*", output->str) ||
		    g_pattern_match_simple ("*not have administrator privileges*", output->str) ||
		    g_pattern_match_simple ("*failure*: *not been granted the requested logon type*", output->str) ||
		    g_pattern_match_simple ("*failure*: User not allowed to log on to this computer*", output->str) ||
		    g_pattern_match_simple ("*failure*: *specified account is not allowed to authenticate to the machine*", output->str)) {
			g_set_error (&error, REALM_ERROR, REALM_ERROR_AUTH_FAILED,
			             "Insufficient permissions to join the domain %s",
			             join->realm);
		} else if (g_pattern_match_simple ("*: Logon failure*", output->str) ||
		           g_pattern_match_simple ("*: Password expired*", output->str)) {
			g_set_error (&error, REALM_ERROR, REALM_ERROR_AUTH_FAILED,
			             "The %s account, password, or credentials are invalid",
			             join->user_name);
		} else {
			g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
			             "Joining the domain %s failed", join->realm);
		}
	}

	if (output)
		g_string_free (output, TRUE);

	if (error != NULL) {
		egg_task_return_error (task, error);

	/* Do keytab with a user name */
	} else if (join->user_name != NULL) {
		begin_net_process (join, join->password_input,
		                   on_keytab_do_finish, g_object_ref (task),
		                   "-U", join->user_name, "ads", "keytab", "create", NULL);

	/* Do keytab with a ccache file */
	} else {
		begin_net_process (join, NULL,
		                   on_keytab_do_finish, g_object_ref (task),
		                   "-k", "ads", "keytab", "create", NULL);
	}

	g_object_unref (task);
}

static gchar *
fallback_workgroup (const gchar *realm)
{
	const gchar *pos;

	pos = strchr (realm, '.');
	if (pos == NULL)
		return g_utf8_strup (realm, -1);
	else
		return g_utf8_strup (realm, pos - realm);
}

static void
begin_config_and_join (JoinClosure *join,
                       EggTask *task)
{
	GError *error = NULL;
	gchar *workgroup;

	/*
	 * Samba complains if we don't set a 'workgroup' setting for the realm we're
	 * going to join. If we didn't yet manage to lookup the workgroup, then go ahead
	 * and assume that the first domain component is the workgroup name.
	 */
	workgroup = realm_ini_config_get (join->config, REALM_SAMBA_CONFIG_GLOBAL, "workgroup");
	if (workgroup == NULL) {
		workgroup = fallback_workgroup (join->realm);
		realm_diagnostics_info (join->invocation, "Calculated workgroup name: %s", workgroup);
		realm_ini_config_set (join->config, REALM_SAMBA_CONFIG_GLOBAL,
		                      "workgroup", workgroup, NULL);
	}
	free (workgroup);

	/* Write out the config file for various changes */
	realm_ini_config_write_file (join->config, NULL, &error);

	if (error != NULL) {
		egg_task_return_error (task, error);

	/* Do join with a user name */
	} else if (join->user_name) {
		begin_net_process (join, join->password_input,
		                   on_join_do_keytab, g_object_ref (task),
		                   "-U", join->user_name, "ads", "join", join->realm,
		                   join->join_args[0], join->join_args[1],
		                   join->join_args[2], join->join_args[3],
		                   join->join_args[4], NULL);

	/* Do join with a ccache */
	} else {
		begin_net_process (join, NULL,
		                   on_join_do_keytab, g_object_ref (task),
		                   "-k", "ads", "join", join->realm,
		                   join->join_args[0], join->join_args[1],
		                   join->join_args[2], join->join_args[3],
		                   join->join_args[4], NULL);
	}

}

static gchar *
find_workgroup_in_output (GString *output)
{
	const gchar *match = ":";
	const gchar *pos;
	const gchar *end;
	gchar *workgroup;

	/* Beginning */
	pos = g_strstr_len (output->str, output->len, match);
	if (pos == NULL)
		return NULL;
	pos += strlen (match);

	/* Find the end */
	end = strchr (pos, '\n');
	if (end == NULL)
		end = output->str + output->len;

	workgroup = g_strndup (pos, end - pos);
	g_strstrip (workgroup);
	return workgroup;
}

static void
on_net_ads_workgroup (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	JoinClosure *join = egg_task_get_task_data (task);
	GError *error = NULL;
	GString *output = NULL;
	gchar *workgroup;
	gint status;

	status = realm_command_run_finish (result, &output, &error);
	if (error == NULL && status != 0) {
		g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             "Couldn't lookup domain info");
	}

	if (error == NULL) {
		workgroup = find_workgroup_in_output (output);
		if (workgroup) {
			realm_diagnostics_info (join->invocation, "Looked up workgroup name: %s", workgroup);
			realm_ini_config_set (join->config, REALM_SAMBA_CONFIG_GLOBAL,
			                      "workgroup", workgroup, NULL);
			g_free (workgroup);
		}

		g_string_free (output, TRUE);

	} else {
		realm_diagnostics_error (join->invocation, error, NULL);
		g_error_free (error);
	}

	begin_config_and_join (join, task);

	g_object_unref (task);
}


static void
begin_net_lookup (JoinClosure *join,
                  EggTask *task,
                  GHashTable *discovery)
{
	const gchar **kdcs;

	kdcs = realm_discovery_get_strings (discovery, REALM_DBUS_DISCOVERY_KDCS);

	/* If we discovered KDCs then try to ask first one what the workgroup name is */
	if (kdcs && kdcs[0]) {
		begin_net_process (join, NULL,
		                   on_net_ads_workgroup, g_object_ref (task),
		                   "ads", "workgroup", "-S", kdcs[0], NULL);

	} else {
		begin_config_and_join (join, task);
	}
}

static void
on_discover_do_lookup (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	JoinClosure *join = egg_task_get_task_data (task);
	GError *error = NULL;
	GHashTable *discovery;

	realm_kerberos_discover_finish (result, &discovery, &error);
	if (error == NULL) {
		begin_net_lookup (join, task, discovery);
		g_hash_table_unref (discovery);

	} else {
		egg_task_return_error (task, error);
	}

	g_object_unref (task);
}

static void
begin_join (EggTask *task,
            JoinClosure *join,
            const gchar *realm,
            GVariant *options,
            GHashTable *discovery)
{
	const gchar *computer_ou;
	gchar *strange_ou;
	GError *error = NULL;
	const gchar *upn;
	const gchar *os;
	int at = 0;

	computer_ou = realm_options_computer_ou (options, realm);
	if (computer_ou != NULL) {
		strange_ou = realm_samba_util_build_strange_ou (computer_ou, realm);
		if (strange_ou) {
			if (!g_str_equal (strange_ou, ""))
				join->join_args[at++] = g_strdup_printf ("createcomputer=%s", strange_ou);
			g_free (strange_ou);
		} else {
			g_set_error (&error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
			             "The computer-ou argument must be a valid LDAP DN and contain only OU=xxx RDN values.");
		}
	}

	os = realm_settings_value ("active-directory", "os-name");
	if (os != NULL && !g_str_equal (os, ""))
		join->join_args[at++] = g_strdup_printf ("osName=%s", os);

	os = realm_settings_value ("active-directory", "os-version");
	if (os != NULL && !g_str_equal (os, ""))
		join->join_args[at++] = g_strdup_printf ("osVer=%s", os);

	upn = realm_options_user_principal (options, realm);
	if (upn) {
		if (g_str_equal (upn, ""))
			upn = NULL;
		join->join_args[at++] = g_strdup_printf ("createupn%s%s",
		                                         upn ? "=" : "",
		                                         upn ? upn : "");
	}

	g_assert (at < G_N_ELEMENTS (join->join_args));

	if (error != NULL) {
		egg_task_return_error (task, error);

	} else if (discovery) {
		begin_net_lookup (join, task, discovery);

	} else {
		realm_kerberos_discover_async (join->realm, join->invocation,
		                               on_discover_do_lookup, g_object_ref (task));
	}
}

void
realm_samba_enroll_join_async (const gchar *realm,
                               RealmCredential *cred,
                               GVariant *options,
                               GHashTable *discovery,
                               GDBusMethodInvocation *invocation,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	EggTask *task;
	JoinClosure *join;

	g_return_if_fail (realm != NULL);
	g_return_if_fail (cred != NULL);

	task = egg_task_new (NULL, NULL, callback, user_data);
	join = join_closure_init (task, realm, invocation);

	switch (cred->type) {
	case REALM_CREDENTIAL_PASSWORD:
		join->password_input = realm_command_build_password_line (cred->x.password.value);
		join->user_name = g_strdup (cred->x.password.name);
		break;
	case REALM_CREDENTIAL_CCACHE:
		join->envvar = g_strdup_printf ("KRB5CCNAME=%s", cred->x.ccache.file);
		break;
	default:
		g_return_if_reached ();
	}

	begin_join (task, join, realm, options, discovery);

	g_object_unref (task);
}

gboolean
realm_samba_enroll_join_finish (GAsyncResult *result,
                                GHashTable **settings,
                                GError **error)
{
	JoinClosure *join;

	g_return_val_if_fail (egg_task_is_valid (result, NULL), FALSE);

	if (!egg_task_propagate_boolean (EGG_TASK (result), error))
		return FALSE;

	if (settings != NULL) {
		join = egg_task_get_task_data (EGG_TASK (result));
		*settings = realm_ini_config_get_all (join->config, REALM_SAMBA_CONFIG_GLOBAL);
	}

	return TRUE;
}

static void
on_leave_complete (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	JoinClosure *join = egg_task_get_task_data (task);
	GError *error = NULL;
	gint status;

	status = realm_command_run_finish (result, NULL, &error);
	if (error == NULL && status != 0)
		g_set_error (&error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             "Leaving the domain %s failed", join->realm);

	if (error != NULL)
		egg_task_return_error (task, error);
	else
		egg_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

void
realm_samba_enroll_leave_async (const gchar *realm,
                                RealmCredential *cred,
                                GVariant *options,
                                GDBusMethodInvocation *invocation,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	EggTask *task;
	JoinClosure *join;

	task = egg_task_new (NULL, NULL, callback, user_data);
	join = join_closure_init (task, realm, invocation);

	switch (cred->type) {
	case REALM_CREDENTIAL_PASSWORD:
		join->password_input = realm_command_build_password_line (cred->x.password.value);
		join->user_name = g_strdup (cred->x.password.name);
		begin_net_process (join, join->password_input,
		                   on_leave_complete, g_object_ref (task),
		                   "-U", join->user_name, "ads", "leave", NULL);
		break;
	case REALM_CREDENTIAL_CCACHE:
		join->envvar = g_strdup_printf ("KRB5CCNAME=%s", cred->x.ccache.file);
		begin_net_process (join, join->password_input,
		                   on_leave_complete, g_object_ref (task),
		                   "-k", "ads", "leave", NULL);
		break;
	default:
		g_return_if_reached ();
	}


	g_object_unref (task);
}

gboolean
realm_samba_enroll_leave_finish (GAsyncResult *result,
                                 GError **error)
{
	g_return_val_if_fail (egg_task_is_valid (result, NULL), FALSE);
	return egg_task_propagate_boolean (EGG_TASK (result), error);
}
