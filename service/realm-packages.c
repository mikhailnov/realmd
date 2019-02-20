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

#include "realm-diagnostics.h"
#include "realm-daemon.h"
#include "realm-errors.h"
#include "realm-invocation.h"
#include "realm-options.h"
#include "realm-packages.h"
#include "realm-settings.h"

#include <glib/gi18n.h>

#define CALL_TIMEOUT (24 * 60 * 60 * 1000)

static gboolean
packages_check_paths (const gchar **paths,
                            GDBusMethodInvocation *invocation)
{
	gint i;

	g_return_val_if_fail (paths != NULL, FALSE);
	g_return_val_if_fail (invocation == NULL || G_IS_DBUS_METHOD_INVOCATION (invocation), FALSE);

	for (i = 0; paths[i] != NULL; i++) {
		if (!g_file_test (paths[i], G_FILE_TEST_EXISTS)) {
			realm_diagnostics_info (invocation, "Couldn't find file: %s", paths[i]);
			return FALSE;
		}
	}

	return TRUE;
}

static gchar *
packages_to_list (gchar **package_ids)
{
	GString *string;
	gchar **parts;
	gint i;

	string = g_string_new ("");
	for (i = 0; package_ids != NULL && package_ids[i] != NULL; i++) {
		parts = g_strsplit (package_ids[i], ";", 2);
		if (string->len)
			g_string_append (string, " ");
		g_string_append (string, parts[0]);
		g_strfreev (parts);
	}

	return g_string_free (string, FALSE);
}

typedef struct {
    GDBusConnection *connection;
    guint subscription;
    gchar *path;

    /* The method call */
    const gchar *method;
    GVariant *parameters;

    /* Package IDs seen when resolving */
    GHashTable *packages;

    GVariant *error_code;
} PackageTransaction;

static void
package_transaction_free (gpointer data)
{
	PackageTransaction *transaction = data;

	g_debug ("packages: freeing transtaction");

	if (transaction->subscription) {
		g_dbus_connection_signal_unsubscribe (transaction->connection,
		                                      transaction->subscription);
	}
	g_object_unref (transaction->connection);
	g_free (transaction->path);
	if (transaction->packages)
		g_hash_table_unref (transaction->packages);
	if (transaction->parameters)
		g_variant_unref (transaction->parameters);
	if (transaction->error_code)
		g_variant_unref (transaction->error_code);
	g_free (transaction);
}

static void
on_transaction_signal (GDBusConnection *connection,
                       const gchar *sender_name,
                       const gchar *object_path,
                       const gchar *interface_name,
                       const gchar *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PackageTransaction *transaction = g_task_get_task_data (task);
	const gchar *message;
	const gchar *id;
	const gchar *pos;
	guint code, percent;
	gboolean installed;
	gchar *package;
	gchar *string;

	g_debug ("packages: signal: %s %s", signal_name,
	         string = g_variant_print (parameters, FALSE));
	g_free (string);

	if (g_str_equal (signal_name, "ErrorCode")) {
		if (transaction->error_code)
			g_variant_unref (transaction->error_code);
		transaction->error_code = g_variant_ref (parameters);

	} else if (g_str_equal (signal_name, "Finished")) {
		g_dbus_connection_signal_unsubscribe (connection, transaction->subscription);
		transaction->subscription = 0;
		if (!g_task_had_error (task)) {
			if (transaction->error_code) {
				g_variant_get (transaction->error_code, "(u&s)", &code, &message);
				g_task_return_new_error (task, REALM_ERROR, REALM_ERROR_FAILED, "%s", message);
			} else {
				g_task_return_boolean (task, TRUE);
			}
		}
		g_object_unref (task);

	} else if (g_str_equal (signal_name, "Package")) {
		g_variant_get (parameters, "(u&s&s)", &code, &id, &message);

		if (!transaction->packages) {
			transaction->packages = g_hash_table_new_full (g_str_hash, g_str_equal,
			                                               g_free, g_free);
		}
		pos = strchr (id, ';');
		if (pos == NULL)
			pos = id + strlen (id);

		installed = (code == 1 /* PK_INFO_ENUM_INSTALLED */);
		package = g_strndup (id, pos - id);

		if (installed)
			id = "";

		if (installed || !g_hash_table_lookup (transaction->packages, package)) {
			g_hash_table_replace (transaction->packages, package, g_strdup (id));
			package = NULL;
		}

		g_free (package);

	} else if (g_str_equal (signal_name, "ItemProgress")) {
		g_variant_get (parameters, "(&suu)", &id, &code, &percent);
		g_debug ("packages: progress: %s %u %u", id, code, code);
	}
}

static void
on_method_done (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PackageTransaction *transaction = g_task_get_task_data (task);
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (error != NULL) {
		g_debug ("packages: call %s failed: %s", transaction->method, error->message);
		g_task_return_error (task, error);
	} else {
		g_debug ("packages: call %s completed", transaction->method);
		g_variant_unref (retval);
	}

	/* Not done until Finished signal */

	g_object_unref (task);
}

static void
on_set_hints (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PackageTransaction *transaction;
	GError *error = NULL;
	GVariant *retval;
	gchar *string;

	transaction = g_task_get_task_data (task);
	retval = g_dbus_connection_call_finish (transaction->connection, result, &error);

	if (error != NULL) {
		g_debug ("packages: call SetHints failed: %s", error->message);
		g_task_return_error (task, error);

	} else {
		g_variant_unref (retval);

		g_debug ("packages: call %s %s", transaction->method,
		         string = g_variant_print (transaction->parameters, FALSE));
		g_dbus_connection_call (transaction->connection,
		                        "org.freedesktop.PackageKit",
		                        transaction->path,
		                        "org.freedesktop.PackageKit.Transaction",
		                        transaction->method,
		                        transaction->parameters,
		                        G_VARIANT_TYPE ("()"),
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        CALL_TIMEOUT, g_task_get_cancellable (task),
		                        on_method_done, g_object_ref (task));
	}

	g_object_unref (task);
}

static void
on_create_transaction (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	PackageTransaction *transaction;
	GError *error = NULL;
	GVariant *retval;

	const gchar *hints[] = { "interactive=false", "background=false", NULL };

	transaction = g_task_get_task_data (task);
	retval = g_dbus_connection_call_finish (transaction->connection, result, &error);

	if (error != NULL) {
		g_debug ("packages: CreateTransaction failed: %s", error->message);
		g_task_return_error (task, error);

	} else {
		g_variant_get (retval, "(o)", &transaction->path);
		g_variant_unref (retval);

		transaction->subscription =
			g_dbus_connection_signal_subscribe (transaction->connection,
			                                    "org.freedesktop.PackageKit",
			                                    "org.freedesktop.PackageKit.Transaction",
			                                    NULL,
			                                    transaction->path,
			                                    NULL,
			                                    G_DBUS_SIGNAL_FLAGS_NONE,
			                                    on_transaction_signal,
			                                    task, NULL);

		g_debug ("packages: SetHints call");
		g_dbus_connection_call (transaction->connection,
		                        "org.freedesktop.PackageKit",
		                        transaction->path,
		                        "org.freedesktop.PackageKit.Transaction",
		                        "SetHints",
		                        g_variant_new ("(^as)", hints),
		                        G_VARIANT_TYPE ("()"),
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        CALL_TIMEOUT, g_task_get_cancellable (task),
		                        on_set_hints, g_object_ref (task));
	}

	g_object_unref (task);
}

static void
package_transaction_create (const gchar *method,
                            GVariant *parameters,
                            GDBusConnection *connection,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	PackageTransaction *transaction;
	GTask *task;

	task = g_task_new (NULL, cancellable, callback, user_data);
	transaction = g_new0 (PackageTransaction, 1);
	transaction->method = method;
	transaction->parameters = g_variant_ref_sink (parameters);
	transaction->connection = g_object_ref (connection);
	g_task_set_task_data (task, transaction, package_transaction_free);

	g_debug ("packages: CreateTransaction call");

	g_dbus_connection_call (connection, "org.freedesktop.PackageKit",
	                        "/org/freedesktop/PackageKit",
	                        "org.freedesktop.PackageKit",
	                        "CreateTransaction",
	                        g_variant_new ("()"),
	                        G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        CALL_TIMEOUT, cancellable,
	                        on_create_transaction, g_object_ref (task));
}

static void
packages_install_async (GDBusConnection *connection,
                        const gchar **package_ids,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	guint64 transaction_flags = 1 /* PK_TRANSACTION_FLAG_ENUM_ONLY_TRUSTED */;
	package_transaction_create ("InstallPackages", g_variant_new ("(t^as)", transaction_flags, package_ids),
	                            connection, cancellable, callback, user_data);
}

static gboolean
packages_install_finish (GAsyncResult *result,
                         GError **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
packages_resolve_async (GDBusConnection *connection,
                        const gchar **package_names,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	guint64 flags = 1 << 18 /* PK_FILTER_ENUM_ARCH */;
	flags |= 1 << 16 /* PK_FILTER_ENUM_NEWEST */;
	package_transaction_create ("Resolve", g_variant_new ("(t^as)", flags, package_names),
	                            connection, cancellable, callback, user_data);
}

static gchar **
packages_resolve_finish (GAsyncResult *result,
                         GError **error)
{
	GTask *task = G_TASK (result);
	PackageTransaction *transaction;
	gchar **requested;
	GPtrArray *packages;
	GHashTableIter iter;
	guint64 flags;
	gchar *missing;
	gchar *id;
	gint i;

	if (!g_task_propagate_boolean (task, error))
		return NULL;

	transaction = g_task_get_task_data (task);
	g_variant_get (transaction->parameters, "(t^a&s)", &flags, &requested);

	/*
	 * In an unexpected move, Resolve() does not fail or provide
	 * any feedback when a requested package does not exist.
	 *
	 * So we make a note of the ones we requested here, to compare against
	 * what we get back.
	 */

	packages = g_ptr_array_new ();
	for (i = 0; requested[i] != NULL; i++) {
		if (!g_hash_table_lookup (transaction->packages, requested[i]))
			g_ptr_array_add (packages, requested[i]);
	}

	missing = NULL;
	if (packages->len) {
		g_ptr_array_add (packages, NULL);
		missing = packages_to_list ((gchar **)packages->pdata);
		g_set_error (error, REALM_ERROR, REALM_ERROR_INTERNAL,
		             _("The following packages are not available for installation: %s"), missing);
		g_free (missing);
	}
	g_ptr_array_free (packages, TRUE);

	if (missing) {
		return NULL;
	}

	packages = g_ptr_array_new ();
	g_hash_table_iter_init (&iter, transaction->packages);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *)&id)) {
		if (!g_str_equal (id, "")) {
			g_hash_table_iter_steal (&iter);
			g_ptr_array_add (packages, id);
		}
	}

	g_ptr_array_add (packages, NULL);
	return (gchar **)g_ptr_array_free (packages, FALSE);
}

typedef struct {
	GDBusConnection *connection;
	GDBusMethodInvocation *invocation;
	gchar **packages;
	gboolean automatic;
} InstallClosure;

static void
install_closure_free (gpointer data)
{
	InstallClosure *install = data;
	g_clear_object (&install->invocation);
	g_clear_object (&install->connection);
	g_strfreev (install->packages);
	g_free (install);
}

static void
on_install_installed (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	packages_install_finish (result, &error);
	if (error == NULL) {
		g_task_return_boolean (task, TRUE);
	} else {
		g_task_return_error (task, error);
	}

	g_object_unref (task);
}

static void
on_install_resolved (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	InstallClosure *install = g_task_get_task_data (task);
	gchar **package_ids = NULL;
	GHashTable *names;
	GCancellable *cancellable;
	GError *error = NULL;
	gchar *remote;
	gchar *missing;

	names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	package_ids = packages_resolve_finish (result, &error);

	if (error == NULL) {
		missing = packages_to_list (package_ids);
		if (package_ids == NULL || *package_ids == NULL) {
			g_task_return_boolean (task, TRUE);

		} else if (!install->automatic) {
			g_set_error (&error, REALM_ERROR, REALM_ERROR_FAILED,
			             _("Necessary packages are not installed: %s"), missing);

		} else {

			/* String should match that in realm-client.c */
			realm_diagnostics_info (install->invocation, "%s: %s",
			                        _("Installing necessary packages"), missing);
			cancellable = realm_invocation_get_cancellable (install->invocation);
			packages_install_async (install->connection,
			                        (const gchar **)package_ids, cancellable,
			                        on_install_installed, g_object_ref (task));
		}

		g_free (missing);
	}

	if (error != NULL) {
		/*
		 * This is after our first interaction with package-kit. If it's
		 * not installed then we'll get a standard DBus error that it
		 * couldn't activate the service.
		 *
		 * So translate that into something useful for the caller. If
		 * PackageKit is not installed, then it is assumed that the
		 * distro or administrator wants to take full control over the
		 * installation of packages.
		 */
		if (error->domain == G_DBUS_ERROR) {
			remote = g_dbus_error_get_remote_error (error);
			if (remote && g_str_equal (remote, "org.freedesktop.DBus.Error.ServiceUnknown")) {
				g_dbus_error_strip_remote_error (error);
				realm_diagnostics_error (install->invocation, error, "PackageKit not available");
				g_clear_error (&error);
				missing = packages_to_list (install->packages);
				g_set_error (&error, REALM_ERROR, REALM_ERROR_FAILED,
				             _("Necessary packages are not installed: %s"), missing);
				g_free (missing);
			}
			g_free (remote);
		}

		g_task_return_error (task, error);
	}

	g_hash_table_unref (names);
	g_strfreev (package_ids);
	g_object_unref (task);
}

static void
lookup_required_files_and_packages (const gchar **package_sets,
                                    gchar ***result_packages,
                                    gchar ***result_files,
                                    gboolean *result_unconditional)
{
	GHashTable *settings;
	GHashTableIter iter;
	GPtrArray *packages;
	GPtrArray *files;
	gboolean unconditional;
	gchar *section;
	gchar *package;
	gchar *file;
	gint i;

	unconditional = FALSE;
	packages = g_ptr_array_new_with_free_func (g_free);
	files = g_ptr_array_new_with_free_func (g_free);

	for (i = 0; package_sets[i] != NULL; i++) {
		section = g_strdup_printf ("%s-packages", package_sets[i]);
		settings = realm_settings_section (section);
		if (settings == NULL) {
			g_critical ("No section found in settings: %s", section);
			return;
		}
		g_free (section);

		g_hash_table_iter_init (&iter, settings);
		while (g_hash_table_iter_next (&iter, (gpointer *)&package, (gpointer *)&file)) {
			file = g_strstrip (g_strdup (file));
			if (g_str_equal (file, "")) {
				g_free (file);
				unconditional = TRUE;
			} else {
				g_ptr_array_add (files, file);
			}
			package = g_strstrip (g_strdup (package));
			if (g_str_equal (package, ""))
				g_free (package);
			else
				g_ptr_array_add (packages, package);
		}
	}

	if (result_packages) {
		g_ptr_array_add (packages, NULL);
		*result_packages = (gchar **)g_ptr_array_free (packages, FALSE);
	} else {
		g_ptr_array_free (packages, TRUE);
	}

	if (result_files) {
		g_ptr_array_add (files, NULL);
		*result_files = (gchar **)g_ptr_array_free (files, FALSE);
	} else {
		g_ptr_array_free (files, TRUE);
	}

	if (result_unconditional)
		*result_unconditional = unconditional;
}

gchar **
realm_packages_expand_sets (const gchar **package_sets)
{
	gchar **packages = NULL;

	g_return_val_if_fail (package_sets != NULL, NULL);

	lookup_required_files_and_packages (package_sets, &packages, NULL, NULL);
	return packages;
}

void
realm_packages_install_async (const gchar **package_sets,
                              GDBusMethodInvocation *invocation,
                              GDBusConnection *connection,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GTask *task;
	InstallClosure *install;
	gboolean unconditional;
	gchar **required_files;
	GCancellable *cancellable;
	gchar *string;
	gboolean have;

	g_return_if_fail (package_sets != NULL);
	g_return_if_fail (G_IS_DBUS_CONNECTION (connection));

	task = g_task_new (NULL, NULL, callback, user_data);
	install = g_new0 (InstallClosure, 1);
	install->automatic = realm_options_automatic_install ();
	install->invocation = invocation ? g_object_ref (invocation) : NULL;
	install->connection = g_object_ref (connection);
	g_task_set_task_data (task, install, install_closure_free);

	lookup_required_files_and_packages (package_sets, &install->packages, &required_files, &unconditional);

	if (realm_daemon_is_install_mode ()) {
		have = TRUE;
		realm_diagnostics_info (invocation, "Assuming packages are installed");

	} else if (unconditional) {
		have = FALSE;
		realm_diagnostics_info (invocation, "Unconditionally checking packages");

	} else {
		have = packages_check_paths ((const gchar **)required_files, invocation);
		if (required_files[0] != NULL) {
			string = g_strjoinv (", ", required_files);
			realm_diagnostics_info (invocation, "Required files: %s", string);
			g_free (string);
		}
	}

	g_strfreev (required_files);

	if (have) {
		g_task_return_boolean (task, TRUE);

	} else {
		realm_diagnostics_info (invocation, "Resolving required packages");

		cancellable = realm_invocation_get_cancellable (install->invocation);
		packages_resolve_async (connection, (const gchar **)install->packages, cancellable,
		                        on_install_resolved, g_object_ref (task));
	}

	g_object_unref (task);
}

gboolean
realm_packages_install_finish (GAsyncResult *result,
                               GError **error)
{
	if (g_task_propagate_boolean (G_TASK (result), error))
		return FALSE;

	return TRUE;
}
