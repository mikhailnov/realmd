/* realmd -- Realm configuration service
 *
 * Copyright 2012 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) all later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "realm-all-provider.h"
#include "realm-daemon.h"
#define DEBUG_FLAG REALM_DEBUG_PROVIDER
#include "realm-debug.h"
#include "realm-diagnostics.h"
#include "realm-errors.h"
#include "realm-dbus-constants.h"
#include "realm-dbus-generated.h"
#include "realm-provider.h"

#include <glib/gstdio.h>

#include <errno.h>
#include <string.h>

typedef struct {
	GDBusProxy *proxy;
	guint diagnostics_sig;
} ProviderProxy;

struct _RealmAllProvider {
	RealmProvider parent;
	GList *providers;
	GHashTable *invocations;
};

typedef struct {
	RealmProviderClass parent_class;
} RealmAllProviderClass;

static guint operation_unique_id = 0;

#define   REALM_DBUS_ALL_PROVIDER_NAME             "org.freedesktop.realmd"
#define   REALM_DBUS_ALL_PROVIDER_PATH             "/org/freedesktop/realmd"

static void realm_all_provider_async_initable_iface (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (RealmAllProvider, realm_all_provider, REALM_TYPE_PROVIDER,
	G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, realm_all_provider_async_initable_iface);
);

static void
realm_all_provider_init (RealmAllProvider *self)
{
	self->invocations = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, g_object_unref);

	/* The dbus Name property of the provider */
	g_object_set (self, "name", "All", NULL);
}

static gboolean
provider_load (const gchar *filename,
               gchar **name,
               gchar **path)
{
	gboolean ret = TRUE;
	GError *error = NULL;
	GKeyFile *key_file;

	g_assert (name != NULL);
	g_assert (path != NULL);

	*name = NULL;
	*path = NULL;

	key_file = g_key_file_new ();
	g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, &error);
	if (error == NULL)
		*name = g_key_file_get_string (key_file, "provider", "name", &error);
	if (error == NULL)
		*path = g_key_file_get_string (key_file, "provider", "path", &error);
	if (error == NULL && (!g_dbus_is_name (*name) || g_dbus_is_unique_name (*name)))
		g_set_error (&error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
		             "Invalid DBus name: %s", *name);
	if (error == NULL && !g_variant_is_object_path (*path)) {
		g_set_error (&error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
		             "Invalid DBus object path: %s", *path);
	}

	if (error != NULL) {
		g_warning ("Couldn't load provider information from: %s: %s",
		           filename, error->message);
		g_error_free (error);
		g_free (*name);
		g_free (*path);
		*name = *path = NULL;
		ret = FALSE;
	}

	g_key_file_free (key_file);
	return ret;
}

static GVariant *
reduce_array (GQueue *input,
              const gchar *array_sig)
{
	GVariantBuilder builder;
	GVariant *element;
	GVariant *array;
	GVariantIter iter;

	g_variant_builder_init (&builder, G_VARIANT_TYPE (array_sig));

	for (;;) {
		array = g_queue_pop_head (input);
		if (!array)
			break;
		g_variant_iter_init (&iter, array);
		for (;;) {
			element = g_variant_iter_next_value (&iter);
			if (!element)
				break;
			g_variant_builder_add_value (&builder, element);
			g_variant_unref (element);
		}
		g_variant_unref (array);
	}

	return g_variant_builder_end (&builder);
}

static void
update_realms_property (RealmAllProvider *self)
{
	GQueue realms = G_QUEUE_INIT;
	ProviderProxy *prov;
	GVariant *variant;
	GList *l;

	for (l = self->providers; l != NULL; l = g_list_next (l)) {
		prov = l->data;
		variant = g_dbus_proxy_get_cached_property (prov->proxy, "Realms");
		if (variant)
			g_queue_push_tail (&realms, variant);
	}

	variant = g_variant_ref_sink (reduce_array (&realms, "a(sos)"));
	g_object_set (self, "realms", variant, NULL);
	g_variant_unref (variant);
}

static void
update_all_properties (RealmAllProvider *self)
{
	update_realms_property (self);
}

static void
on_proxy_properties_changed (GDBusProxy *proxy,
                             GVariant   *changed_properties,
                             GStrv       invalidated_properties,
                             gpointer    user_data)
{
	RealmAllProvider *self = REALM_ALL_PROVIDER (user_data);
	update_all_properties (self);
}

typedef struct {
	GDBusMethodInvocation *invocation;
	gchar *operation_id;
	guint timeout_id;
	gboolean completed;
	gint outstanding;
	GQueue failures;
	GQueue results;
	gint relevance;
	GVariant *realms;
} DiscoverClosure;

static void
discover_closure_free (gpointer data)
{
	DiscoverClosure *discover = data;
	g_free (discover->operation_id);
	g_object_unref (discover->invocation);
	while (!g_queue_is_empty (&discover->results))
		g_variant_unref (g_queue_pop_head (&discover->results));
	while (!g_queue_is_empty (&discover->failures))
		g_error_free (g_queue_pop_head (&discover->failures));
	if (discover->realms)
		g_variant_unref (discover->realms);
	if (discover->timeout_id)
		g_source_remove (discover->timeout_id);
	g_slice_free (DiscoverClosure, discover);
}

static gint
compare_relevance (gconstpointer a,
                   gconstpointer b,
                   gpointer user_data)
{
	gint relevance_a = 0;
	gint relevance_b = 0;
	GVariant *realms;

	g_variant_get ((GVariant *)a, "(i@a(sos))", &relevance_a, &realms);
	g_variant_unref (realms);

	g_variant_get ((GVariant *)b, "(i@a(sos))", &relevance_b, &realms);
	g_variant_unref (realms);

	return relevance_b - relevance_a;
}

static void
discover_process_results (GSimpleAsyncResult *res,
                          DiscoverClosure *discover)
{
	gint relevance = 0;
	GError *error;
	GVariant *result;
	GVariant *realms;
	gboolean any = FALSE;
	GPtrArray *results;
	GVariantIter iter;
	GVariant *realm;

	g_queue_sort (&discover->results, compare_relevance, NULL);
	results = g_ptr_array_new_with_free_func ((GDestroyNotify)g_variant_unref);

	for (;;) {
		result = g_queue_pop_head (&discover->results);
		if (result == NULL)
			break;
		g_variant_get (result, "(i@a(sos))", &relevance, &realms);
		g_variant_iter_init (&iter, realms);
		while ((realm = g_variant_iter_next_value (&iter)) != NULL)
			g_ptr_array_add (results, realm);
		if (relevance > discover->relevance)
			discover->relevance = relevance;
		g_variant_unref (realms);
		g_variant_unref (result);
		any = TRUE;
	}

	discover->realms = g_variant_new_array (G_VARIANT_TYPE ("(sos)"),
	                                        (GVariant *const *)results->pdata,
	                                        results->len);
	g_variant_ref_sink (discover->realms);
	g_ptr_array_free (results, TRUE);

	if (!any) {
		/* If there was a failure, return one of them */
		error = g_queue_pop_head (&discover->failures);
		if (error != NULL)
			g_simple_async_result_take_error (res, error);
	}
}

static void
on_proxy_discover (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DiscoverClosure *discover = g_simple_async_result_get_op_res_gpointer (res);
	RealmAllProvider *self = REALM_ALL_PROVIDER (g_async_result_get_source_object (user_data));
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error == NULL)
		g_queue_push_tail (&discover->results, retval);
	else
		g_queue_push_tail (&discover->failures, error);

	g_assert (discover->outstanding > 0);
	discover->outstanding--;

	/* All done at this point? */
	if (!discover->completed && discover->outstanding == 0) {
		g_hash_table_remove (self->invocations, discover->operation_id);
		discover_process_results (res, discover);
		discover->completed = TRUE;
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
	g_object_unref (self);
}

static gboolean
on_discover_timeout (gpointer user_data)
{
	GSimpleAsyncResult *async = G_SIMPLE_ASYNC_RESULT (user_data);
	DiscoverClosure *discover = g_simple_async_result_get_op_res_gpointer (async);

	if (discover->completed)
		return TRUE;

	/*
	 * So at this point if we have results, then consider the rest of
	 * the providers as taking too long, and ignore their results.
	 */

	if (!g_queue_is_empty (&discover->results)) {
		discover_process_results (async, discover);
		discover->completed = TRUE;
		g_simple_async_result_complete (async);
	}

	return TRUE;
}

static void
realm_all_provider_discover_async (RealmProvider *provider,
                                   const gchar *string,
                                   GDBusMethodInvocation *invocation,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	RealmAllProvider *self = REALM_ALL_PROVIDER (provider);
	GSimpleAsyncResult *res;
	DiscoverClosure *discover;
	ProviderProxy *prov;
	GList *l;

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 realm_all_provider_discover_async);
	discover = g_slice_new0 (DiscoverClosure);
	g_queue_init (&discover->results);
	discover->invocation = g_object_ref (invocation);
	discover->operation_id = g_strdup_printf ("realm-all-provider-%d", operation_unique_id++);
	discover->timeout_id = g_timeout_add_seconds (3, on_discover_timeout, res);
	g_simple_async_result_set_op_res_gpointer (res, discover, discover_closure_free);

	for (l = self->providers; l != NULL; l = g_list_next (l)) {
		prov = l->data;
		g_dbus_proxy_call (prov->proxy, "Discover",
		                   g_variant_new ("(ss)", string, discover->operation_id),
		                   G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL,
		                   on_proxy_discover, g_object_ref (res));
		discover->outstanding++;
	}

	/* If no discovery going on then just complete */
	if (discover->outstanding == 0) {
		discover_process_results (res, discover);
		discover->completed = TRUE;
		g_simple_async_result_complete_in_idle (res);

	/* Here we mark down our operation_id so diagnostics work */
	} else {
		g_hash_table_insert (self->invocations,
		                     g_strdup (discover->operation_id),
		                     g_object_ref (invocation));
	}

	g_object_unref (res);
}

static gint
realm_all_provider_discover_finish (RealmProvider *provider,
                                    GAsyncResult *result,
                                    GVariant **realms,
                                    GError **error)
{
	GSimpleAsyncResult *res;
	DiscoverClosure *discover;

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return -1;

	discover = g_simple_async_result_get_op_res_gpointer (res);
	*realms = discover->realms;
	discover->realms = NULL;
	return discover->relevance;
}

static void
realm_all_provider_finalize (GObject *obj)
{
	RealmAllProvider *self = REALM_ALL_PROVIDER (obj);
	ProviderProxy *prov;
	GList *l;

	for (l = self->providers; l != NULL; l = g_list_next (l)) {
		prov = l->data;
		if (prov->diagnostics_sig) {
			g_dbus_connection_signal_unsubscribe (g_dbus_proxy_get_connection (prov->proxy),
			                                      prov->diagnostics_sig);
		}
		g_object_unref (prov->proxy);
		g_slice_free (ProviderProxy, prov);
	}
	g_list_free (self->providers);

	g_hash_table_destroy (self->invocations);

	G_OBJECT_CLASS (realm_all_provider_parent_class)->finalize (obj);
}

void
realm_all_provider_class_init (RealmAllProviderClass *klass)
{
	RealmProviderClass *provider_class = REALM_PROVIDER_CLASS (klass);
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = realm_all_provider_finalize;

	provider_class->dbus_name = REALM_DBUS_ALL_PROVIDER_NAME;
	provider_class->dbus_path = REALM_DBUS_ALL_PROVIDER_PATH;

	provider_class->discover_async = realm_all_provider_discover_async;
	provider_class->discover_finish = realm_all_provider_discover_finish;
}

typedef struct {
	gint outstanding;
} InitClosure;

static void
init_closure_free (gpointer data)
{
	InitClosure *init = data;
	g_slice_free (InitClosure, init);
}

static void
on_provider_proxy_diagnostics (GDBusConnection *connection,
                               const gchar *sender_name,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *signal_name,
                               GVariant *parameters,
                               gpointer user_data)
{
	RealmAllProvider *self = REALM_ALL_PROVIDER (user_data);
	GDBusMethodInvocation *invocation;
	const gchar *operation_id;
	const gchar *data;

	/* Here we relay diagnostic information from separate providers back to caller */
	g_return_if_fail (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(ss)")));
	g_variant_get (parameters, "(&s&s)", &data, &operation_id);
	invocation = g_hash_table_lookup (self->invocations, operation_id);
	if (invocation != NULL)
		realm_diagnostics_signal (invocation, data);
}

static void
on_provider_proxy_created (GObject *source,
                           GAsyncResult *result,
                           gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	InitClosure *init = g_simple_async_result_get_op_res_gpointer (res);
	RealmAllProvider *self = REALM_ALL_PROVIDER (g_async_result_get_source_object (user_data));
	GDBusProxy *proxy;
	ProviderProxy *prov;
	GError *error = NULL;
	guint sig;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (error == NULL) {
		g_signal_connect (proxy, "g-properties-changed",
		                  G_CALLBACK (on_proxy_properties_changed), self);

		sig = g_dbus_connection_signal_subscribe (g_dbus_proxy_get_connection (proxy),
		                                          g_dbus_proxy_get_name (proxy),
		                                          "org.freedesktop.realmd.Diagnostics",
		                                          "Diagnostics",
		                                          g_dbus_proxy_get_object_path (proxy),
		                                          NULL,
		                                          G_DBUS_SIGNAL_FLAGS_NONE,
		                                          on_provider_proxy_diagnostics,
		                                          self, NULL);

		prov = g_slice_new0 (ProviderProxy);
		prov->proxy = proxy;
		prov->diagnostics_sig = sig;
		self->providers = g_list_prepend (self->providers, prov);

	} else {
		g_warning ("Couldn't load realm provider: %s", error->message);
		g_error_free (error);
	}

	init->outstanding--;
	if (init->outstanding == 0) {
		update_all_properties (self);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

static void
realm_all_provider_init_async (GAsyncInitable *initable,
                               int io_priority,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	RealmAllProvider *self = REALM_ALL_PROVIDER (initable);
	GSimpleAsyncResult *res;
	InitClosure *init;
	GError *error = NULL;
	GDir *dir = NULL;
	gchar *filename;
	const gchar *name;
	gchar *provider_name;
	gchar *provider_path;

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 realm_all_provider_init_async);
	init = g_slice_new0 (InitClosure);
	g_simple_async_result_set_op_res_gpointer (res, init, init_closure_free);

	dir = g_dir_open (PROVIDER_DIR, 0, &error);
	if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
		g_clear_error (&error);
	if (error != NULL) {
		g_warning ("Couldn't list provider directory: %s: %s",
		           PROVIDER_DIR, error->message);
		g_clear_error (&error);
		dir = NULL;
	}

	for (;;) {
		if (dir == NULL)
			name = NULL;
		else
			name = g_dir_read_name (dir);
		if (name == NULL)
			break;

		/* Only files ending in *.provider are loaded */
		if (!g_pattern_match_simple ("*.provider", name))
			continue;

		filename = g_build_filename (PROVIDER_DIR, name, NULL);
		if (provider_load (filename, &provider_name, &provider_path)) {
			g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
			                          realm_dbus_provider_interface_info (),
			                          provider_name, provider_path,
			                          REALM_DBUS_PROVIDER_INTERFACE,
			                          cancellable, on_provider_proxy_created,
			                          g_object_ref (res));

			realm_debug ("Initializing provider: %s", provider_name);

			g_free (provider_name);
			g_free (provider_path);
			init->outstanding++;
		}

		g_free (filename);
	}

	if (init->outstanding == 0) {
		realm_debug ("No realm providers found");
		g_simple_async_result_complete_in_idle (res);
	}

	g_object_unref (res);
}

static gboolean
realm_all_provider_init_finish (GAsyncInitable *initable,
                                GAsyncResult *result,
                                GError **error)
{
	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

static void
realm_all_provider_async_initable_iface (GAsyncInitableIface *iface)
{
	iface->init_async = realm_all_provider_init_async;
	iface->init_finish = realm_all_provider_init_finish;
}
