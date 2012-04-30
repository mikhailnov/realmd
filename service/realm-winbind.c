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

#include "realm-winbind.h"
#include "realm-command.h"
#include "realm-constants.h"
#include "realm-daemon.h"
#include "realm-diagnostics.h"
#include "realm-errors.h"
#include "realm-samba-config.h"
#include "realm-service.h"

#include <glib/gstdio.h>

#include <errno.h>

static void
on_winbind_enabled (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;

	realm_service_enable_finish (result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
on_samba_config_done (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GDBusMethodInvocation *invocation = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	realm_samba_config_set_finish (result, &error);
	if (error == NULL) {
		realm_service_enable_and_restart (REALM_WINBIND_SERVICE,
		                                  invocation,
		                                  on_winbind_enabled,
		                                  g_object_ref (res));
	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

void
realm_winbind_configure_async (GDBusMethodInvocation *invocation,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (invocation != NULL || G_IS_DBUS_METHOD_INVOCATION (invocation));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 realm_winbind_configure_async);
	if (invocation != NULL)
		g_simple_async_result_set_op_res_gpointer (res, g_object_ref (invocation),
		                                           g_object_unref);

	/* TODO: need to use autorid mapping */

	realm_samba_config_set_async ("global", invocation,
	                              on_samba_config_done, g_object_ref (res),
	                              "idmap uid", "10000-20000",
	                              "idmap gid", "10000-20000",
	                              "winbind enum users", "no",
	                              "winbind enum groups", "no",
	                              "template shell", REALM_BASH_PATH,
	                              NULL);

	g_object_unref (res);
}

gboolean
realm_winbind_configure_finish (GAsyncResult *result,
                                GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      realm_winbind_configure_async), FALSE);
	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;
	return TRUE;
}

static void
on_winbind_disabled (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;

	realm_service_disable_finish (result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}


void
realm_winbind_deconfigure_async (GDBusMethodInvocation *invocation,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (invocation != NULL || G_IS_DBUS_METHOD_INVOCATION (invocation));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 realm_winbind_deconfigure_async);

	realm_service_disable_and_stop (REALM_WINBIND_SERVICE,
	                                invocation,
	                                on_winbind_disabled,
	                                g_object_ref (res));

	g_object_unref (res);
}

gboolean
realm_winbind_deconfigure_finish (GAsyncResult *result,
                                  GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      realm_winbind_deconfigure_async), FALSE);
	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;
	return TRUE;

}
