/* realmd -- Realm configuration service
 *
 * Copyright 2013 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "egg-task.h"
#include "realm-dbus-constants.h"
#include "realm-disco-mscldap.h"
#include "realm-ldap.h"

#include <glib/gi18n.h>

#include <resolv.h>

typedef struct {
	gchar *explicit_server;
	GSocketProtocol protocol;
	GSource *source;
	gint count;
	gint fever_id;
	gint normal_id;
} Closure;

/* Number of rapid requets to do */
#define DISCO_FEVER  4

static void
closure_free (gpointer data)
{
	Closure *clo = data;

	g_free (clo->explicit_server);
	if (clo->fever_id)
		g_source_remove (clo->fever_id);
	if (clo->normal_id)
		g_source_remove (clo->normal_id);
	g_source_destroy (clo->source);
	g_source_unref (clo->source);
	g_slice_free (Closure, clo);
}

static gchar *
get_string (guchar *beg,
            guchar *end,
            guchar **at)
{
	gchar buffer[HOST_NAME_MAX];
	int n;

	n = dn_expand (beg, end, *at, buffer, sizeof (buffer));
	if (n < 0)
		return NULL;

	(*at) += n;
	return g_strdup (buffer);
}

static gboolean
parse_string (guchar *beg,
              guchar *end,
              guchar **at,
              gchar **result)
{
	gchar *string;

	g_assert (result);

	string = get_string (beg, end, at);
	if (string == NULL)
		return FALSE;

	g_free (*result);
	*result = string;

	return TRUE;
}

static gboolean
get_32_le (unsigned char **at,
           unsigned char *end,
           unsigned int *val)
{
	unsigned char *p = *at;
	if (p + 4 > end)
		return FALSE;
	*val = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
	(*at) += 4;
	return TRUE;
}

static gboolean
skip_n (unsigned char **at,
        unsigned char *end,
        int n)
{
	if ((*at) + n > end)
		return FALSE;
	(*at) += n;
	return TRUE;
}

static RealmDisco *
parse_netlogon (struct berval **bvs,
                GError **error)
{
	RealmDisco *disco = NULL;
	guchar *at, *end, *beg;
	gchar *unused = NULL;
	guint type, flags;

	if (bvs != NULL && bvs[0] != NULL) {
		beg = (guchar *)bvs[0]->bv_val;
		end = beg + bvs[0]->bv_len;
		at = beg;
		disco = realm_disco_new (NULL);
	}

	/* domain forest */
	if (disco == NULL ||
	    !get_32_le (&at, end, &type) || type != 23 ||
	    !get_32_le (&at, end, &flags) ||
	    !skip_n (&at, end, 16) || /* guid */
	    !parse_string (beg, end, &at, &unused) || /* forest */
	    !parse_string (beg, end, &at, &disco->domain_name) ||
	    !parse_string (beg, end, &at, &unused) || /* hostname */
	    !parse_string (beg, end, &at, &disco->workgroup) ||
	    !parse_string (beg, end, &at, &unused) || /* shorthost */
	    !parse_string (beg, end, &at, &unused) || /* user */
	    !parse_string (beg, end, &at, &unused) || /* server site */
	    !parse_string (beg, end, &at, &unused)) { /* client site */
		realm_disco_unref (disco);
		disco = NULL;
	}

	g_free (unused);

	if (disco == NULL) {
		g_set_error (error, REALM_LDAP_ERROR, LDAP_PROTOCOL_ERROR,
		             _("Received invalid Netlogon data from server"));
		return NULL;
	}

	disco->server_software = REALM_DBUS_IDENTIFIER_ACTIVE_DIRECTORY;
	disco->kerberos_realm = g_ascii_strup (disco->domain_name, -1);
	return disco;
}

static RealmDisco *
parse_disco (LDAP *ldap,
             LDAPMessage *message,
             GError **error)
{
	RealmDisco *disco = NULL;
	struct berval **bvs = NULL;
	LDAPMessage *entry;

	entry = ldap_first_entry (ldap, message);
	if (entry != NULL)
		bvs = ldap_get_values_len (ldap, entry, "NetLogon");
	disco = parse_netlogon (bvs, error);
	ldap_value_free_len (bvs);

	return disco;
}

static gboolean
on_resend (gpointer user_data)
{
	realm_ldap_set_condition (user_data, G_IO_OUT | G_IO_IN);
	return TRUE;
}

static GIOCondition
on_ldap_io (LDAP *ldap,
            GIOCondition cond,
            gpointer user_data)
{
	EggTask *task = EGG_TASK (user_data);
	Closure *clo = egg_task_get_task_data (task);
	char *attrs[] = { "NetLogon", NULL };
	struct timeval tvpoll = { 0, 0 };
	LDAPMessage *message;
	GError *error = NULL;
	RealmDisco *disco;
	int msgid;
	gint rc;

	/* Cancelled */
	if (cond & G_IO_ERR) {
		realm_ldap_set_error (&error, ldap, 0);
		egg_task_return_error (task, error);
		return G_IO_NVAL;
	}

	/* Ready for input */
	if (cond & G_IO_OUT) {
		g_debug ("Sending NetLogon ping");
		rc = ldap_search_ext (ldap, "", LDAP_SCOPE_BASE,
		                      "(&(NtVer=\\06\\00\\00\\00)(AAC=\\00\\00\\00\\00))",
		                      attrs, 0, NULL, NULL, NULL,
		                      -1, &msgid);

		if (rc != LDAP_SUCCESS) {
			realm_ldap_set_error (&error, ldap, rc);
			egg_task_return_error (task, error);
			return G_IO_NVAL;
		}

		/* Remove rapid fire after sending a feverish batch */
		if (clo->count++ > DISCO_FEVER && clo->fever_id != 0) {
			g_source_remove (clo->fever_id);
			clo->fever_id = 0;
		}
	}

	/* Ready to get a result */
	if (cond & G_IO_IN) {
		switch (ldap_result (ldap, LDAP_RES_ANY, 0, &tvpoll, &message)) {
		case LDAP_RES_SEARCH_ENTRY:
			g_debug ("Received response");
			disco = parse_disco (ldap, message, &error);
			if (disco && clo->explicit_server)
				disco->explicit_server = g_strdup (clo->explicit_server);
			egg_task_return_pointer (task, disco, realm_disco_unref);
			ldap_msgfree (message);
			return G_IO_NVAL;
		case LDAP_RES_SEARCH_RESULT:
			egg_task_return_pointer (task, NULL, NULL);
			ldap_msgfree (message);
			return G_IO_NVAL;
		case -1:
			realm_ldap_set_error (&error, ldap, -1);
			egg_task_return_error (task, error);
			return G_IO_NVAL;
		case 0:
			break;
		default:
			/* Ignore and keep waiting */
			ldap_msgfree (message);
			break;
		}
	}

	/* Now wait for a response */
	return G_IO_IN;
}

static GSocketProtocol
get_cldap_protocol (void)
{
	static gboolean checked = FALSE;
	static GSocketProtocol protocol;

	if (!checked) {
		if (ldap_is_ldap_url ("cldap://hostname"))
			protocol = G_SOCKET_PROTOCOL_UDP;
		else
			protocol = G_SOCKET_PROTOCOL_TCP;
		checked = TRUE;
	}

	return protocol;
}

void
realm_disco_mscldap_async (GSocketAddress *address,
                           const gchar *explicit_server,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	EggTask *task;
	Closure *clo;

	g_return_if_fail (address != NULL);

	task = egg_task_new (NULL, cancellable, callback, user_data);
	clo = g_slice_new0 (Closure);
	clo->explicit_server = g_strdup (explicit_server);
	clo->protocol = get_cldap_protocol ();
	egg_task_set_task_data (task, clo, closure_free);

	clo->source = realm_ldap_connect_anonymous (address, clo->protocol,
	                                            cancellable);
	g_source_set_callback (clo->source, (GSourceFunc)on_ldap_io,
	                       g_object_ref (task), g_object_unref);
	g_source_attach (clo->source, egg_task_get_context (task));

	if (clo->protocol == G_SOCKET_PROTOCOL_UDP) {
		clo->fever_id = g_timeout_add (100, on_resend, clo->source);
		clo->normal_id = g_timeout_add (1000, on_resend, clo->source);
	}

	g_object_unref (task);
}

RealmDisco *
realm_disco_mscldap_finish (GAsyncResult *result,
                            GError **error)
{
	g_return_val_if_fail (egg_task_is_valid (result, NULL), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	return egg_task_propagate_pointer (EGG_TASK (result), error);
}