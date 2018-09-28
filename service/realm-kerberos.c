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
#include "realm-credential.h"
#include "realm-daemon.h"
#include "realm-dbus-constants.h"
#include "realm-dbus-generated.h"
#include "realm-diagnostics.h"
#include "realm-disco.h"
#include "realm-errors.h"
#include "realm-invocation.h"
#include "realm-kerberos.h"
#include "realm-kerberos-membership.h"
#include "realm-login-name.h"
#include "realm-options.h"
#include "realm-packages.h"
#include "realm-provider.h"
#include "realm-settings.h"

#include <krb5/krb5.h>

#include <glib/gi18n.h>
#include <glib/gstdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

struct _RealmKerberosPrivate {
	RealmDisco *disco;
	RealmDbusRealm *realm_iface;
	RealmDbusKerberos *kerberos_iface;
	RealmDbusKerberosMembership *membership_iface;
};

enum {
	PROP_0,
	PROP_NAME,
	PROP_DISCO,
	PROP_PROVIDER,
	PROP_MANAGES_SYSTEM,
};

/* A global weak pointer which tracks the manage-system domain */
static RealmKerberos *realm_which_manages_system = NULL;

G_DEFINE_TYPE (RealmKerberos, realm_kerberos, G_TYPE_DBUS_OBJECT_SKELETON);

#define return_if_krb5_failed(ctx, code) G_STMT_START \
	if G_LIKELY ((code) == 0) { } else { \
		g_warn_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		                krb5_get_error_message ((ctx), (code))); \
		 return; \
	} G_STMT_END

#define return_val_if_krb5_failed(ctx, code, val) G_STMT_START \
	if G_LIKELY ((code) == 0) { } else { \
		g_warn_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		                krb5_get_error_message ((ctx), (code))); \
		 return (val); \
	} G_STMT_END

#define warn_if_krb5_failed(ctx, code) G_STMT_START \
	if G_LIKELY ((code) == 0) { } else { \
		g_warn_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
		                krb5_get_error_message ((ctx), (code))); \
	} G_STMT_END

typedef struct {
	RealmKerberos *self;
	GDBusMethodInvocation *invocation;
	RealmCredential *cred;
} MethodClosure;

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

static MethodClosure *
method_closure_new (RealmKerberos *self,
                    GDBusMethodInvocation *invocation)
{
	MethodClosure *method = g_new0 (MethodClosure, 1);
	method->self = g_object_ref (self);
	method->invocation = g_object_ref (invocation);
	return method;
}

static void
method_closure_free (MethodClosure *closure)
{
	g_object_unref (closure->self);
	g_object_unref (closure->invocation);
	if (closure->cred)
		realm_credential_unref (closure->cred);
	g_free (closure);
}

static void
enroll_method_reply (GDBusMethodInvocation *invocation,
                     GError *error)
{
	if (error == NULL) {
		realm_diagnostics_info (invocation, "Successfully enrolled machine in realm");
		g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

	} else if (error->domain == REALM_ERROR || error->domain == G_DBUS_ERROR) {
		realm_diagnostics_error (invocation, error, NULL);
		g_dbus_method_invocation_return_gerror (invocation, error);

	} else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		realm_diagnostics_error (invocation, error, "Cancelled");
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_CANCELLED,
		                                       _("Operation was cancelled."));

	} else {
		realm_diagnostics_error (invocation, error, "Failed to enroll machine in realm");
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_FAILED,
		                                       _("Failed to enroll machine in realm. See diagnostics."));
	}

	realm_invocation_unlock_daemon (invocation);
}

static void
on_name_caches_flush (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	MethodClosure *closure = user_data;
	GError *error = NULL;
	gint status;

	status = realm_command_run_finish (result, NULL, &error);
	if (status != 0) {
		realm_diagnostics_error (closure->invocation, error,
		                         "Flushing name caches failed");
	}

	g_clear_error (&error);
	enroll_method_reply (closure->invocation, NULL);
	method_closure_free (closure);
}

static void
on_enroll_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	MethodClosure *closure = user_data;
	RealmKerberosMembershipIface *iface;
	GCancellable *cancellable;
	GError *error = NULL;

	iface = REALM_KERBEROS_MEMBERSHIP_GET_IFACE (closure->self);
	g_return_if_fail (iface->join_finish != NULL);

	cancellable = realm_invocation_get_cancellable (closure->invocation);
	if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
		(iface->join_finish) (REALM_KERBEROS_MEMBERSHIP (closure->self), result, &error);

	if (error != NULL) {
		enroll_method_reply (closure->invocation, error);
		method_closure_free (closure);
		g_clear_error (&error);

	/* Only flush the name caches if not in install mode */
	} else if (!realm_daemon_is_install_mode ()) {
		realm_command_run_known_async ("name-caches-flush", NULL, closure->invocation,
		                               on_name_caches_flush, closure);

	} else {
		enroll_method_reply (closure->invocation, NULL);
	}
}

static void
unenroll_method_reply (GDBusMethodInvocation *invocation,
                       GError *error)
{
	if (error == NULL) {
		realm_diagnostics_info (invocation, "Successfully unenrolled machine from realm");
		g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

	} else if (error->domain == REALM_ERROR || error->domain == G_DBUS_ERROR) {
		realm_diagnostics_error (invocation, error, NULL);
		g_dbus_method_invocation_return_gerror (invocation, error);

	} else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		realm_diagnostics_error (invocation, error, "Cancelled");
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_CANCELLED,
		                                       _("Operation was cancelled."));

	} else {
		realm_diagnostics_error (invocation, error, "Failed to unenroll machine from realm");
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_FAILED,
		                                       _("Failed to unenroll machine from domain. See diagnostics."));
	}

	realm_invocation_unlock_daemon (invocation);
}

static void
on_unenroll_complete (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	MethodClosure *closure = user_data;
	RealmKerberosMembershipIface *iface;
	GCancellable *cancellable;
	GError *error = NULL;

	iface = REALM_KERBEROS_MEMBERSHIP_GET_IFACE (closure->self);
	g_return_if_fail (iface->leave_finish != NULL);

	cancellable = realm_invocation_get_cancellable (closure->invocation);
	if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
		(iface->leave_finish) (REALM_KERBEROS_MEMBERSHIP (closure->self), result, &error);

	unenroll_method_reply (closure->invocation, error);

	g_clear_error (&error);
	method_closure_free (closure);
}

static gboolean
is_credential_supported (RealmKerberosMembershipIface *iface,
                         RealmKerberosMembership *membership,
                         RealmCredential *cred,
                         gboolean join,
                         GError **error)
{
	const RealmCredential *supported;
	const char *message = NULL;
	gboolean found = FALSE;
	gint i;

	g_assert (iface->join_creds != NULL);
	g_assert (iface->leave_creds != NULL);

	supported = (join ? iface->join_creds (membership) : iface->leave_creds (membership));
	if (supported) {
		for (i = 0; supported[i].type != 0; i++) {
			if (cred->type == supported[i].type) {
				found = TRUE;
				break;
			}
		}
	}

	if (found)
		return TRUE;

	switch (cred->type) {
	case REALM_CREDENTIAL_AUTOMATIC:
		message = join ? _("Joining this realm without credentials is not supported") :
		                 _("Leaving this realm without credentials is not supported");
		break;
	case REALM_CREDENTIAL_CCACHE:
		message = join ? _("Joining this realm using a credential cache is not supported") :
		                 _("Leaving this realm using a credential cache is not supported");
		break;
	case REALM_CREDENTIAL_SECRET:
		message = join ? _("Joining this realm using a secret is not supported") :
		                 _("Unenrolling this realm using a secret is not supported");
		break;
	case REALM_CREDENTIAL_PASSWORD:
		message = join ? _("Enrolling this realm using a password is not supported") :
		                 _("Unenrolling this realm using a password is not supported");
		break;
	}

	g_set_error_literal (error, G_DBUS_ERROR, G_DBUS_ERROR_NOT_SUPPORTED, message);
	return FALSE;
}

static void
join_or_leave (RealmKerberos *self,
               GVariant *credential,
               GVariant *options,
               GDBusMethodInvocation *invocation,
               gboolean join)
{
	RealmKerberosMembershipIface *iface = REALM_KERBEROS_MEMBERSHIP_GET_IFACE (self);
	RealmKerberosMembership *membership = REALM_KERBEROS_MEMBERSHIP (self);
	RealmCredential *cred;
	MethodClosure *method;
	GError *error = NULL;

	g_return_if_fail (iface != NULL);

	if ((join && iface && iface->join_async == NULL) ||
	    (!join && iface && iface->leave_async == NULL)) {
		g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR, G_DBUS_ERROR_NOT_SUPPORTED,
		                                       join ? _("Joining this realm is not supported") :
		                                              _("Leaving this realm is not supported"));
		return;
	}

	cred = realm_credential_parse (credential, &error);
	if (error != NULL) {
		g_dbus_method_invocation_return_gerror (invocation, error);
		g_error_free (error);
		return;
	}

	if (!is_credential_supported (iface, membership, cred, join, &error)) {
		g_dbus_method_invocation_return_gerror (invocation, error);
		realm_credential_unref (cred);
		g_error_free (error);
		return;
	}

	if (!realm_invocation_lock_daemon (invocation)) {
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_BUSY,
		                                       _("Already running another action"));
		return;
	}

	method = method_closure_new (self, invocation);
	method->cred = cred;

	if (join) {
		g_return_if_fail (iface->join_finish != NULL);
		(iface->join_async) (membership, cred, options, invocation, on_enroll_complete, method);
	} else {
		g_return_if_fail (iface->leave_finish != NULL);
		(iface->leave_async) (membership, cred, options, invocation, on_unenroll_complete, method);
	}
}

static gboolean
handle_join (RealmDbusKerberosMembership *membership,
             GDBusMethodInvocation *invocation,
             GVariant *credentials,
             GVariant *options,
             gpointer user_data)
{
	RealmKerberos *self = REALM_KERBEROS (user_data);
	gchar hostname[HOST_NAME_MAX + 1];
	RealmKerberos *manages;
	gint ret;

	/* Check the host name */
	ret = gethostname (hostname, sizeof (hostname));
	if (ret < 0 || g_ascii_strcasecmp (hostname, "localhost") == 0 ||
	    g_ascii_strncasecmp (hostname, "localhost.", 10) == 0 ||
	    hostname[0] == '.') {
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_BAD_HOSTNAME,
		                                       "This computer's host name is not set correctly.");
		return TRUE;
	}

	if (realm_options_manage_system (options, realm_kerberos_get_name (self))) {
		manages = realm_kerberos_which_manages_system ();
		if (manages != NULL && manages != self) {
			g_dbus_method_invocation_return_error (invocation, REALM_ERROR,
			                                       REALM_ERROR_ALREADY_CONFIGURED,
			                                       _("Already joined to another domain: %s"),
			                                       realm_kerberos_get_name (manages));
			return TRUE;
		}
	}

	join_or_leave (self, credentials, options, invocation, TRUE);
	return TRUE;
}

static gboolean
handle_leave (RealmDbusKerberosMembership *membership,
              GDBusMethodInvocation *invocation,
              GVariant *credentials,
              GVariant *options,
              gpointer user_data)
{
	RealmKerberos *self = REALM_KERBEROS (user_data);

	if (realm_options_computer_ou (options, NULL)) {
		g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
		                                       "The computer-ou argument is not supported when leaving a domain.");
		return TRUE;
	}

	join_or_leave (self, credentials, options, invocation, FALSE);
	return TRUE;
}

static gboolean
handle_deconfigure (RealmDbusRealm *realm,
                    GDBusMethodInvocation *invocation,
                    GVariant *options,
                    gpointer user_data)
{
	GVariant *credential;

	credential = g_variant_new ("(ss@v)", "automatic", "none",
	                            g_variant_new_variant (g_variant_new_string ("")));
	join_or_leave (REALM_KERBEROS (user_data), credential, options, invocation, FALSE);
	g_variant_unref (credential);

	return TRUE;
}


static void
on_logins_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	MethodClosure *closure = user_data;
	RealmKerberosClass *klass;
	GError *error = NULL;

	klass = REALM_KERBEROS_GET_CLASS (closure->self);
	g_return_if_fail (klass->logins_finish != NULL);

	if ((klass->logins_finish) (closure->self, result, &error)) {
		realm_diagnostics_info (closure->invocation, "Successfully changed permitted logins for realm");
		g_dbus_method_invocation_return_value (closure->invocation, g_variant_new ("()"));

	} else if (error != NULL &&
	           (error->domain == REALM_ERROR || error->domain == G_DBUS_ERROR)) {
		realm_diagnostics_error (closure->invocation, error, NULL);
		g_dbus_method_invocation_return_gerror (closure->invocation, error);
		g_error_free (error);

	} else {
		realm_diagnostics_error (closure->invocation, error, "Failed to change permitted logins");
		g_dbus_method_invocation_return_error (closure->invocation, REALM_ERROR, REALM_ERROR_INTERNAL,
		                                       _("Failed to change permitted logins. See diagnostics."));
		g_error_free (error);
	}

	realm_invocation_unlock_daemon (closure->invocation);
	method_closure_free (closure);
}

static gboolean
handle_change_login_policy (RealmDbusRealm *realm,
                            GDBusMethodInvocation *invocation,
                            const gchar *login_policy,
                            const gchar *const *add,
                            const gchar *const *remove,
                            GVariant *options,
                            gpointer user_data)
{
	RealmKerberosLoginPolicy policy = REALM_KERBEROS_POLICY_NOT_SET;
	RealmKerberos *self = REALM_KERBEROS (user_data);
	RealmKerberosClass *klass;
	gchar **policies;
	gint policies_set = 0;
	gint i;

	policies = g_strsplit_set (login_policy, ", \t", -1);
	for (i = 0; policies[i] != NULL; i++) {
		if (g_str_equal (policies[i], REALM_DBUS_LOGIN_POLICY_ANY)) {
			policy = REALM_KERBEROS_ALLOW_ANY_LOGIN;
			policies_set++;
		} else if (g_str_equal (policies[i], REALM_DBUS_LOGIN_POLICY_REALM)) {
			policy = REALM_KERBEROS_ALLOW_REALM_LOGINS;
			policies_set++;
		} else if (g_str_equal (policies[i], REALM_DBUS_LOGIN_POLICY_PERMITTED)) {
			policy = REALM_KERBEROS_ALLOW_PERMITTED_LOGINS;
			policies_set++;
		} else if (g_str_equal (policies[i], REALM_DBUS_LOGIN_POLICY_DENY)) {
			policy = REALM_KERBEROS_DENY_ANY_LOGIN;
			policies_set++;
		} else {
			g_strfreev (policies);
			g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
			                                       G_DBUS_ERROR_INVALID_ARGS,
			                                       "Invalid or unknown login_policy argument");
			return TRUE;
		}
	}

	g_strfreev (policies);

	if (policies_set > 1) {
		g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
		                                       G_DBUS_ERROR_INVALID_ARGS,
		                                       "Conflicting flags in login_policy argument");
		return TRUE;
	}

	if (!realm_invocation_lock_daemon (invocation)) {
		g_dbus_method_invocation_return_error (invocation, REALM_ERROR, REALM_ERROR_BUSY,
		                                       _("Already running another action"));
		return TRUE;
	}

	klass = REALM_KERBEROS_GET_CLASS (self);
	g_return_val_if_fail (klass->logins_async != NULL, FALSE);

	(klass->logins_async) (self, invocation, policy, (const gchar **)add,
	                       (const gchar **)remove, options, on_logins_complete,
	                       method_closure_new (self, invocation));

	return TRUE;
}

static gboolean
realm_kerberos_authorize_method (GDBusObjectSkeleton    *object,
                                 GDBusInterfaceSkeleton *iface,
                                 GDBusMethodInvocation  *invocation)
{
	return realm_invocation_authorize (invocation);
}

static void
realm_kerberos_init (RealmKerberos *self)
{
	GDBusObjectSkeleton *skeleton = G_DBUS_OBJECT_SKELETON (self);

	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, REALM_TYPE_KERBEROS,
	                                        RealmKerberosPrivate);

	self->pv->realm_iface = realm_dbus_realm_skeleton_new ();
	g_signal_connect (self->pv->realm_iface, "handle-deconfigure",
	                  G_CALLBACK (handle_deconfigure), self);
	g_signal_connect (self->pv->realm_iface, "handle-change-login-policy",
	                  G_CALLBACK (handle_change_login_policy), self);
	g_dbus_object_skeleton_add_interface (skeleton, G_DBUS_INTERFACE_SKELETON (self->pv->realm_iface));

	self->pv->kerberos_iface = realm_dbus_kerberos_skeleton_new ();
	g_dbus_object_skeleton_add_interface (skeleton, G_DBUS_INTERFACE_SKELETON (self->pv->kerberos_iface));
}

static void
realm_kerberos_constructed (GObject *obj)
{
	RealmKerberosMembershipIface *iface;
	RealmKerberosMembership *membership;
	RealmKerberos *self = REALM_KERBEROS (obj);
	const gchar *supported_interfaces[3];
	GVariant *supported;

	g_return_if_fail (self != NULL);

	G_OBJECT_CLASS (realm_kerberos_parent_class)->constructed (obj);

	if (REALM_IS_KERBEROS_MEMBERSHIP (self)) {
		self->pv->membership_iface = realm_dbus_kerberos_membership_skeleton_new ();
		g_signal_connect (self->pv->membership_iface, "handle-join",
		                  G_CALLBACK (handle_join), self);
		g_signal_connect (self->pv->membership_iface, "handle-leave",
		                  G_CALLBACK (handle_leave), self);
		g_dbus_object_skeleton_add_interface (G_DBUS_OBJECT_SKELETON (self),
		                                      G_DBUS_INTERFACE_SKELETON (self->pv->membership_iface));

		iface = REALM_KERBEROS_MEMBERSHIP_GET_IFACE (self);
		membership = REALM_KERBEROS_MEMBERSHIP (self);

		supported = realm_credential_build_supported (iface->join_creds (membership));
		realm_dbus_kerberos_membership_set_supported_join_credentials (self->pv->membership_iface, supported);

		supported = realm_credential_build_supported (iface->leave_creds (membership));
		realm_dbus_kerberos_membership_set_supported_leave_credentials (self->pv->membership_iface, supported);
	}

	supported_interfaces[0] = REALM_DBUS_KERBEROS_INTERFACE;
	if (self->pv->membership_iface)
		supported_interfaces[1] = REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE;
	else
		supported_interfaces[1] = NULL;
	supported_interfaces[2] = NULL;

	realm_dbus_realm_set_supported_interfaces (self->pv->realm_iface,
	                                           supported_interfaces);

	if (self->pv->disco) {
		if (self->pv->disco->domain_name)
			realm_kerberos_set_domain_name (self, self->pv->disco->domain_name);
		if (self->pv->disco->kerberos_realm)
			realm_kerberos_set_realm_name (self, self->pv->disco->kerberos_realm);
	}
}

static void
realm_kerberos_get_property (GObject *obj,
                             guint prop_id,
                             GValue *value,
                             GParamSpec *pspec)
{
	RealmKerberos *self = REALM_KERBEROS (obj);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, realm_kerberos_get_name (self));
		break;
	case PROP_DISCO:
		g_value_set_boxed (value, realm_kerberos_get_disco (self));
		break;
	case PROP_MANAGES_SYSTEM:
		g_value_set_boolean (value, realm_kerberos_get_manages_system (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
realm_kerberos_set_property (GObject *obj,
                             guint prop_id,
                             const GValue *value,
                             GParamSpec *pspec)
{
	RealmKerberos *self = REALM_KERBEROS (obj);

	switch (prop_id) {
	case PROP_NAME:
		realm_dbus_realm_set_name (self->pv->realm_iface,
		                           g_value_get_string (value));
		break;
	case PROP_DISCO:
		realm_kerberos_set_disco (self, g_value_get_boxed (value));
		break;
	case PROP_PROVIDER:
		/* ignore */
		break;
	case PROP_MANAGES_SYSTEM:
		realm_kerberos_set_manages_system (self, g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
realm_kerberos_finalize (GObject *obj)
{
	RealmKerberos *self = REALM_KERBEROS (obj);

	g_object_unref (self->pv->realm_iface);
	g_object_unref (self->pv->kerberos_iface);
	if (self->pv->membership_iface)
		g_object_unref (self->pv->membership_iface);

	if (self->pv->disco)
		realm_disco_unref (self->pv->disco);

	G_OBJECT_CLASS (realm_kerberos_parent_class)->finalize (obj);
}

static void
realm_kerberos_class_init (RealmKerberosClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GDBusObjectSkeletonClass *skeleton_class = G_DBUS_OBJECT_SKELETON_CLASS (klass);

	object_class->constructed = realm_kerberos_constructed;
	object_class->get_property = realm_kerberos_get_property;
	object_class->set_property = realm_kerberos_set_property;
	object_class->finalize = realm_kerberos_finalize;

	skeleton_class->authorize_method = realm_kerberos_authorize_method;

	g_type_class_add_private (klass, sizeof (RealmKerberosPrivate));

	g_object_class_install_property (object_class, PROP_NAME,
	             g_param_spec_string ("name", "Name", "Name",
	                                  NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_DISCO,
	             g_param_spec_boxed ("disco", "Discovery", "Discovery Data",
	                                 REALM_TYPE_DISCO, G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_PROVIDER,
	            g_param_spec_object ("provider", "Provider", "Realm Provider",
	                                 REALM_TYPE_PROVIDER, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_MANAGES_SYSTEM,
	            g_param_spec_boolean ("manages-system", "Manages System", "Whether domain configured to manage system",
	                                  FALSE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

void
realm_kerberos_set_disco (RealmKerberos *self,
                          RealmDisco *disco)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));

	if (disco)
		realm_disco_ref (disco);
	realm_disco_unref (self->pv->disco);
	self->pv->disco = disco;
	g_object_notify (G_OBJECT (self), "disco");
}

RealmDisco *
realm_kerberos_get_disco (RealmKerberos *self)
{
	RealmKerberosClass *klass;
	RealmDisco *disco;

	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);

	if (!self->pv->disco) {
		disco = realm_disco_new (NULL);
		if (!disco->domain_name)
			disco->domain_name = g_strdup (realm_kerberos_get_domain_name (self));
		if (!disco->kerberos_realm)
			disco->kerberos_realm = g_strdup (realm_kerberos_get_realm_name (self));
		klass = REALM_KERBEROS_GET_CLASS (self);
		if (klass && klass->discover_myself)
			(klass->discover_myself) (self, disco);
		self->pv->disco = disco;
	}

	return self->pv->disco;
}

gchar **
realm_kerberos_parse_logins (RealmKerberos *self,
                             gboolean lower,
                             const gchar **logins,
                             GError **error)
{
	const gchar *failed = NULL;
	const gchar *const *formats;
	gchar **result;

	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);

	formats = realm_dbus_realm_get_login_formats (self->pv->realm_iface);
	if (formats == NULL) {
		g_set_error (error, REALM_ERROR,
		             REALM_ERROR_NOT_CONFIGURED,
		             _("The realm does not allow specifying logins"));
		return NULL;
	}

	result = realm_login_name_parse_all (formats, lower, logins, &failed);
	if (result == NULL) {
		g_set_error (error, G_DBUS_ERROR,
		             G_DBUS_ERROR_INVALID_ARGS,
		             _("Invalid login argument%s%s%s does not match the login format."),
		             failed ? " '" : "", failed, failed ? "'" : "");
	}

	return result;
}

gchar *
realm_kerberos_format_login (RealmKerberos *self,
                             const gchar *user)
{
	const gchar *const *formats;

	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);
	g_return_val_if_fail (user != NULL, NULL);

	formats = realm_dbus_realm_get_login_formats (self->pv->realm_iface);
	if (formats == NULL || formats[0] == NULL)
		return NULL;

	return realm_login_name_format (formats[0], user);
}

static void
set_krb5_error (GError **error,
                krb5_error_code code,
                krb5_context context,
                const gchar *message,
                ...) G_GNUC_PRINTF (4, 5);

static void
set_krb5_error (GError **error,
                krb5_error_code code,
                krb5_context context,
                const gchar *message,
                ...)
{
	gchar *string;
	va_list va;

	va_start (va, message);
	string = g_strdup_vprintf (message, va);
	va_end (va);

	g_set_error (error, REALM_KRB5_ERROR, code,
	             "%s: %s", string, krb5_get_error_message (context, code));
	g_free (string);
}

const gchar *
realm_kerberos_get_name (RealmKerberos *self)
{
	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);
	return realm_dbus_realm_get_name (self->pv->realm_iface);
}

const gchar *
realm_kerberos_get_realm_name (RealmKerberos *self)
{
	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);
	return realm_dbus_kerberos_get_realm_name (self->pv->kerberos_iface);
}

void
realm_kerberos_set_realm_name (RealmKerberos *self,
                               const gchar *value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_kerberos_set_realm_name (self->pv->kerberos_iface, value);
}

const gchar *
realm_kerberos_get_domain_name (RealmKerberos *self)
{
	g_return_val_if_fail (REALM_IS_KERBEROS (self), NULL);
	return realm_dbus_kerberos_get_domain_name (self->pv->kerberos_iface);
}

void
realm_kerberos_set_domain_name (RealmKerberos *self,
                                const gchar *value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_kerberos_set_domain_name (self->pv->kerberos_iface, value);
}

gboolean
realm_kerberos_get_manages_system (RealmKerberos *self)
{
	g_return_val_if_fail (REALM_IS_KERBEROS (self), FALSE);
	return (self == realm_which_manages_system);
}

void
realm_kerberos_set_manages_system (RealmKerberos *self,
                                   gboolean manages)
{
	GObject *obj;

	g_return_if_fail (REALM_IS_KERBEROS (self));

	if (manages == realm_kerberos_get_manages_system (self))
		return;

	if (realm_which_manages_system) {
		obj = G_OBJECT (realm_which_manages_system);
		g_object_remove_weak_pointer (G_OBJECT (obj), (gpointer *)&realm_which_manages_system);
		realm_which_manages_system = NULL;
		g_object_notify (obj, "manages-system");
	}

	if (manages) {
		obj = G_OBJECT (self);
		realm_which_manages_system = self;
		g_object_add_weak_pointer (G_OBJECT (obj), (gpointer *)&realm_which_manages_system);
		g_object_notify (obj, "manages-system");
	}
}

RealmKerberos *
realm_kerberos_which_manages_system (void)
{
	return realm_which_manages_system;
}

gboolean
realm_kerberos_matches (RealmKerberos *self,
                        const gchar *string)
{
	const gchar *value;

	g_return_val_if_fail (REALM_IS_KERBEROS (self), FALSE);

	value = realm_dbus_realm_get_name (self->pv->realm_iface);
	if (value != NULL && g_utf8_collate (value, string) == 0)
		return TRUE;
	value = realm_dbus_kerberos_get_domain_name (self->pv->kerberos_iface);
	if (value != NULL && g_utf8_collate (value, string) == 0)
		return TRUE;
	value = realm_dbus_kerberos_get_realm_name (self->pv->kerberos_iface);
	if (value != NULL && g_utf8_collate (value, string) == 0)
		return TRUE;

	return FALSE;
}

void
realm_kerberos_set_suggested_admin (RealmKerberos *self,
                                    const gchar *value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	g_return_if_fail (self->pv->membership_iface != NULL);
	realm_dbus_kerberos_membership_set_suggested_administrator (self->pv->membership_iface, value);
}

void
realm_kerberos_set_permitted_logins (RealmKerberos *self,
                                     const gchar **value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_realm_set_permitted_logins (self->pv->realm_iface, (const gchar * const*)value);
}

void
realm_kerberos_set_permitted_groups (RealmKerberos *self,
                                     const gchar **value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_realm_set_permitted_groups (self->pv->realm_iface, (const gchar * const*)value);
}

const gchar *
realm_kerberos_login_policy_to_string (RealmKerberosLoginPolicy value)
{
	switch (value) {
	case REALM_KERBEROS_ALLOW_ANY_LOGIN:
		return REALM_DBUS_LOGIN_POLICY_ANY;
	case REALM_KERBEROS_ALLOW_REALM_LOGINS:
		return REALM_DBUS_LOGIN_POLICY_REALM;
	case REALM_KERBEROS_ALLOW_PERMITTED_LOGINS:
		return REALM_DBUS_LOGIN_POLICY_PERMITTED;
	case REALM_KERBEROS_DENY_ANY_LOGIN:
		return REALM_DBUS_LOGIN_POLICY_DENY;
	case REALM_KERBEROS_POLICY_NOT_SET:
		return "";
	default:
		g_return_val_if_reached ("");
	}
}

void
realm_kerberos_set_login_policy (RealmKerberos *self,
                                 RealmKerberosLoginPolicy value)
{
	realm_dbus_realm_set_login_policy (self->pv->realm_iface,
	                                   realm_kerberos_login_policy_to_string (value));
}

void
realm_kerberos_set_login_formats (RealmKerberos *self,
                                  const gchar **value)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_realm_set_login_formats (self->pv->realm_iface, (const gchar * const*)value);
}

void
realm_kerberos_set_details (RealmKerberos *self,
                            ...)
{
	GPtrArray *tuples;
	GVariant *tuple;
	GVariant *details;
	const gchar *name;
	const gchar *value;
	GVariant *values[2];
	va_list va;

	g_return_if_fail (REALM_IS_KERBEROS (self));

	va_start (va, self);
	tuples = g_ptr_array_new ();

	for (;;) {
		name = va_arg (va, const gchar *);
		if (name == NULL)
			break;
		value = va_arg (va, const gchar *);
		if (value == NULL) {
			va_end (va);
			g_return_if_reached ();
		}

		values[0] = g_variant_new_string (name);
		values[1] = g_variant_new_string (value);
		tuple = g_variant_new_tuple (values, 2);
		g_ptr_array_add (tuples, tuple);
	}
	va_end (va);

	details = g_variant_new_array (G_VARIANT_TYPE ("(ss)"),
	                               (GVariant * const *)tuples->pdata,
	                               tuples->len);

	realm_dbus_realm_set_details (self->pv->realm_iface, details);

	g_ptr_array_free (tuples, TRUE);
}

gboolean
realm_kerberos_is_configured (RealmKerberos *self)
{
	const gchar *configured;

	g_return_val_if_fail (REALM_IS_KERBEROS (self), FALSE);
	configured = realm_dbus_realm_get_configured (self->pv->realm_iface);
	return configured && !g_str_equal (configured, "");
}

void
realm_kerberos_set_configured (RealmKerberos *self,
                               gboolean configured)
{
	g_return_if_fail (REALM_IS_KERBEROS (self));
	realm_dbus_realm_set_configured (self->pv->realm_iface,
	                                 configured ? REALM_DBUS_KERBEROS_MEMBERSHIP_INTERFACE : "");
}

void
realm_kerberos_set_required_package_sets (RealmKerberos *self,
                                          const gchar **package_sets)
{
	gchar **packages;

	g_return_if_fail (REALM_IS_KERBEROS (self));
	packages = realm_packages_expand_sets (package_sets);
	realm_dbus_realm_set_required_packages (self->pv->realm_iface, (const gchar **)packages);
	g_strfreev (packages);
}

static gboolean
flush_keytab_entries (krb5_context ctx,
                      krb5_keytab keytab,
                      krb5_principal realm_princ,
                      int *remaining,
                      GError **error)
{
	krb5_error_code code;
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	int count = 0;

	code = krb5_kt_start_seq_get (ctx, keytab, &cursor);
	if (code == KRB5_KT_END || code == ENOENT ) {
		*remaining = 0;
		return TRUE;
	}

	while (!krb5_kt_next_entry (ctx, keytab, &entry, &cursor)) {
		count++;

		if (krb5_realm_compare (ctx, realm_princ, entry.principal)) {
			code = krb5_kt_end_seq_get (ctx, keytab, &cursor);
			return_val_if_krb5_failed (ctx, code, FALSE);

			code = krb5_kt_remove_entry (ctx, keytab, &entry);
			return_val_if_krb5_failed (ctx, code, FALSE);

			code = krb5_kt_start_seq_get (ctx, keytab, &cursor);
			return_val_if_krb5_failed (ctx, code, FALSE);
			count = 0;
		}

		code = krb5_kt_free_entry (ctx, &entry);
		return_val_if_krb5_failed (ctx, code, FALSE);
	}

	code = krb5_kt_end_seq_get (ctx, keytab, &cursor);
	return_val_if_krb5_failed (ctx, code, FALSE);

	*remaining = count;
	return TRUE;
}

gboolean
realm_kerberos_flush_keytab (const gchar *realm_name,
                             GError **error)
{
	char kt_name[MAX_KEYTAB_NAME_LEN];
	krb5_error_code code;
	krb5_keytab keytab;
	krb5_context ctx;
	krb5_principal princ;
	int remaining;
	gchar *name;
	gboolean ret;

	code = krb5_init_context (&ctx);
	if (code != 0) {
		set_krb5_error (error, code, NULL, "Couldn't initialize kerberos");
		return FALSE;
	}

	code = krb5_kt_default (ctx, &keytab);
	if (code != 0) {
		set_krb5_error (error, code, NULL, "Couldn't open default host keytab");
		krb5_free_context (ctx);
		return FALSE;
	}

	name = g_strdup_printf ("user@%s", realm_name);
	code = krb5_parse_name (ctx, name, &princ);
	return_val_if_krb5_failed (ctx, code, FALSE);
	g_free (name);

	ret = flush_keytab_entries (ctx, keytab, princ, &remaining, error);
	krb5_free_principal (ctx, princ);

	if (ret && remaining == 0) {
		code = krb5_kt_get_name (ctx, keytab, kt_name, sizeof (kt_name));
		return_val_if_krb5_failed (ctx, code, FALSE);
	}

	code = krb5_kt_close (ctx, keytab);
	warn_if_krb5_failed (ctx, code);

	krb5_free_context (ctx);

	if (ret && remaining == 0) {
		if (strncmp (kt_name, "FILE:", 5) == 0) {
			if (g_unlink (kt_name + 5) < 0 && errno != ENOENT) {
				g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
				             "Couldn't remove empty host keytab");
				ret = FALSE;
			}
		}
	}

	return ret;

}

gchar *
realm_kerberos_get_netbios_name_from_keytab (const gchar *realm_name)
{
	krb5_error_code code;
	krb5_keytab keytab = NULL;
	krb5_context ctx;
	krb5_kt_cursor cursor = NULL;
	krb5_keytab_entry entry;
	krb5_principal realm_princ = NULL;
	gchar *princ_name = NULL;
	gchar *netbios_name = NULL;
	krb5_data *name_data;

	code = krb5_init_context (&ctx);
	if (code != 0) {
		return NULL;
	}

	princ_name = g_strdup_printf ("user@%s", realm_name);
	code = krb5_parse_name (ctx, princ_name, &realm_princ);
	g_free (princ_name);

	if (code == 0) {
		code = krb5_kt_default (ctx, &keytab);
	}

	if (code == 0) {
		code = krb5_kt_start_seq_get (ctx, keytab, &cursor);
	}

	if (code == 0) {
		while (!krb5_kt_next_entry (ctx, keytab, &entry, &cursor) && netbios_name == NULL) {
			if (krb5_realm_compare (ctx, realm_princ, entry.principal)) {
				name_data = krb5_princ_component (ctx, entry.principal, 0);
				if (name_data != NULL
				                && name_data->length > 0
				                && name_data->data[name_data->length - 1] == '$') {
					netbios_name = g_strndup (name_data->data, name_data->length - 1);
					if (netbios_name == NULL) {
						code = krb5_kt_free_entry (ctx, &entry);
						warn_if_krb5_failed (ctx, code);
						break;
					}
				}
			}
			code = krb5_kt_free_entry (ctx, &entry);
			warn_if_krb5_failed (ctx, code);
		}
	}

	code = krb5_kt_end_seq_get (ctx, keytab, &cursor);
	warn_if_krb5_failed (ctx, code);

	code = krb5_kt_close (ctx, keytab);
	warn_if_krb5_failed (ctx, code);

	krb5_free_principal (ctx, realm_princ);

	krb5_free_context (ctx);

	return netbios_name;

}
