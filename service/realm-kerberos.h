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

#ifndef __REALM_KERBEROS_H__
#define __REALM_KERBEROS_H__

#include <gio/gio.h>

#include <krb5/krb5.h>

#include "realm-dbus-generated.h"
#include "realm-disco.h"

G_BEGIN_DECLS

typedef enum {
	REALM_KERBEROS_POLICY_NOT_SET = 0,
	REALM_KERBEROS_ALLOW_ANY_LOGIN = 1,
	REALM_KERBEROS_ALLOW_REALM_LOGINS,
	REALM_KERBEROS_ALLOW_PERMITTED_LOGINS,
	REALM_KERBEROS_DENY_ANY_LOGIN,
} RealmKerberosLoginPolicy;

#define REALM_TYPE_KERBEROS            (realm_kerberos_get_type ())
#define REALM_KERBEROS(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), REALM_TYPE_KERBEROS, RealmKerberos))
#define REALM_IS_KERBEROS(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), REALM_TYPE_KERBEROS))
#define REALM_KERBEROS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), REALM_TYPE_KERBEROS, RealmKerberosClass))
#define REALM_IS_KERBEROS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), REALM_TYPE_KERBEROS))
#define REALM_KERBEROS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), REALM_TYPE_KERBEROS, RealmKerberosClass))

typedef struct _RealmKerberos RealmKerberos;
typedef struct _RealmKerberosClass RealmKerberosClass;
typedef struct _RealmKerberosPrivate RealmKerberosPrivate;

struct _RealmKerberos {
	GDBusObjectSkeleton parent;
	RealmKerberosPrivate *pv;
};

struct _RealmKerberosClass {
	GDBusObjectSkeletonClass parent_class;

	void       (* logins_async)             (RealmKerberos *realm,
	                                         GDBusMethodInvocation *invocation,
	                                         RealmKerberosLoginPolicy login_policy,
	                                         const gchar **permitted_add,
	                                         const gchar **permitted_remove,
	                                         GVariant *options,
	                                         GAsyncReadyCallback callback,
	                                         gpointer user_data);

	gboolean   (* logins_finish)            (RealmKerberos *realm,
	                                         GAsyncResult *result,
	                                         GError **error);

	void       (* discover_myself)          (RealmKerberos *realm,
	                                         RealmDisco *disco);
};

GType               realm_kerberos_get_type              (void) G_GNUC_CONST;

void                realm_kerberos_set_disco             (RealmKerberos *self,
                                                          RealmDisco *disco);

RealmDisco *        realm_kerberos_get_disco             (RealmKerberos *self);

gchar **            realm_kerberos_parse_logins          (RealmKerberos *self,
                                                          gboolean lower,
                                                          const gchar **logins,
                                                          GError **error);

gchar *             realm_kerberos_format_login          (RealmKerberos *self,
                                                          const gchar *user);

gboolean            realm_kerberos_flush_keytab                (const gchar *realm_name,
                                                                GError **error);

gchar *             realm_kerberos_get_netbios_name_from_keytab (const gchar *realm_name);

const gchar *       realm_kerberos_get_name                    (RealmKerberos *self);

const gchar *       realm_kerberos_get_realm_name              (RealmKerberos *self);

void                realm_kerberos_set_realm_name              (RealmKerberos *self,
                                                                const gchar *value);

const gchar *       realm_kerberos_get_domain_name             (RealmKerberos *self);

void                realm_kerberos_set_domain_name             (RealmKerberos *self,
                                                                const gchar *value);

gboolean            realm_kerberos_get_manages_system          (RealmKerberos *self);

void                realm_kerberos_set_manages_system          (RealmKerberos *self,
                                                                gboolean manages);

RealmKerberos *     realm_kerberos_which_manages_system        (void);

void                realm_kerberos_set_suggested_admin         (RealmKerberos *self,
                                                                const gchar *value);

void                realm_kerberos_set_permitted_logins        (RealmKerberos *self,
                                                                const gchar **value);

void                realm_kerberos_set_permitted_groups        (RealmKerberos *self,
                                                                const gchar **value);

void                realm_kerberos_set_login_policy            (RealmKerberos *self,
                                                                RealmKerberosLoginPolicy value);

const gchar *       realm_kerberos_login_policy_to_string      (RealmKerberosLoginPolicy value);

void                realm_kerberos_set_login_formats           (RealmKerberos *self,
                                                                const gchar **value);

void                realm_kerberos_set_details                 (RealmKerberos *self,
                                                                ...) G_GNUC_NULL_TERMINATED;

gboolean            realm_kerberos_is_configured               (RealmKerberos *self);

void                realm_kerberos_set_configured              (RealmKerberos *self,
                                                                gboolean configured);

void                realm_kerberos_set_required_package_sets   (RealmKerberos *self,
                                                                const gchar **package_sets);

gboolean            realm_kerberos_matches                     (RealmKerberos *self,
                                                                const gchar *string);

G_END_DECLS

#endif /* __REALM_KERBEROS_H__ */
