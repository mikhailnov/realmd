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

#include "realm-errors.h"
#include "realm-ini-config.h"
#include "realm-sssd-config.h"
#include "realm-settings.h"

#include <glib/gi18n.h>

#include <string.h>

RealmIniConfig *
realm_sssd_config_new_with_flags (RealmIniFlags flags,
                                  GError **error)
{
	RealmIniConfig *config;
	const gchar *filename;
	GError *err = NULL;

	config = realm_ini_config_new (flags | REALM_INI_PRIVATE | REALM_INI_STRICT_BOOLEAN);

	filename = realm_settings_path ("sssd.conf");
	realm_ini_config_read_file (config, filename, &err);

	if (err != NULL) {
		/* If the caller wants errors, then don't return an invalid samba config */
		if (error) {
			g_propagate_error (error, err);
			g_object_unref (config);
			config = NULL;

		/* If the caller doesn't care, then warn but continue */
		} else {
			g_warning ("Couldn't load config file: %s: %s", filename,
			           err->message);
			g_error_free (err);
		}
	}

	return config;
}

RealmIniConfig *
realm_sssd_config_new (GError **error)
{
	return realm_sssd_config_new_with_flags (REALM_INI_NONE, error);
}

gchar **
realm_sssd_config_get_domains (RealmIniConfig *config)
{
	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), NULL);
	return realm_ini_config_get_list (config, "sssd", "domains", ",");
}

gchar *
realm_sssd_config_domain_to_section (const gchar *domain)
{
	g_return_val_if_fail (domain != NULL, NULL);
	return g_strdup_printf ("domain/%s", domain);
}

gboolean
realm_sssd_config_have_domain (RealmIniConfig *config,
                               const gchar *domain)
{
	gchar **domains;
	gboolean have = FALSE;
	gint i;

	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);

	domains = realm_sssd_config_get_domains (config);
	for (i = 0; domains && domains[i] != NULL; i++) {
		if (g_str_equal (domain, domains[i])) {
			have = TRUE;
			break;
		}
	}
	g_strfreev (domains);

	return have;
}

static gboolean
update_domain (RealmIniConfig *config,
               const char *section,
               va_list va,
               GError **error)
{
	GHashTable *parameters;
	const gchar *name;
	const gchar *value;

	parameters = g_hash_table_new (g_str_hash, g_str_equal);
	while ((name = va_arg (va, const gchar *)) != NULL) {
		value = va_arg (va, const gchar *);
		g_hash_table_insert (parameters, (gpointer)name, (gpointer)value);
	}

	realm_ini_config_set_all (config, section, parameters);
	g_hash_table_unref (parameters);

	return realm_ini_config_finish_change (config, error);

}

gboolean
realm_sssd_config_add_domain (RealmIniConfig *config,
                              const gchar *domain,
                              GError **error,
                              ...)
{
	const gchar *domains[2];
	gchar **already;
	gboolean ret;
	gchar *section;
	const gchar *services[] = { "nss", "pam", NULL };
	va_list va;
	gint i;

	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!realm_ini_config_begin_change (config, error))
		return FALSE;

	already = realm_sssd_config_get_domains (config);
	for (i = 0; already && already[i] != NULL; i++) {
		if (g_str_equal (domain, already[i])) {
			realm_ini_config_abort_change (config);
			g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_EXIST,
			             _("Already have domain %s in sssd.conf config file"), domain);
			g_strfreev (already);
			return FALSE;
		}
	}

	g_strfreev (already);

	/* Setup a default sssd section */
	realm_ini_config_set_list_diff (config, "sssd", "services", ", ", services, NULL);
	if (!realm_ini_config_have (config, "sssd", "config_file_version"))
		realm_ini_config_set (config, "sssd", "config_file_version", "2", NULL);

	domains[0] = domain;
	domains[1] = NULL;
	realm_ini_config_set_list_diff (config, "sssd", "domains", ", ", domains, NULL);

	section = realm_sssd_config_domain_to_section (domain);

	va_start (va, error);
	ret = update_domain (config, section, va, error);
	va_end (va);

	g_free (section);

	return ret;
}

gboolean
realm_sssd_config_update_domain (RealmIniConfig *config,
                                 const gchar *domain,
                                 GError **error,
                                 ...)
{
	gchar *section;
	gboolean ret;
	va_list va;

	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!realm_ini_config_begin_change (config, error))
		return FALSE;

	section = realm_sssd_config_domain_to_section (domain);
	if (!realm_ini_config_have_section (config, section)) {
		realm_ini_config_abort_change (config);
		g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_NOENT,
		             _("Don't have domain %s in sssd.conf config file"), domain);
		g_free (section);
		return FALSE;
	}

	va_start (va, error);
	ret = update_domain (config, section, va, error);
	va_end (va);

	g_free (section);

	return ret;
}

gboolean
realm_sssd_config_remove_domain (RealmIniConfig *config,
                                 const gchar *domain,
                                 GError **error)
{
	const gchar *domains[2];
	gchar *section;

	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!realm_ini_config_begin_change (config, error))
		return FALSE;

	section = realm_sssd_config_domain_to_section (domain);

	domains[0] = domain;
	domains[1] = NULL;
	realm_ini_config_set_list_diff (config, "sssd", "domains", ", ", NULL, domains);
	realm_ini_config_remove_section (config, section);
	g_free (section);

	return realm_ini_config_finish_change (config, error);
}

gboolean
realm_sssd_config_load_domain (RealmIniConfig *config,
                               const gchar *domain,
                               gchar **out_section,
                               gchar **id_provider,
                               gchar **realm_name)
{
	const gchar *field_name;
	gchar *section;
	gchar *type;
	gchar *name;

	g_return_val_if_fail (REALM_IS_INI_CONFIG (config), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);

	section = realm_sssd_config_domain_to_section (domain);
	type = realm_ini_config_get (config, section, "id_provider");

	if (g_strcmp0 (type, "ad") == 0) {
		field_name = "ad_domain";

	} else if (g_strcmp0 (type, "ipa") == 0) {
		field_name = "ipa_domain";

	} else {
		g_free (section);
		g_free (type);
		return FALSE;
	}

	name = realm_ini_config_get (config, section, field_name);
	if (name == NULL)
		name = realm_ini_config_get (config, section, "krb5_realm");
	if (name == NULL)
		name = g_strdup (domain);

	if (realm_name) {
		*realm_name = name;
		name = NULL;
	}

	if (id_provider) {
		*id_provider = type;
		type = NULL;
	}

	if (out_section) {
		*out_section = section;
		section = NULL;
	}

	g_free (type);
	g_free (section);
	g_free (name);
	return TRUE;
}
