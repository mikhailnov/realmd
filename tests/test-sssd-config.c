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

#include "service/realm-settings.h"
#include "service/realm-sssd-config.h"

#include <glib/gstdio.h>

#include <string.h>

typedef struct {
	RealmIniConfig *config;
} Test;

static void
setup (Test *test,
       gconstpointer unused)
{
	test->config = realm_ini_config_new (REALM_INI_NO_WATCH);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_object_unref (test->config);
}

static void
test_get_domains (Test *test,
                  gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[domain/two]\nval=2\n[domain/three]\nval=3\n[sssd]\ndomains=one, two";
	gchar **domains;

	realm_ini_config_read_string (test->config, data);

	domains = realm_sssd_config_get_domains (test->config);
	g_assert (domains != NULL);
	g_assert_cmpstr (domains[0], ==, "one");
	g_assert_cmpstr (domains[1], ==, "two");
	g_assert (domains[2] == NULL);

	g_strfreev (domains);
}

static void
test_domain_section (Test *test,
                     gconstpointer unused)
{
	gchar *section;

	section = realm_sssd_config_domain_to_section ("domain");
	g_assert_cmpstr (section, ==, "domain/domain");
	g_free (section);

	section = realm_sssd_config_domain_to_section ("Another");
	g_assert_cmpstr (section, ==, "domain/Another");
	g_free (section);
}

static void
test_have_domain (Test *test,
                  gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[domain/two]\nval=2\n[domain/three]\nval=3\n[sssd]\ndomains=one, two";

	realm_ini_config_read_string (test->config, data);
	g_assert (realm_sssd_config_have_domain (test->config, "one") == TRUE);
	g_assert (realm_sssd_config_have_domain (test->config, "two") == TRUE);
	g_assert (realm_sssd_config_have_domain (test->config, "three") == FALSE);
	g_assert (realm_sssd_config_have_domain (test->config, "non-existant") == FALSE);
}

static void
test_add_domain (Test *test,
                 gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains=one";
	const gchar *check = "[domain/one]\nval=1\n[sssd]\ndomains = one, two\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/two]\ndos = 2\n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (realm_sssd_config_have_domain (test->config, "one") == TRUE);
	ret = realm_sssd_config_add_domain (test->config, "two", &error,
	                                    "dos", "2",
	                                    NULL);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (check, ==, output);
	g_free (output);
}

static void
test_add_domain_already (Test *test,
                         gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains=one";
	GError *error = NULL;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_add_domain (test->config, "one", &error,
	                                    "uno", "1",
	                                    NULL);
	g_assert_error (error, G_FILE_ERROR, G_FILE_ERROR_EXIST);
	g_assert (ret == FALSE);
}


static void
test_add_domain_only (Test *test,
                      gconstpointer unused)
{
	const gchar *check = "\n[sssd]\ndomains = two\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/two]\ndos = 2\n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_add_domain (test->config, "two", &error,
	                                    "dos", "2",
	                                    NULL);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (check, ==, output);
	g_free (output);
}

static void check_for_test_update_domain (char *new)
{
	char *token;
	char *saveptr;
	size_t c;
	int result = 0;

	token = strtok_r (new, "\n", &saveptr);
	g_assert_nonnull (token);
	g_assert_cmpstr (token, ==, "[domain/one]");

	for (c = 0; c < 3; c++) {
		token = strtok_r (NULL, "\n", &saveptr);
		g_assert_nonnull (token);
		if (strcmp (token, "val=1") == 0) {
			result += 1;
		} else if (strcmp (token, "uno = 1") == 0) {
			result += 2;
		} else if (strcmp (token, "eins = one") == 0) {
			result += 4;
		} else {
			g_assert_not_reached ();
		}
	}
	g_assert_cmpint (result, ==, 7);

	token = strtok_r (NULL, "\n", &saveptr);
	g_assert_nonnull (token);
	g_assert_cmpstr (token, ==, "[sssd]");

	token = strtok_r (NULL, "\n", &saveptr);
	g_assert_nonnull (token);
	g_assert_cmpstr (token, ==, "domains=one");

	token = strtok_r (NULL, "\n", &saveptr);
	g_assert_null (token);
}

static void
test_update_domain (Test *test,
                    gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains=one";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (realm_sssd_config_have_domain (test->config, "one") == TRUE);
	ret = realm_sssd_config_update_domain (test->config, "one", &error,
	                                       "uno", "1",
	                                       "eins", "one",
	                                       NULL);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	check_for_test_update_domain (output);
	g_free (output);
}

static void
test_update_domain_missing (Test *test,
                            gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains=one";
	GError *error = NULL;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (realm_sssd_config_have_domain (test->config, "another") == FALSE);
	ret = realm_sssd_config_update_domain (test->config, "another", &error,
	                                       "uno", "1",
	                                       "eins", "one",
	                                       NULL);
	g_assert_error (error, G_FILE_ERROR, G_FILE_ERROR_NOENT);
	g_assert (ret == FALSE);
}

static void
test_remove_domain (Test *test,
                    gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains=one, two\n[domain/two]\ndos=2\n";
	const gchar *check = "[sssd]\ndomains = two\n[domain/two]\ndos=2\n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_remove_domain (test->config, "one", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (check, ==, output);
	g_free (output);
}

static void
test_remove_domain_not_exist (Test *test,
                              gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval=1\n[sssd]\ndomains = two\n[domain/two]\ndos=2\n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_remove_domain (test->config, "nonexistant", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (data, ==, output);
	g_free (output);
}


static void
test_remove_domain_only (Test *test,
                         gconstpointer unused)
{
	const gchar *data = "[sssd]\ndomains = two\n[domain/two]\ndos=2\n";
	const gchar *check = "[sssd]\ndomains = \n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_remove_domain (test->config, "two", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_ini_config_write_file (test->config, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (check, ==, output);
	g_free (output);
}

static void
test_remove_and_add_domain (Test *test,
                        gconstpointer unused)
{
	const gchar *data = "[domain/one]\nval = 1\n\n[nss]\ndefault_shell = /bin/bash\n\n[sssd]\ndomains = one, two\nconfig_file_version = 2\nservices = nss, pam\n\n[domain/two]\nval = 2\n";
	GError *error = NULL;
	gchar *output;
	gboolean ret;

	realm_ini_config_read_string (test->config, data);
	ret = realm_ini_config_write_file (test->config, "/tmp/test-sssd.conf", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_remove_domain (test->config, "two", &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = realm_sssd_config_add_domain (test->config, "two", &error,
	                                    "val", "2",
	                                    NULL);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	ret = g_file_get_contents ("/tmp/test-sssd.conf", &output, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert_cmpstr (output, ==, data);
	g_free (output);
}

int
main (int argc,
      char **argv)
{
#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-sssd-config");

	realm_settings_init ();

	g_test_add ("/realmd/sssd-config/get-domains", Test, NULL, setup, test_get_domains, teardown);
	g_test_add ("/realmd/sssd-config/domain-section", Test, NULL, setup, test_domain_section, teardown);
	g_test_add ("/realmd/sssd-config/have-domain", Test, NULL, setup, test_have_domain, teardown);
	g_test_add ("/realmd/sssd-config/add-domain", Test, NULL, setup, test_add_domain, teardown);
	g_test_add ("/realmd/sssd-config/add-domain-already", Test, NULL, setup, test_add_domain_already, teardown);
	g_test_add ("/realmd/sssd-config/add-domain-only", Test, NULL, setup, test_add_domain_only, teardown);
	g_test_add ("/realmd/sssd-config/update-domain", Test, NULL, setup, test_update_domain, teardown);
	g_test_add ("/realmd/sssd-config/update-domain-missing", Test, NULL, setup, test_update_domain_missing, teardown);
	g_test_add ("/realmd/sssd-config/remove-domain", Test, NULL, setup, test_remove_domain, teardown);
	g_test_add ("/realmd/sssd-config/remove-domain-not-exist", Test, NULL, setup, test_remove_domain_not_exist, teardown);
	g_test_add ("/realmd/sssd-config/remove-domain-only", Test, NULL, setup, test_remove_domain_only, teardown);
	g_test_add ("/realmd/sssd-config/remove-and-add-domain", Test, NULL, setup, test_remove_and_add_domain, teardown);

	return g_test_run ();
}
