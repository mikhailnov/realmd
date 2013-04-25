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

#ifndef __REALM_OPTIONS_H__
#define __REALM_OPTIONS_H__

#include <gio/gio.h>

G_BEGIN_DECLS

gboolean       realm_options_manage_system            (GVariant *options,
                                                       const gchar *realm_name);

gboolean       realm_options_assume_packages          (GVariant *options);

const gchar *  realm_options_computer_ou              (GVariant *options,
                                                       const gchar *realm_name);

const gchar *  realm_options_user_principal           (GVariant *options,
                                                       const gchar *realm_name);

gboolean       realm_options_automatic_mapping        (const gchar *realm_name);

G_END_DECLS

#endif /* __REALM_OPTIONS_H__ */