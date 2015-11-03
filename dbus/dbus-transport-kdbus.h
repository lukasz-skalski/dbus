/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-transport-kdbus.h kdbus subclasses of DBusTransport
 *
 * Copyright (C) 2002, 2006  Red Hat Inc.
 * Copyright (C) 2013  Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#ifndef DBUS_TRANSPORT_KDBUS_H_
#define DBUS_TRANSPORT_KDBUS_H_

#include "../config.h"
#include "dbus-transport-protected.h"
#include <linux/types.h>

#define REGISTER_FLAG_MONITOR       1 << 0

__u64 dbus_transport_get_bloom_size(DBusTransport* transport);
__u64 dbus_transport_get_bloom_n_hash(DBusTransport* transport);
void* dbus_transport_get_pool_pointer(DBusTransport* transport);
DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry *entry, DBusTransport **transport_p, DBusError *error);
DBusWatch * dbus_transport_get_read_watch(DBusTransport* transport);
char* dbus_transport_get_activator_name(DBusTransport *transport);

#endif
