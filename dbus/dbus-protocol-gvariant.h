/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-protocol.h  D-Bus protocol constants
 *
 * Copyright (C) 2015  Samsung Electronics
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

#ifndef DBUS_PROTOCOL_GVARIANT_H
#define DBUS_PROTOCOL_GVARIANT_H

#define DBUS_PROTOCOL_VERSION_GVARIANT 2

/** Header format is defined as a signature:
 *   byte                            byte order
 *   byte                            message type ID
 *   byte                            flags
 *   byte                            protocol version
 *   uint64                          cookie
 *   array of dict entries (uint64,variant)  (field name, value)
 *
 * The length of the header can be computed as the
 * fixed size of the initial data, plus the length of
 * the array at the end, plus padding to an 8-boundary.
 */
#define DBUS_HEADER_GVARIANT_SIGNATURE                   \
     DBUS_TYPE_BYTE_AS_STRING                   \
     DBUS_TYPE_BYTE_AS_STRING                   \
     DBUS_TYPE_BYTE_AS_STRING                   \
     DBUS_TYPE_BYTE_AS_STRING                   \
     DBUS_TYPE_UINT64_AS_STRING                 \
     DBUS_TYPE_ARRAY_AS_STRING                  \
     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING       \
     DBUS_TYPE_BYTE_AS_STRING                   \
     DBUS_TYPE_VARIANT_AS_STRING                \
     DBUS_DICT_ENTRY_END_CHAR_AS_STRING         \
     DBUS_TYPE_VARIANT_AS_STRING

#define FIRST_GVARIANT_FIELD_OFFSET  16 /* yyyyut is before a{tv}*/

#endif /* DBUS_PROTOCOL_GVARIANT_H */
