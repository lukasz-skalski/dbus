/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-marshal-gvariant.h  Managing GVariant marshaling/demarshaling of messages
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

#ifndef DBUS_MARSHAL_GVARIANT_H
#define DBUS_MARSHAL_GVARIANT_H

#include <dbus/dbus-marshal-header.h>
#include <dbus/dbus-marshal-recursive.h>
#include <dbus/dbus-message.h>
#include <dbus/dbus-connection.h>

const DBusString *_dbus_get_gvariant_header_signature_str (void);

dbus_bool_t   _dbus_header_gvariant_create           (DBusHeader     *header,
                                                      int             byte_order,
                                                      int             type,
                                                      const char     *destination,
                                                      const char     *path,
                                                      const char     *interface,
                                                      const char     *member,
                                                      const char     *error_name);

dbus_bool_t   _dbus_type_writer_write_gvariant_basic (DBusTypeWriter *writer,
                                                      int             type,
                                                      const void     *value);

dbus_bool_t   _dbus_marshal_write_gvariant_basic     (DBusString     *str,
                                                      int             insert_at,
                                                      int             type,
                                                      const void     *value,
                                                      int             byte_order,
                                                      int            *pos_after);

dbus_bool_t   _dbus_header_set_field_basic_gvariant  (DBusHeader     *header,
                                                      int             field,
                                                      int             type,
                                                      const void     *value);

dbus_bool_t   _dbus_header_get_field_basic_gvariant  (DBusHeader     *header,
                                                      int             field,
                                                      int             type,
                                                      void           *value);

dbus_bool_t   _dbus_header_gvariant_delete_field     (DBusHeader *header,
                                                      int field);

void          _dbus_marshal_read_gvariant_basic      (const DBusString *str,
                                                      int               pos,
                                                      int               type,
                                                      void             *value,
                                                      int               byte_order,
                                                      int              *new_pos);

void          _dbus_marshal_skip_gvariant_basic      (const DBusString *str,
                                                      int               type,
                                                      int               byte_order,
                                                      int              *pos);

dbus_bool_t   _dbus_header_load_gvariant             (DBusHeader     *header,
                                                      DBusTypeReader *reader,
                                                      DBusValidity   *validity);

dbus_bool_t   _dbus_gvariant_raw_get_lengths         (const DBusString *str,
                                                      dbus_uint32_t    *fields_array_len_unsigned,
                                                      dbus_uint32_t    *body_len_unsigned,
                                                      DBusValidity     *validity);

DBusValidity  _dbus_validate_gvariant_body_with_reason (const DBusString *expected_signature,
                                                        int               expected_signature_start,
                                                        int               byte_order,
                                                        int              *bytes_remaining,
                                                        const DBusString *value_str,
                                                        int               value_pos,
                                                        int               len);

dbus_bool_t  _dbus_message_gvariant_get_signature    (DBusMessage       *message,
                                                      const DBusString **type_str_p,
                                                      int               *type_pos_p,
                                                      int               *type_str_len);

dbus_bool_t  _dbus_message_gvariant_add_signature    (DBusMessage       *message,
                                                       const DBusString  *type_str);

dbus_bool_t  _dbus_message_append_body_offset                   (DBusMessage *message);
dbus_bool_t  _dbus_message_gvariant_remove_body_offset          (DBusMessage       *message);

dbus_bool_t  _dbus_message_finalize_gvariant                    (DBusMessage *message,
                                                                 dbus_bool_t  remove_signature_from_header);

size_t       _dbus_reader_get_offset_of_end_of_variable         (DBusTypeReader *reader);
int          _dbus_reader_get_type_fixed_size                   (DBusTypeReader *reader,
                                                                 int            *alignment);

int          _dbus_type_gvariant_get_fixed_size                 (const DBusString *type_str,
                                                                 int         type_pos,
                                                                 int        *alignment);

int          _dbus_reader_count_offsets                         (const DBusTypeReader *reader);

int          _dbus_reader_count_array_elems                     (const DBusTypeReader *reader);

dbus_bool_t  _dbus_type_writer_gvariant_write_basic_no_typecode (DBusTypeWriter *writer,
                                                                 int             type,
                                                                 const void     *value);

dbus_bool_t  _dbus_writer_unrecurse_gvariant_write              (DBusTypeWriter *writer,
                                                                 DBusTypeWriter *sub);

void         _dbus_type_reader_gvariant_init                    (DBusTypeReader        *reader,
                                                                 DBusMessage           *message);

#endif /* DBUS_MARSHAL_GVARIANT_H */
