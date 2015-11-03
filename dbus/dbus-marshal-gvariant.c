/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-marshal-gvariant.c  Marshalling routines for GVariant protocol
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

#include <config.h>
#include "dbus-internals.h"
#include "dbus-marshal-gvariant.h"
#include "dbus-protocol-gvariant.h"
#include "dbus-marshal-basic.h"
#include "dbus-message-private.h"
#include "dbus-signature.h"
#include "dbus-connection-internal.h"
#include <endian.h>

/** Static #DBusString containing the signature of a message header */
_DBUS_STRING_DEFINE_STATIC(_dbus_header_gvariant_signature_str, DBUS_HEADER_GVARIANT_SIGNATURE);

#define FIELD_ID_SIZE sizeof(dbus_uint64_t)

const DBusString *
_dbus_get_gvariant_header_signature_str (void)
{
  return &_dbus_header_gvariant_signature_str;
}

static dbus_bool_t
append_sized_value (DBusString *str,
                    size_t value,
                    size_t value_size)
{
  /* always write as little endian */
  int i;
  for (i = 0; i < value_size; i++)
  {
    size_t move = 8 * i;
    size_t mask = 0xFF << move;
    if (!_dbus_string_append_byte(str, (value & mask) >> move))
      return FALSE;
  }
  return TRUE;
}

#define MAX_OFFSET_SIZE 8
#define MAX_VALUE_FOR_OFFSET_SIZE(o) ((1ULL<<(8*(o)))-1)

/* taken from systemd */
static size_t
bus_gvariant_determine_word_size(size_t sz, size_t extra)
{
  if (sz + extra <= 0xFF)
    return 1;
  else if (sz + extra*2 <= 0xFFFF)
    return 2;
  else if (sz + extra*4 <= 0xFFFFFFFF)
    return 4;
  else
    return 8;
}

/* taken from systemd */
static size_t
bus_gvariant_read_word_le (const void *p, size_t sz)
{
  union {
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
  } x;

  // FIXME
//  assert(p);

  if (sz == 1)
    return *(uint8_t*) p;

  memcpy(&x, p, sz);

  if (sz == 2)
    return le16toh(x.u16);
  else if (sz == 4)
    return le32toh(x.u32);
  else if (sz == 8)
    return le64toh(x.u64);
  return 0;
}

static const char *
get_header_const_array (DBusHeader *header)
{
  return _dbus_string_get_const_data (&header->data) + FIRST_GVARIANT_FIELD_OFFSET;
}

static size_t
get_header_array_size (DBusHeader *header)
{
  return _dbus_string_get_length (&header->data) - FIRST_GVARIANT_FIELD_OFFSET - header->padding;
}

static dbus_bool_t
append_offsets (DBusString *str,
                size_t *fields_offsets,
                size_t n_fields_offsets)
{
  int i;
  size_t array_size = _dbus_string_get_length (str) - FIRST_GVARIANT_FIELD_OFFSET;
  size_t offset_size = bus_gvariant_determine_word_size (array_size, n_fields_offsets);

  for (i = 0; i < n_fields_offsets; i++)
  {
    if (!append_sized_value (str, fields_offsets[i], offset_size))
      return FALSE;
  }
  return TRUE;
}

static dbus_bool_t
append_field_string (DBusString *str,
              dbus_uint64_t field,
              const char *value,
              char type,
              size_t *fields_offsets,
              size_t *n_fields_offsets)
{
  dbus_bool_t res = TRUE;
  if (value != NULL)
  {
    res = res && _dbus_string_align_length(str, 8);
    res = res && append_sized_value(str, field, FIELD_ID_SIZE);
    res = res && _dbus_string_append_len(str, value, strlen(value)+1);
    res = res && _dbus_string_append_byte(str, 0); /* variant value-signature separator */
    res = res && _dbus_string_append_byte(str, type);
    fields_offsets[(*n_fields_offsets)++] = _dbus_string_get_length(str) - FIRST_GVARIANT_FIELD_OFFSET;
  }
  return res;
}

static dbus_bool_t
append_field_uint64 (DBusString *str,
              dbus_uint64_t field,
              dbus_uint64_t value,
              size_t *fields_offsets,
              size_t *n_fields_offsets)
{
  dbus_bool_t res = TRUE;
  res = res && _dbus_string_align_length(str, 8);
  res = res && append_sized_value(str, field, FIELD_ID_SIZE);
  res = res && append_sized_value(str, value, 8);
  res = res && _dbus_string_append_byte(str, 0); /* variant value-signature separator */
  res = res && _dbus_string_append_byte(str, DBUS_TYPE_UINT64);
  fields_offsets[(*n_fields_offsets)++] = _dbus_string_get_length(str) - FIRST_GVARIANT_FIELD_OFFSET;
  return res;
}

static dbus_bool_t
append_field_uint32 (DBusString *str,
              dbus_uint64_t field,
              dbus_uint32_t value,
              size_t *fields_offsets,
              size_t *n_fields_offsets)
{
  dbus_bool_t res = TRUE;
  res = res && _dbus_string_align_length(str, 8);
  res = res && append_sized_value(str, field, FIELD_ID_SIZE);
  res = res && append_sized_value(str, value, 4);
  res = res && _dbus_string_append_byte(str, 0); /* variant value-signature separator */
  res = res && _dbus_string_append_byte(str, DBUS_TYPE_UINT32);

  fields_offsets[(*n_fields_offsets)++] = _dbus_string_get_length(str) - FIRST_GVARIANT_FIELD_OFFSET;
  return res;
}

static void
_dbus_header_toggle_gvariant (DBusHeader *header, dbus_bool_t gvariant)
{
#ifdef ENABLE_KDBUS_TRANSPORT
  header->protocol_version = gvariant ? DBUS_PROTOCOL_VERSION_GVARIANT : DBUS_MAJOR_PROTOCOL_VERSION;
#endif
}

static const char *
get_next_field_address (const char *array_buffer, size_t offset)
{
  return array_buffer + _DBUS_ALIGN_VALUE(offset, 8);
}

static dbus_uint64_t
get_field_after (const char *array_buffer, size_t offset)
{
  return *(dbus_uint64_t*)(get_next_field_address(array_buffer, offset));
}

static void
_dbus_header_fill_cache (DBusHeader *header,
                         size_t     *fields_offsets,
                         size_t      n_fields_offsets)
{
  const char *array_buffer = get_header_const_array (header);
  int i;

  if (get_header_array_size (header) > 0)
  {
    header->fields[get_field_after (array_buffer, 0)].value_pos = FIELD_ID_SIZE + FIRST_GVARIANT_FIELD_OFFSET;
    for (i=0; i < n_fields_offsets-1; i++)
    {
      dbus_uint64_t field = get_field_after (array_buffer, fields_offsets[i]);
      header->fields[field].value_pos = _DBUS_ALIGN_VALUE(fields_offsets[i],8) +
                                        FIELD_ID_SIZE + FIRST_GVARIANT_FIELD_OFFSET;
    }
  }
}

static dbus_bool_t
correct_header_padding (DBusHeader *header)
{
  int unpadded_len = _dbus_string_get_length (&header->data);
  if (!_dbus_string_align_length (&header->data, 8))
	  return FALSE;

  header->padding = _dbus_string_get_length (&header->data) - unpadded_len;
  return TRUE;
}

dbus_bool_t
_dbus_header_gvariant_create (DBusHeader        *header,
                              int                byte_order,
                              int                type,
                              const char        *destination,
                              const char        *path,
                              const char        *interface,
                              const char        *member,
                              const char        *error_name)
{
  size_t fields_offsets[DBUS_HEADER_FIELD_LAST];
  size_t n_fields_offsets = 0;
  dbus_bool_t res = TRUE;

  _dbus_assert (byte_order == DBUS_LITTLE_ENDIAN ||
                byte_order == DBUS_BIG_ENDIAN);
  _dbus_assert (((interface || type != DBUS_MESSAGE_TYPE_SIGNAL) && member) ||
                (error_name) ||
                !(interface || member || error_name));
  _dbus_assert (_dbus_string_get_length (&header->data) == 0);

  _dbus_header_toggle_gvariant (header, TRUE);

  res = res && _dbus_string_append_byte (&header->data, byte_order);
  res = res && _dbus_string_append_byte (&header->data, type);
  res = res && _dbus_string_append_byte (&header->data, 0);   /* flags */
  res = res && _dbus_string_append_byte (&header->data, DBUS_PROTOCOL_VERSION_GVARIANT);
  res = res && append_sized_value (&header->data, 0, sizeof(dbus_uint32_t));    /* reserved */
  res = res && append_sized_value (&header->data, 0, sizeof(dbus_uint64_t));    /* cookie */
  /* array of fields */
  res = res && append_field_string (&header->data, DBUS_HEADER_FIELD_PATH, path, DBUS_TYPE_OBJECT_PATH,
                      fields_offsets, &n_fields_offsets);
  res = res && append_field_string (&header->data, DBUS_HEADER_FIELD_DESTINATION, destination, DBUS_TYPE_STRING,
                      fields_offsets, &n_fields_offsets);
  res = res && append_field_string (&header->data, DBUS_HEADER_FIELD_INTERFACE, interface, DBUS_TYPE_STRING,
                      fields_offsets, &n_fields_offsets);
  res = res && append_field_string (&header->data, DBUS_HEADER_FIELD_MEMBER, member, DBUS_TYPE_STRING,
                      fields_offsets, &n_fields_offsets);
  res = res && append_field_string (&header->data, DBUS_HEADER_FIELD_ERROR_NAME, error_name, DBUS_TYPE_STRING,
                      fields_offsets, &n_fields_offsets);
  res = res && append_offsets (&header->data, fields_offsets, n_fields_offsets);

  _dbus_header_fill_cache (header, fields_offsets, n_fields_offsets);
  res = res && correct_header_padding (header);

  return res;
}

static dbus_bool_t
marshal_gvariant_string (DBusString    *str,
                         int            insert_at,
                         const char    *value,
                         int           *pos_after,
                         dbus_bool_t    with_nul)
{
  DBusString value_str;
  size_t value_len = strlen(value);

  if (with_nul)
    value_len++;

  _dbus_string_init_const_len (&value_str, value, value_len);
  if (!_dbus_string_copy_len (&value_str, 0, value_len, str, insert_at))
  {
    return FALSE;
  }

  if (pos_after)
    *pos_after = insert_at + value_len;

  return TRUE;
}

dbus_bool_t
_dbus_marshal_write_gvariant_basic (DBusString *str,
                                    int         insert_at,
                                    int         type,
                                    const void *value,
                                    int         byte_order,
                                    int        *pos_after)
{
  const DBusBasicValue *vp;
  _dbus_assert (dbus_type_is_basic (type));

  vp = value;

  switch (type)
  {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
      return marshal_gvariant_string (str, insert_at, vp->str, pos_after, TRUE);
    case DBUS_TYPE_BOOLEAN:
      if (pos_after)
        (*pos_after)++;
      return _dbus_string_insert_byte (str, insert_at, vp->u32 != FALSE);
    default:
      return _dbus_marshal_write_basic (str, insert_at, type, value, byte_order, pos_after);
  }
}

void
_dbus_marshal_read_gvariant_basic (const DBusString *str,
                                    int               pos,
                                    int               type,
                                    void             *value,
                                    int               byte_order,
                                    int              *new_pos)
{
  const char *str_data;

  _dbus_assert (dbus_type_is_basic (type));

  str_data = _dbus_string_get_const_data (str);
  switch (type)
  {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
      {
        volatile char **vp = value;
        *vp = (char*) str_data + pos;
        pos += strlen (str_data+pos)+1;
      }
      break;
    case DBUS_TYPE_BOOLEAN:
      {
        volatile dbus_bool_t *vp = value;
        *vp = (dbus_bool_t) _dbus_string_get_byte (str, pos);
        (pos)++;
      }
      break;
    default:
      _dbus_marshal_read_basic (str, pos, type, value, byte_order, new_pos);
      break;
  }

  if (new_pos)
    *new_pos = pos;
}

static void
get_offsets (const char *buffer, size_t container_size,
             size_t *fields_offsets, size_t *n_fields_offsets,
             size_t *offset_size)
{
  *offset_size = bus_gvariant_determine_word_size (container_size, 0);

  if (0 < container_size && 0 < *offset_size)
  {
    size_t last_offset_position = container_size - (*offset_size);
    size_t last_offset = bus_gvariant_read_word_le (buffer + last_offset_position,
                                                    (*offset_size));
    int i;

    *n_fields_offsets = (container_size - last_offset) / (*offset_size);
    fields_offsets[(*n_fields_offsets)-1] = last_offset;
    for (i = 0; i < (*n_fields_offsets)-1; i++)
    {
      fields_offsets[i] = bus_gvariant_read_word_le (buffer + last_offset + i*(*offset_size),
                                                     (*offset_size));
    }
  }
}

static int
find_field (int field, const char *array_buffer, size_t *fields_offsets, size_t n_fields_offsets,
            size_t *field_offset)
{
    /* last_offset points to the offsets array, beyond the last element of the array container */
    size_t last_offset = fields_offsets[n_fields_offsets-1];
    int i = 0;
    size_t next_offset = 0;

    while ( next_offset < last_offset && get_field_after (array_buffer, next_offset) != field)
    {
      next_offset = fields_offsets[i];
      i++;
    }
    if (next_offset < last_offset)
    {
      *field_offset = next_offset;
      return i;
    }
    return -1;
}

dbus_bool_t
_dbus_header_gvariant_delete_field (DBusHeader *header,
                                    int field)
{
  size_t fields_offsets[DBUS_HEADER_FIELD_LAST];
  size_t n_fields_offsets = 0;
  size_t offset_size = 0;
  const char *array_buffer;

  _dbus_assert(field <= DBUS_HEADER_FIELD_LAST);

  array_buffer = get_header_const_array (header);

  get_offsets (array_buffer,
               get_header_array_size (header),
               fields_offsets, &n_fields_offsets, &offset_size );

  if (0 < n_fields_offsets)
  {
    /* check if the field is already in the header */
    size_t field_offset;
    int field_index = find_field (field, array_buffer, fields_offsets, n_fields_offsets, &field_offset);

    /* prepare for changing - remove array offsets and offsets */
    _dbus_string_shorten (&header->data, n_fields_offsets*offset_size + header->padding);

    if (field_index >= 0)
    {
      /* field exists */
      size_t field_len = 0;
      size_t field_start = 0;
      /* let's remove aligned block of the field, along with padding */
      if (field_index == 0)
      {
        field_len = _DBUS_ALIGN_VALUE (fields_offsets[0],8);
      }
      else
      {
        field_len = _DBUS_ALIGN_VALUE (fields_offsets[field_index],8) -
                    _DBUS_ALIGN_VALUE (fields_offsets[field_index-1],8);
      }

      field_start = FIRST_GVARIANT_FIELD_OFFSET + _DBUS_ALIGN_VALUE (field_offset, 8);

      /* if this is the last field, then there is no padding at the end */
      if (field_start + field_len > _dbus_string_get_length (&header->data))
      {
        field_len = _dbus_string_get_length (&header->data) - field_start;
      }

      /* remove the field */
      _dbus_string_delete (&header->data, field_start, field_len);
      header->fields[field].value_pos = _DBUS_HEADER_FIELD_VALUE_NONEXISTENT;
      /* and update offsets */
      for (; field_index < n_fields_offsets-1; field_index++)
      {
        fields_offsets[field_index] = fields_offsets[field_index+1]-field_len;
      }
      n_fields_offsets--;

      /* remove padding from now-last field */
      _dbus_string_shorten (&header->data,
                            _dbus_string_get_length(&header->data) -
                               (FIRST_GVARIANT_FIELD_OFFSET + fields_offsets[n_fields_offsets-1]));
      header->padding = 0;
    }
  }

  /* It seems impossible for append_offsets() and correct_header_padding() to fail,
     because space for offsets was already allocated */
  if (!append_offsets(&header->data, fields_offsets, n_fields_offsets))
    return FALSE;
  _dbus_header_fill_cache (header, fields_offsets, n_fields_offsets);
  if (!correct_header_padding (header))
    return FALSE;

  return TRUE;
}

dbus_bool_t
_dbus_header_set_field_basic_gvariant (DBusHeader       *header,
                              int               field,
                              int               type,
                              const void       *value)
{
  size_t fields_offsets[DBUS_HEADER_FIELD_LAST];
  size_t n_fields_offsets = 0;
  dbus_bool_t result = TRUE;
  const DBusBasicValue *vp = value;
  size_t offset_size = 0;
  const char *array_buffer;

  _dbus_assert(field != DBUS_HEADER_FIELD_INVALID);
  _dbus_assert(field <= DBUS_HEADER_FIELD_LAST);

  array_buffer = get_header_const_array (header);

  result = result && _dbus_header_gvariant_delete_field (header, field);

  /* now, we are sure that there is no such field (anymore) - so, simply append */

  get_offsets (array_buffer,
               get_header_array_size (header),
               fields_offsets, &n_fields_offsets, &offset_size );

  /* prepare for changing - remove array offsets and padding */
  _dbus_string_shorten (&header->data, n_fields_offsets*offset_size + header->padding);

  switch (type)
  {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
      result = result && append_field_string (&header->data, field, vp->str, type,
          fields_offsets, &n_fields_offsets);
      break;
    case DBUS_TYPE_UINT32:
      result = result && append_field_uint32 (&header->data, field, vp->u32,
          fields_offsets, &n_fields_offsets);
      break;
    case DBUS_TYPE_UINT64:
      append_field_uint64 (&header->data, field, vp->u64,
          fields_offsets, &n_fields_offsets);
      result = TRUE;
      break;
    default:
      _dbus_assert_not_reached("Not a basic type");
      result = FALSE;
      break;
  }

  result = result && append_offsets(&header->data, fields_offsets, n_fields_offsets);
  _dbus_header_fill_cache (header, fields_offsets, n_fields_offsets);
  result = result && correct_header_padding (header);

  return result;
}

dbus_bool_t
_dbus_header_get_field_basic_gvariant (DBusHeader    *header,
                                       int            field,
                                       int            type,
                                       void          *value)
{
  size_t fields_offsets[DBUS_HEADER_FIELD_LAST];
  size_t n_fields_offsets = 0;
  dbus_bool_t result = FALSE;
  DBusBasicValue *vp = value;
  size_t offset_size = 0;
  const char *array_buffer;

  _dbus_assert(field != DBUS_HEADER_FIELD_INVALID);
  _dbus_assert(field <= DBUS_HEADER_FIELD_LAST);

  array_buffer = get_header_const_array (header);

  get_offsets( array_buffer,
               get_header_array_size (header),
               fields_offsets, &n_fields_offsets, &offset_size );

  if (0 < n_fields_offsets)
  {
    /* check if the field is already in the header */
    size_t field_offset;
    int field_index = find_field (field, array_buffer, fields_offsets, n_fields_offsets, &field_offset);
    if (0 <= field_index)
    {
      /* field found, get value */
      const void *field_begin = array_buffer + _DBUS_ALIGN_VALUE(field_offset,8) + FIELD_ID_SIZE;
      dbus_uint32_t byte_order = _dbus_header_get_byte_order (header);

      switch (type)
      {
        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_SIGNATURE:
          {
            vp->str = (char *)field_begin;
          }
          break;
        case DBUS_TYPE_UINT32:
          {
            vp->u32 = *(const dbus_uint32_t *)field_begin;
            if (byte_order != DBUS_COMPILER_BYTE_ORDER)
              vp->u32 = DBUS_UINT32_SWAP_LE_BE (vp->u32);
          }
          break;
        case DBUS_TYPE_UINT64:
          {
            vp->u64 = *(const dbus_uint64_t *)field_begin;
            if (byte_order != DBUS_COMPILER_BYTE_ORDER)
              vp->u64 = DBUS_UINT64_SWAP_LE_BE (vp->u64);
          }
          break;
        default:
          _dbus_assert_not_reached("Not a basic type");
          break;
      }

      result = TRUE;
    }
  }
  return result;
}

void
_dbus_marshal_skip_gvariant_basic (const DBusString *str,
                                   int               type,
                                   int               byte_order,
                                   int              *pos)
{
  switch (type)
  {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
      /* FIXME - this will require redesign... size should come from upper container */
      *pos += strlen (_dbus_string_get_const_data (str) + *pos) + 1; /* length plus nul */
      break;
    case DBUS_TYPE_BOOLEAN:
      (*pos)++;
      break;
    default:
      _dbus_marshal_skip_basic (str, type, byte_order, pos);
      break;
  }
}

dbus_bool_t
_dbus_header_load_gvariant (DBusHeader     *header,
                            DBusTypeReader *reader,
                            DBusValidity   *validity)
{
  size_t fields_offsets[DBUS_HEADER_FIELD_LAST];
  size_t n_fields_offsets = 0;
  size_t offset_size = 0;
  const char *array_buffer = get_header_const_array (header);

  get_offsets( array_buffer,
               get_header_array_size (header),
               fields_offsets, &n_fields_offsets, &offset_size );

  _dbus_header_fill_cache (header, fields_offsets, n_fields_offsets);
  return TRUE;
}

dbus_bool_t
_dbus_gvariant_raw_get_lengths (const DBusString *str,
                                dbus_uint32_t    *fields_array_len_unsigned,
                                dbus_uint32_t    *body_len_unsigned,
                                DBusValidity     *validity)
{
  size_t message_len = _dbus_string_get_length (str);
  size_t body_offsets_size = bus_gvariant_determine_word_size (message_len, 0);
  const char *message_ptr = _dbus_string_get_const_data (str);
  /* so, the offset of end of fields is written at offset str->len - body_offsets_size */
  size_t end_of_fields = bus_gvariant_read_word_le (message_ptr + message_len - body_offsets_size,
                                                    body_offsets_size);
  *fields_array_len_unsigned = end_of_fields - FIRST_GVARIANT_FIELD_OFFSET;

  *body_len_unsigned = message_len - _DBUS_ALIGN_VALUE (end_of_fields, 8);
  return TRUE;
}

DBusValidity
_dbus_validate_gvariant_body_with_reason (const DBusString *expected_signature,
                                          int               expected_signature_start,
                                          int               byte_order,
                                          int              *bytes_remaining,
                                          const DBusString *value_str,
                                          int               value_pos,
                                          int               len)
{
  /* FIXME stub */
  if (bytes_remaining)
    *bytes_remaining = 0;
  return DBUS_VALID;
}

dbus_bool_t
_dbus_message_gvariant_get_signature (DBusMessage       *message,
                                      const DBusString **type_str_p,
                                      int               *type_pos_p,
                                      int               *type_str_len)
{
  size_t body_len = _dbus_string_get_length (&message->body);
  size_t message_len = _dbus_string_get_length (&message->header.data) + body_len;
  size_t body_offsets_size = bus_gvariant_determine_word_size (message_len, 0);
  const char *body_ptr = _dbus_string_get_const_data (&message->body);
  const char *sig_end_ptr = body_ptr + body_len - body_offsets_size;
  const char *sig_ptr = sig_end_ptr - 1;

  while (sig_ptr >= body_ptr && (*sig_ptr) != 0)
  {
    sig_ptr--;
  }

  if (sig_ptr < body_ptr)
    return FALSE;

  if (type_str_p != NULL)
    *type_str_p = &message->body;
  *type_pos_p = sig_ptr - body_ptr + 1;
  *type_str_len = sig_end_ptr - sig_ptr - 1;

  return TRUE;
}

dbus_bool_t
_dbus_message_append_body_offset (DBusMessage *message)
{
  size_t body_len = _dbus_string_get_length (&message->body);
  size_t end_of_fields_offset = _dbus_string_get_length (&message->header.data) - message->header.padding;
  size_t message_len = _dbus_string_get_length (&message->header.data) + body_len;
  size_t body_offsets_size = bus_gvariant_determine_word_size (message_len, 1);

  return append_sized_value (&message->body, end_of_fields_offset, body_offsets_size);
}

dbus_bool_t
_dbus_message_gvariant_add_signature (DBusMessage       *message,
                                      const DBusString  *type_str)
{
  dbus_bool_t res = _dbus_string_append_byte (&message->body, 0);
  res = res && _dbus_string_append_byte (&message->body, '(');
  res = res && marshal_gvariant_string (&message->body, _dbus_string_get_length (&message->body),
                           _dbus_string_get_const_data (type_str), NULL, FALSE);
  res = res && _dbus_string_append_byte (&message->body, ')');
  return res;
}

dbus_bool_t
_dbus_message_gvariant_remove_body_offset (DBusMessage *message)
{
  size_t offset_size = bus_gvariant_determine_word_size (_dbus_string_get_length (&message->header.data) +
                                                            _dbus_string_get_length (&message->body),
                                                         0);
  _dbus_string_shorten (&message->body, offset_size);
  return TRUE;
}

dbus_bool_t
_dbus_message_finalize_gvariant (DBusMessage *message, dbus_bool_t remove_signature_from_header)
{
  DBusString str;
  const DBusString *type_str;
  int type_pos;
  dbus_bool_t fieldSignaturePresent;
  dbus_bool_t res = TRUE;

  _dbus_assert (!message->locked);

  if (message->header.protocol_version != DBUS_PROTOCOL_VERSION_GVARIANT)
    return TRUE;

  fieldSignaturePresent = _dbus_header_get_field_raw (&message->header,
                                                      DBUS_HEADER_FIELD_SIGNATURE,
                                                      &type_str,
                                                      &type_pos);
  if (fieldSignaturePresent)
  {
    /* if there is signature field, then we need to move this signature to body,
     * and delete the field
     */
    const char *sig_ptr = _dbus_string_get_const_data (type_str) + type_pos;
    _dbus_string_init_const (&str, sig_ptr);
  }
  else
  {
    /* If there is no signature field, then the body is empty.
     * However, we need to add signature anyway, because body is a variant.
     */
    _dbus_string_init_const (&str, "");
    type_str = &str;
    type_pos = 0;
    /* Let's set the body also */
    _dbus_string_set_length (&message->body, 0);
    _dbus_string_append_byte (&message->body, 0);
  }

  res = res && _dbus_message_gvariant_add_signature (message, &str);

  if (res && fieldSignaturePresent && remove_signature_from_header)
    res = res && _dbus_header_gvariant_delete_field (&message->header, DBUS_HEADER_FIELD_SIGNATURE);

  res = res && _dbus_message_append_body_offset (message);

  return res;
}

/* returns length of the body inside the outermost variant
 * that is, without offset and signature from the end of messages
 */
static size_t
_dbus_message_gvariant_get_body_length (DBusMessage *message)
{
  size_t body_len = _dbus_string_get_length (&message->body);
  size_t message_len = body_len + _dbus_string_get_length (&message->header.data);
  body_len -= bus_gvariant_determine_word_size (message_len , 0);

  while (body_len > 0 && _dbus_string_get_byte (&message->body, body_len) != 0)
    body_len--;

  return body_len;
}

static inline int
get_max (int a, int b)
{
  return (a>b) ? a : b;
}

static int
update_size (int current_size, int size_of_element, int *alignment, int new_alignment)
{
  *alignment = get_max (*alignment, new_alignment);
  current_size = _DBUS_ALIGN_VALUE (current_size, *alignment);
  return current_size + size_of_element;
}

static int
_dbus_reader_get_signature_fixed_size (const DBusString *signature, int *pos, int *alignment)
{
  int res = 0;
  int depth = 0;
  int current_alignment = 1;
  dbus_bool_t variable = FALSE;

  char c = _dbus_string_get_byte (signature, *pos);
  if (c == DBUS_STRUCT_BEGIN_CHAR || c == DBUS_DICT_ENTRY_BEGIN_CHAR)
  {
    depth = 1;
    (*pos)++;
  }

  do {
    switch (_dbus_string_get_byte (signature, *pos))
    {
      case DBUS_TYPE_BYTE:
      case DBUS_TYPE_BOOLEAN:
        res += 1;
        break;
      case DBUS_TYPE_INT16:
      case DBUS_TYPE_UINT16:
        res = update_size (res, 2, &current_alignment, 2);
        break;
      case DBUS_TYPE_INT32:
      case DBUS_TYPE_UINT32:
      case DBUS_TYPE_UNIX_FD:
        res = update_size (res, 4, &current_alignment, 4);
        break;
      case DBUS_TYPE_INT64:
      case DBUS_TYPE_UINT64:
      case DBUS_TYPE_DOUBLE:
        res = update_size (res, 8, &current_alignment, 8);
        break;
      case DBUS_STRUCT_END_CHAR:
      case DBUS_DICT_ENTRY_END_CHAR:
        depth--;
        break;
      case DBUS_STRUCT_BEGIN_CHAR:
      case DBUS_DICT_ENTRY_BEGIN_CHAR:
        {
          int alignment_recursive;
          int res_recursive = _dbus_reader_get_signature_fixed_size (signature, pos, &alignment_recursive);
          if (res_recursive == 0)
            variable = TRUE;   /* variable size detected */

          /* we need to update at least alignment */
          res = update_size (res, res_recursive, &current_alignment, alignment_recursive);
        }
        break;
      case DBUS_TYPE_VARIANT:
        current_alignment = 8;
        variable = TRUE;
        break;
      case DBUS_TYPE_ARRAY:
        {
          int alignment_recursive;
          int recursive_pos = *pos + 1;
          int res_recursive = _dbus_reader_get_signature_fixed_size (signature, &recursive_pos, &alignment_recursive);

          variable = TRUE;       /* variable size detected */

          /* we need to update alignment */
          res = update_size (res, res_recursive, &current_alignment, alignment_recursive);

          /* and update position */
          *pos = recursive_pos - 1;
        }
        break;
      default:
        variable = TRUE;       /* variable size detected */
    }
    (*pos)++;
  } while (depth > 0);

  /* we want to point it to the last character, to allow upper instance to skip it */
  (*pos)--;

  if (alignment != NULL)
    *alignment = current_alignment;

  return variable ? 0 : res;
}

int
_dbus_reader_get_type_fixed_size (DBusTypeReader *reader, int *alignment)
{
  int pos = reader->type_pos;
  return _dbus_reader_get_signature_fixed_size (reader->type_str, &pos, alignment);
}

int
_dbus_type_gvariant_get_fixed_size (const DBusString *type_str, int type_pos, int *alignment)
{
  return _dbus_reader_get_signature_fixed_size (type_str, &type_pos, alignment);
}

/* This is for structs and dict entries.
 * Counts variable elements inside a container.
 * This is equal to number of offsets embedded into the container.
 */
int
_dbus_reader_count_offsets (const DBusTypeReader *reader)
{
  DBusTypeReader r;
  int variables = 0;
  dbus_bool_t prev_is_variable = FALSE;
  int current_type;
  int ending_char = DBUS_TYPE_INVALID;

  /* if signature is not empty, it must be after initial parenthesis */
  /* empty signature has length 1 - only nul byte */
  _dbus_assert (reader->type_pos > 0);

  _dbus_type_reader_init_types_only (&r,
                                     reader->type_str,
                                     reader->type_pos);
  r.gvariant = TRUE;
  r.klass = reader->klass;

  /* Check what container we're in */
  switch (_dbus_string_get_byte (r.type_str, r.type_pos-1))
    {
      case DBUS_STRUCT_BEGIN_CHAR:
        ending_char = DBUS_STRUCT_END_CHAR;
        break;
      case DBUS_DICT_ENTRY_BEGIN_CHAR:
        ending_char = DBUS_DICT_ENTRY_END_CHAR;
        break;
      default:
        _dbus_assert_not_reached ("function must be called inside structs or dict entries");
        break;
    }
  r.finished = (_dbus_string_get_byte (r.type_str, r.type_pos) == ending_char);

  while ((current_type = _dbus_type_reader_get_current_type (&r)) != DBUS_TYPE_INVALID)
  {
    int size = _dbus_reader_get_type_fixed_size (&r, NULL);
    if (prev_is_variable)
      variables++;
    prev_is_variable = (size == 0);
    _dbus_type_signature_next (_dbus_string_get_const_data(r.type_str), &r.type_pos);
    r.finished = (_dbus_string_get_byte (r.type_str, r.type_pos) == ending_char);
  }
  return variables;
}

size_t
_dbus_reader_get_offset_of_end_of_variable (DBusTypeReader *reader)
{
  if (reader->is_variant)
  {
    /* variant has its end set to the separating 0 */
    return reader->value_end;
  }
  else
  {
    const char *buffer = _dbus_string_get_const_data (reader->value_str) + reader->value_start;
    size_t container_size = reader->value_end - reader->value_start;
    size_t offset_size = bus_gvariant_determine_word_size (container_size, 0);
    int index_from_back = reader->offsets_from_back ?
                          reader->variable_index :
                          reader->n_offsets - 1 - reader->variable_index;

    if (0 < container_size && 0 <= index_from_back)
    {
      size_t required_offset_position = container_size - (index_from_back+1)*offset_size;
      if (index_from_back < reader->n_offsets)
        return reader->value_start +
               bus_gvariant_read_word_le (buffer + required_offset_position,
                                          offset_size);
      else if (reader->offsets_from_back)
        return reader->value_start +
               container_size - (reader->n_offsets * offset_size); /* this is end of internal container */
    }
  }

  return reader->value_start;
}

int
_dbus_reader_count_array_elems (const DBusTypeReader *reader)
{
  const char *buffer = _dbus_string_get_const_data (reader->value_str) + reader->value_start;
  size_t container_size = reader->value_end - reader->value_start;
  size_t offset_size = bus_gvariant_determine_word_size (container_size, 0);
  size_t last_offset = bus_gvariant_read_word_le (buffer + container_size - offset_size, offset_size);
  return (container_size - last_offset) / offset_size;
}

static dbus_bool_t
write_offset (DBusString *offsets,
              size_t offset,
              size_t offset_size,
              int insert_at)
{
  DBusString str;
  dbus_bool_t res = _dbus_string_init_preallocated (&str, offset_size);
  res = res && append_sized_value (&str, offset, offset_size);
  res = res && _dbus_string_copy_len (&str, 0, offset_size, offsets, insert_at);
  _dbus_string_free (&str);
  return res;
}

static dbus_bool_t
prepend_offset (DBusString *offsets,
               size_t offset,
               size_t offset_size)
{
  return write_offset (offsets, offset, offset_size, 0);
}

static dbus_bool_t
append_offset (DBusString *offsets,
               size_t offset,
               size_t offset_size)
{
  return write_offset (offsets, offset, offset_size, _dbus_string_get_length(offsets));
}

static dbus_bool_t
convert_offsets (DBusString *offsets,
                 size_t old_offsets_size,
                 size_t new_offsets_size)
{
  char *old_offsets = NULL;
  size_t n_offsets = _dbus_string_get_length (offsets) / old_offsets_size;
  dbus_bool_t result = _dbus_string_steal_data (offsets, &old_offsets);
  int i;

  for (i = 0; i < n_offsets && result; i++)
  {
    size_t offset = bus_gvariant_read_word_le (old_offsets + i*old_offsets_size, old_offsets_size);
    result = result && append_sized_value (offsets, offset, new_offsets_size);
  }

  dbus_free (old_offsets);

  return result;
}

static size_t
get_offsets_count (DBusString *offsets, size_t offsets_size)
{
  return _dbus_string_get_length (offsets) / offsets_size;
}

static dbus_bool_t
check_offsets_for_adding (DBusTypeWriter *writer)
{
  size_t container_size = writer->value_pos - writer->value_start;
  size_t n_offsets = get_offsets_count (writer->offsets,
                                        writer->offsets_size);
  size_t offsets_size = bus_gvariant_determine_word_size (container_size, n_offsets + 1);
  if (offsets_size != writer->offsets_size)
  {
    if (!convert_offsets (writer->offsets, writer->offsets_size, offsets_size))
      return FALSE;
    writer->offsets_size = offsets_size;
  }
  return TRUE;
}

static dbus_bool_t
convert_offsets_in_body (DBusTypeWriter *writer,
                         size_t new_offsets_size)
{
  DBusString offsets;
  size_t n_offsets;
  int i;
  dbus_bool_t result = _dbus_string_init (&offsets);
  char *old_offsets;

  result = result && _dbus_string_move (writer->value_str, writer->value_pos, &offsets, 0);
  n_offsets = _dbus_string_get_length (&offsets) / writer->offsets_size;
  old_offsets = _dbus_string_get_data (&offsets);

  for (i = 0; i < n_offsets && result; i++)
  {
    size_t offset = bus_gvariant_read_word_le (old_offsets + i*writer->offsets_size, writer->offsets_size);
    result = result && append_sized_value (writer->value_str, offset, new_offsets_size);
  }

  _dbus_string_free (&offsets);
  return result;
}

static dbus_bool_t
check_offsets_in_body_for_adding (DBusTypeWriter *writer)
{
  size_t container_size = writer->value_pos - writer->value_start;
  size_t n_offsets = (_dbus_string_get_length (writer->value_str) - writer->value_pos) / writer->offsets_size;
  size_t offsets_size = bus_gvariant_determine_word_size (container_size, n_offsets + 1);
  if (offsets_size != writer->offsets_size)
  {
    if (!convert_offsets_in_body (writer, offsets_size))
      return FALSE;
    writer->offsets_size = offsets_size;
  }
  return TRUE;
}

static dbus_bool_t
_dbus_writer_gvariant_add_offset_with_variability (DBusTypeWriter *writer,
                                                   dbus_bool_t fixed)
{
  writer->is_fixed = writer->is_fixed && fixed;

  if (writer->body_container ||
      DBUS_TYPE_STRUCT == writer->container_type ||
      DBUS_TYPE_DICT_ENTRY == writer->container_type)
  {
    if (writer->u.struct_or_dict.last_offset != 0)
    {
      if (writer->body_container)
      {
        check_offsets_in_body_for_adding (writer);

        write_offset (writer->value_str,
                      writer->u.struct_or_dict.last_offset,
                      writer->offsets_size,
                      writer->value_pos);
      }
      else
      {
        check_offsets_for_adding (writer);

        prepend_offset (writer->offsets,
                        writer->u.struct_or_dict.last_offset,
                        writer->offsets_size);
      }
    }
    if (!fixed)
    {
      writer->u.struct_or_dict.last_offset = writer->value_pos - writer->value_start;
    }
    else
    {
      writer->u.struct_or_dict.last_offset = 0;
    }
  }
  else if (DBUS_TYPE_ARRAY == writer->container_type)
  {
    if (writer->offsets_size > 0)
    {
      check_offsets_for_adding (writer);

      if (!append_offset (writer->offsets,
                     writer->value_pos - writer->value_start,
                     writer->offsets_size))
	      return FALSE;
    }
  }
  return TRUE;
}

static dbus_bool_t
_dbus_writer_gvariant_add_offset (DBusTypeWriter *writer,
                                  int type)
{
  return _dbus_writer_gvariant_add_offset_with_variability (writer, dbus_type_is_fixed (type));
}

/* this function gets only known alignments - other are 1 */
static int
get_alignment (int type)
{
  switch (type)
  {
      case DBUS_TYPE_INT16:
      case DBUS_TYPE_UINT16:
        return 2;
      case DBUS_TYPE_INT32:
      case DBUS_TYPE_UINT32:
      case DBUS_TYPE_UNIX_FD:
        return 4;
      case DBUS_TYPE_INT64:
      case DBUS_TYPE_UINT64:
      case DBUS_TYPE_DOUBLE:
      case DBUS_TYPE_VARIANT:
        return 8;
      default:
        break;
  }
  return 1;
}

static dbus_bool_t
fix_struct_alignment_value (DBusTypeWriter *writer, int alignment)
{
  dbus_bool_t result = TRUE;
  int old_alignment = writer->alignment;
  if (old_alignment < alignment)
  {
    int diff = _DBUS_ALIGN_VALUE (writer->value_start, alignment) - writer->value_start;
    result = _dbus_string_insert_bytes (writer->value_str, writer->value_start, diff, 0);
    writer->value_start += diff;
    writer->value_pos += diff;
    writer->alignment = alignment;
  }
  return result;
}

static dbus_bool_t
fix_struct_alignment (DBusTypeWriter *writer, int type)
{
  return fix_struct_alignment_value (writer, get_alignment (type));
}

dbus_bool_t
_dbus_type_writer_gvariant_write_basic_no_typecode (DBusTypeWriter *writer,
                                                    int             type,
                                                    const void     *value)
{
  dbus_bool_t result = TRUE;

  if (writer->container_type == DBUS_TYPE_STRUCT || writer->container_type == DBUS_TYPE_DICT_ENTRY)
    result = fix_struct_alignment (writer, type);

  result = result && _dbus_marshal_write_gvariant_basic (writer->value_str,
                                                         writer->value_pos,
                                                         type,
                                                         value,
                                                         writer->byte_order,
                                                         &writer->value_pos);

  result = result && _dbus_writer_gvariant_add_offset (writer, type);
  return result;
}

static dbus_bool_t
write_offsets (DBusString *dest, size_t insert_at, DBusString *offsets)
{
  return _dbus_string_copy (offsets, 0, dest, insert_at);
}

dbus_bool_t
_dbus_writer_unrecurse_gvariant_write (DBusTypeWriter *writer,
                                       DBusTypeWriter *sub)
{
  dbus_bool_t result = TRUE;

  if (writer->alignment < sub->alignment)
    writer->alignment = sub->alignment;

  switch (sub->container_type) {
    case DBUS_TYPE_STRUCT:
    case DBUS_TYPE_DICT_ENTRY:
    {
      int diff;
      int sub_len;

      if (NULL != sub->offsets)
      {
        write_offsets (sub->value_str, sub->value_pos, sub->offsets);

        _dbus_string_free (sub->offsets);
        dbus_free (sub->offsets);
      }

      diff = _DBUS_ALIGN_VALUE (writer->value_pos, sub->alignment) - writer->value_pos;

      result = _dbus_string_insert_bytes (writer->value_str, writer->value_pos, diff, 0);
      writer->value_pos += diff;
      sub_len = _dbus_string_get_length (sub->value_str);
      result = result && _dbus_string_copy_len (sub->value_str, 0,
                                                sub_len,
                                                writer->value_str,
                                                writer->value_pos);
      writer->value_pos += sub_len;

      _dbus_string_free (sub->value_str);
      dbus_free (sub->value_str);

      break;
    }
    case DBUS_TYPE_VARIANT:
    {
      int sub_type_len;

      /* write separating nul byte */
      result = _dbus_string_insert_byte (sub->value_str, sub->value_pos, 0);
      sub->value_pos += 1;

      /* write signature */
      sub_type_len = _dbus_string_get_length (sub->type_str);
      result = result && _dbus_string_copy_len (sub->type_str, 0,
                                                sub_type_len,
                                                sub->value_str,
                                                sub->value_pos);
      sub->value_pos += sub_type_len;

      /* free type string allocated in writer_recurse_variant() */
      _dbus_string_free (sub->type_str);
      dbus_free (sub->type_str);

      /* update parent's string pointer */
      writer->value_pos = sub->value_pos;

      break;
    }
    case DBUS_TYPE_ARRAY:
      writer->value_pos = sub->value_pos;
      if (NULL != sub->offsets)
      {
        write_offsets (sub->value_str, sub->value_pos, sub->offsets);

        writer->value_pos += _dbus_string_get_length (sub->offsets);

        _dbus_string_free (sub->offsets);
        dbus_free (sub->offsets);
      }

      break;
    default:
      _dbus_assert_not_reached("Invalid container type");
  }

  /* well, we don't know where in the type string beginning of current container is */
  result = result && _dbus_writer_gvariant_add_offset_with_variability (writer, sub->is_fixed);

  return result;
}

void
_dbus_type_reader_gvariant_init (DBusTypeReader *reader,
                                 DBusMessage    *message)
{
  reader->gvariant = TRUE;
  /* GVariant wraps contents into struct */
  if (_dbus_string_get_byte (reader->type_str, reader->type_pos) == DBUS_STRUCT_BEGIN_CHAR)
  {
    reader->type_pos++;
    if (_dbus_string_get_byte (reader->type_str, reader->type_pos) == DBUS_STRUCT_END_CHAR)
      reader->finished = TRUE;
  }

  reader->value_end = _dbus_message_gvariant_get_body_length (message);
  reader->n_offsets = _dbus_reader_count_offsets (reader);
}
