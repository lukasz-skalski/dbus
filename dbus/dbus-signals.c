/* signals.c  Bus signal connection implementation
 *
 * Copyright (C) 2003, 2005  Red Hat, Inc.
 * Copyright 2014 Samsung Electronics
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

#include "../config.h"
#include "dbus-signals.h"
#include <dbus/dbus-marshal-validate.h>
#include "dbus-internals.h"
#include "dbus-hash.h"
#include "dbus-list.h"
#include "kdbus-common.h"
#include <stdlib.h>
#include <limits.h>

#define SET_OOM(error) dbus_set_error_const ((error), DBUS_ERROR_NO_MEMORY, "Memory allocation failure in transport, regarding match rules")

struct MatchRule
{
  int refcount;       /**< reference count */

  DBusConnection *matches_go_to; /**< Owner of the rule */

  unsigned int flags; /**< MatchFlags */

  int   message_type;
  char *interface;
  char *member;
  char *sender;
  char *destination;
  char *path;

  unsigned int *arg_lens;
  char **args;
  int args_len;

  __u64 kdbus_cookie;
};

#define MATCH_ARG_FLAGS (MATCH_ARG_NAMESPACE |MATCH_ARG_IS_PATH)

static MatchRule*
bus_match_rule_new (DBusConnection *matches_go_to)
{
  MatchRule *rule;

  rule = dbus_new0 (MatchRule, 1);
  if (rule == NULL)
    return NULL;

  rule->refcount = 1;
  rule->matches_go_to = matches_go_to;
  rule->kdbus_cookie = 0;

#ifndef DBUS_ENABLE_EMBEDDED_TESTS
  _dbus_assert (rule->matches_go_to != NULL);
#endif

  return rule;
}

static MatchRule *
bus_match_rule_ref (MatchRule *rule)
{
  _dbus_assert (rule->refcount > 0);

  rule->refcount += 1;

  return rule;
}

void
match_rule_unref (MatchRule *rule)
{
  _dbus_assert (rule->refcount > 0);

  rule->refcount -= 1;
  if (rule->refcount == 0)
    {
      dbus_free (rule->interface);
      dbus_free (rule->member);
      dbus_free (rule->sender);
      dbus_free (rule->destination);
      dbus_free (rule->path);
      dbus_free (rule->arg_lens);

      /* can't use dbus_free_string_array() since there
       * are embedded NULL
       */
      if (rule->args)
        {
          int i;

          i = 0;
          while (i < rule->args_len)
            {
              if (rule->args[i])
                dbus_free (rule->args[i]);
              ++i;
            }

          dbus_free (rule->args);
        }

      dbus_free (rule);
    }
}

#ifdef DBUS_ENABLE_VERBOSE_MODE
/* Note this function does not do escaping, so it's only
 * good for debug spew at the moment
 */
char*
match_rule_to_string (MatchRule *rule)
{
  DBusString str;
  char *ret;

  if (!_dbus_string_init (&str))
    {
      char *s;
      while ((s = _dbus_strdup ("nomem")) == NULL)
        ; /* only OK for debug spew... */
      return s;
    }

  if (rule->flags & MATCH_MESSAGE_TYPE)
    {
      if (!_dbus_string_append_printf (&str, "type='%s'",
            dbus_message_type_to_string (rule->message_type)))
        goto nomem;
    }

  if (rule->flags & MATCH_INTERFACE)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "interface='%s'", rule->interface))
        goto nomem;
    }

  if (rule->flags & MATCH_MEMBER)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "member='%s'", rule->member))
        goto nomem;
    }

  if (rule->flags & MATCH_PATH)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "path='%s'", rule->path))
        goto nomem;
    }

  if (rule->flags & MATCH_PATH_NAMESPACE)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "path_namespace='%s'", rule->path))
        goto nomem;
    }

  if (rule->flags & MATCH_SENDER)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "sender='%s'", rule->sender))
        goto nomem;
    }

  if (rule->flags & MATCH_DESTINATION)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "destination='%s'", rule->destination))
        goto nomem;
    }

  if (rule->flags & MATCH_CLIENT_IS_EAVESDROPPING)
    {
      if (_dbus_string_get_length (&str) > 0)
        {
          if (!_dbus_string_append (&str, ","))
            goto nomem;
        }

      if (!_dbus_string_append_printf (&str, "eavesdrop='%s'",
            (rule->flags & MATCH_CLIENT_IS_EAVESDROPPING) ?
            "true" : "false"))
        goto nomem;
    }

  if (rule->flags &MATCH_ARGS)
    {
      int i;

      _dbus_assert (rule->args != NULL);

      i = 0;
      while (i < rule->args_len)
        {
          if (rule->args[i] != NULL)
            {
              dbus_bool_t is_path, is_namespace;

              if (_dbus_string_get_length (&str) > 0)
                {
                  if (!_dbus_string_append (&str, ","))
                    goto nomem;
                }

              is_path = (rule->arg_lens[i] & MATCH_ARG_IS_PATH) != 0;
              is_namespace = (rule->arg_lens[i] & MATCH_ARG_NAMESPACE) != 0;

              if (!_dbus_string_append_printf (&str,
                                               "arg%d%s='%s'",
                                               i,
                                               is_path ? "path" :
                                               is_namespace ? "namespace" : "",
                                               rule->args[i]))
                goto nomem;
            }

          ++i;
        }
    }

  if (!_dbus_string_steal_data (&str, &ret))
    goto nomem;

  _dbus_string_free (&str);
  return ret;

 nomem:
  _dbus_string_free (&str);
  {
    char *s;
    while ((s = _dbus_strdup ("nomem")) == NULL)
      ;  /* only OK for debug spew... */
    return s;
  }
}
#endif /* DBUS_ENABLE_VERBOSE_MODE */

static dbus_bool_t
bus_match_rule_set_message_type (MatchRule *rule,
                                 int           type)
{
  rule->flags |=MATCH_MESSAGE_TYPE;

  rule->message_type = type;

  return TRUE;
}

static dbus_bool_t
bus_match_rule_set_interface (MatchRule *rule,
                              const char   *interface)
{
  char *new;

  _dbus_assert (interface != NULL);

  new = _dbus_strdup (interface);
  if (new == NULL)
    return FALSE;

  rule->flags |=MATCH_INTERFACE;
  dbus_free (rule->interface);
  rule->interface = new;

  return TRUE;
}

static dbus_bool_t
bus_match_rule_set_member (MatchRule *rule,
                           const char   *member)
{
  char *new;

  _dbus_assert (member != NULL);

  new = _dbus_strdup (member);
  if (new == NULL)
    return FALSE;

  rule->flags |=MATCH_MEMBER;
  dbus_free (rule->member);
  rule->member = new;

  return TRUE;
}

static dbus_bool_t
bus_match_rule_set_sender (MatchRule *rule,
                           const char   *sender)
{
  char *new;

  _dbus_assert (sender != NULL);

  new = _dbus_strdup (sender);
  if (new == NULL)
    return FALSE;

  rule->flags |=MATCH_SENDER;
  dbus_free (rule->sender);
  rule->sender = new;

  return TRUE;
}

static dbus_bool_t
bus_match_rule_set_destination (MatchRule *rule,
                                const char   *destination)
{
  char *new;

  _dbus_assert (destination != NULL);

  new = _dbus_strdup (destination);
  if (new == NULL)
    return FALSE;

  rule->flags |=MATCH_DESTINATION;
  dbus_free (rule->destination);
  rule->destination = new;

  return TRUE;
}

static void
bus_match_rule_set_client_is_eavesdropping (MatchRule *rule,
                                            dbus_bool_t is_eavesdropping)
{
  if (is_eavesdropping)
    rule->flags |= MATCH_CLIENT_IS_EAVESDROPPING;
  else
    rule->flags &= ~(MATCH_CLIENT_IS_EAVESDROPPING);
}

static dbus_bool_t
bus_match_rule_set_path (MatchRule *rule,
                         const char   *path,
                         dbus_bool_t   is_namespace)
{
  char *new;

  _dbus_assert (path != NULL);

  new = _dbus_strdup (path);
  if (new == NULL)
    return FALSE;

  rule->flags &= ~(MATCH_PATH | MATCH_PATH_NAMESPACE);

  if (is_namespace)
    rule->flags |= MATCH_PATH_NAMESPACE;
  else
    rule->flags |= MATCH_PATH;

  dbus_free (rule->path);
  rule->path = new;

  return TRUE;
}

static dbus_bool_t
bus_match_rule_set_arg (MatchRule     *rule,
                        int                arg,
                        const DBusString *value,
                        dbus_bool_t       is_path,
                        dbus_bool_t       is_namespace)
{
  int length;
  char *new;

  _dbus_assert (value != NULL);

  /* args_len is the number of args not including null termination
   * in the char**
   */
  if (arg >= rule->args_len)
    {
      unsigned int *new_arg_lens;
      char **new_args;
      int new_args_len;
      int i;

      new_args_len = arg + 1;

      /* add another + 1 here for null termination */
      new_args = dbus_realloc (rule->args,
                               sizeof (char *) * (new_args_len + 1));
      if (new_args == NULL)
        return FALSE;

      /* NULL the new slots */
      i = rule->args_len;
      while (i <= new_args_len) /* <= for null termination */
        {
          new_args[i] = NULL;
          ++i;
        }

      rule->args = new_args;

      /* and now add to the lengths */
      new_arg_lens = dbus_realloc (rule->arg_lens,
                                   sizeof (int) * (new_args_len + 1));

      if (new_arg_lens == NULL)
        return FALSE;

      /* zero the new slots */
      i = rule->args_len;
      while (i <= new_args_len) /* <= for null termination */
        {
          new_arg_lens[i] = 0;
          ++i;
        }

      rule->arg_lens = new_arg_lens;
      rule->args_len = new_args_len;
    }

  length = _dbus_string_get_length (value);
  if (!_dbus_string_copy_data (value, &new))
    return FALSE;

  rule->flags |=MATCH_ARGS;

  dbus_free (rule->args[arg]);
  rule->arg_lens[arg] = length;
  rule->args[arg] = new;

  if (is_path)
    rule->arg_lens[arg] |=MATCH_ARG_IS_PATH;

  if (is_namespace)
    rule->arg_lens[arg] |=MATCH_ARG_NAMESPACE;

  /* NULL termination didn't get busted */
  _dbus_assert (rule->args[rule->args_len] == NULL);
  _dbus_assert (rule->arg_lens[rule->args_len] == 0);

  return TRUE;
}

void
match_rule_set_cookie (MatchRule *rule, dbus_uint64_t cookie)
{
  rule->kdbus_cookie = cookie;
}

dbus_uint64_t
match_rule_get_cookie (MatchRule *rule)
{
  return rule->kdbus_cookie;
}

#define ISWHITE(c) (((c) == ' ') || ((c) == '\t') || ((c) == '\n') || ((c) == '\r'))

static dbus_bool_t
find_key (const DBusString *str,
          int               start,
          DBusString       *key,
          int              *value_pos,
          DBusError        *error)
{
  const char *p;
  const char *s;
  const char *key_start;
  const char *key_end;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  s = _dbus_string_get_const_data (str);

  p = s + start;

  while (*p && ISWHITE (*p))
    ++p;

  key_start = p;

  while (*p && *p != '=' && !ISWHITE (*p))
    ++p;

  key_end = p;

  while (*p && ISWHITE (*p))
    ++p;

  if (key_start == key_end)
    {
      /* Empty match rules or trailing whitespace are OK */
      *value_pos = p - s;
      return TRUE;
    }

  if (*p != '=')
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Match rule has a key with no subsequent '=' character");
      return FALSE;
    }
  ++p;

  if (!_dbus_string_append_len (key, key_start, key_end - key_start))
    {
     SET_OOM (error);
      return FALSE;
    }

  *value_pos = p - s;

  return TRUE;
}

static dbus_bool_t
find_value (const DBusString *str,
            int               start,
            const char       *key,
            DBusString       *value,
            int              *value_end,
            DBusError        *error)
{
  const char *p;
  const char *s;
  char quote_char;
  int orig_len;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  orig_len = _dbus_string_get_length (value);

  s = _dbus_string_get_const_data (str);

  p = s + start;

  quote_char = '\0';

  while (*p)
    {
      if (quote_char == '\0')
        {
          switch (*p)
            {
            case '\0':
              goto done;

            case '\'':
              quote_char = '\'';
              goto next;

            case ',':
              ++p;
              goto done;

            case '\\':
              quote_char = '\\';
              goto next;

            default:
              if (!_dbus_string_append_byte (value, *p))
                {
                 SET_OOM (error);
                  goto failed;
                }
            }
        }
      else if (quote_char == '\\')
        {
          /* \ only counts as an escape if escaping a quote mark */
          if (*p != '\'')
            {
              if (!_dbus_string_append_byte (value, '\\'))
                {
                 SET_OOM (error);
                  goto failed;
                }
            }

          if (!_dbus_string_append_byte (value, *p))
            {
             SET_OOM (error);
              goto failed;
            }

          quote_char = '\0';
        }
      else
        {
          _dbus_assert (quote_char == '\'');

          if (*p == '\'')
            {
              quote_char = '\0';
            }
          else
            {
              if (!_dbus_string_append_byte (value, *p))
                {
                 SET_OOM (error);
                  goto failed;
                }
            }
        }

    next:
      ++p;
    }

 done:

  if (quote_char == '\\')
    {
      if (!_dbus_string_append_byte (value, '\\'))
        {
         SET_OOM (error);
          goto failed;
        }
    }
  else if (quote_char == '\'')
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Unbalanced quotation marks in match rule");
      goto failed;
    }
  else
    _dbus_assert (quote_char == '\0');

  /* Zero-length values are allowed */

  *value_end = p - s;

  return TRUE;

 failed:
  _DBUS_ASSERT_ERROR_IS_SET (error);
  _dbus_string_set_length (value, orig_len);
  return FALSE;
}

/* duplicates aren't allowed so the real legitimate max is only 6 or
 * so. Leaving extra so we don't have to bother to update it.
 * FIXME this is sort of busted now with arg matching, but we let
 * you match on up to 10 args for now
 */
#define MAX_RULE_TOKENS 16

/* this is slightly too high level to be termed a "token"
 * but let's not be pedantic.
 */
typedef struct
{
  char *key;
  char *value;
} RuleToken;

static dbus_bool_t
tokenize_rule (const DBusString *rule_text,
               RuleToken         tokens[MAX_RULE_TOKENS],
               DBusError        *error)
{
  int i;
  int pos;
  DBusString key;
  DBusString value;
  dbus_bool_t retval;

  retval = FALSE;

  if (!_dbus_string_init (&key))
    {
     SET_OOM (error);
      return FALSE;
    }

  if (!_dbus_string_init (&value))
    {
      _dbus_string_free (&key);
     SET_OOM (error);
      return FALSE;
    }

  i = 0;
  pos = 0;
  while (i < MAX_RULE_TOKENS &&
         pos < _dbus_string_get_length (rule_text))
    {
      _dbus_assert (tokens[i].key == NULL);
      _dbus_assert (tokens[i].value == NULL);

      if (!find_key (rule_text, pos, &key, &pos, error))
        goto out;

      if (_dbus_string_get_length (&key) == 0)
        goto next;

      if (!_dbus_string_steal_data (&key, &tokens[i].key))
        {
         SET_OOM (error);
          goto out;
        }

      if (!find_value (rule_text, pos, tokens[i].key, &value, &pos, error))
        goto out;

      if (!_dbus_string_steal_data (&value, &tokens[i].value))
        {
         SET_OOM (error);
          goto out;
        }

    next:
      ++i;
    }

  retval = TRUE;

 out:
  if (!retval)
    {
      i = 0;
      while (tokens[i].key || tokens[i].value)
        {
          dbus_free (tokens[i].key);
          dbus_free (tokens[i].value);
          tokens[i].key = NULL;
          tokens[i].value = NULL;
          ++i;
        }
    }

  _dbus_string_free (&key);
  _dbus_string_free (&value);

  return retval;
}

static dbus_bool_t
bus_match_rule_parse_arg_match (MatchRule     *rule,
                                const char       *key,
                                const DBusString *value,
                                DBusError        *error)
{
  dbus_bool_t is_path = FALSE;
  dbus_bool_t is_namespace = FALSE;
  DBusString key_str;
  unsigned long arg;
  int length;
  int end;

  /* For now, arg0='foo' always implies that 'foo' is a
   * DBUS_TYPE_STRING. Someday we could add an arg0type='int32' thing
   * if we wanted, which would specify another type, in which case
   * arg0='5' would have the 5 parsed as an int rather than string.
   */

  /* First we need to parse arg0 = 0, arg27 = 27 */

  _dbus_string_init_const (&key_str, key);
  length = _dbus_string_get_length (&key_str);

  if (_dbus_string_get_length (&key_str) < 4)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Key '%s' in match rule starts with 'arg' but lacks an arg number. Should be 'arg0' or 'arg7' for example.\n", key);
      goto failed;
    }

  if (!_dbus_string_parse_uint (&key_str, 3, &arg, &end))
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Key '%s' in match rule starts with 'arg' but could not parse arg number. Should be 'arg0' or 'arg7' for example.\n", key);
      goto failed;
    }

  if (end != length)
    {
      if ((end + strlen ("path")) == length &&
          _dbus_string_ends_with_c_str (&key_str, "path"))
        {
          is_path = TRUE;
        }
      else if (_dbus_string_equal_c_str (&key_str, "arg0namespace"))
        {
          int value_len = _dbus_string_get_length (value);

          is_namespace = TRUE;

          if (!_dbus_validate_bus_namespace (value, 0, value_len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                  "arg0namespace='%s' is not a valid prefix of a bus name",
                  _dbus_string_get_const_data (value));
              goto failed;
            }
        }
      else
        {
          dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
              "Key '%s' in match rule contains junk after argument number (%u). Only 'arg%upath' (for example) or 'arg0namespace' are valid", key, arg, arg);
          goto failed;
        }
    }

  /* If we didn't check this we could allocate a huge amount of RAM */
  if (arg > DBUS_MAXIMUM_MATCH_RULE_ARG_NUMBER)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Key '%s' in match rule has arg number %lu but the maximum is %d.\n", key, (unsigned long) arg, DBUS_MAXIMUM_MATCH_RULE_ARG_NUMBER);
      goto failed;
    }

  if ((rule->flags &MATCH_ARGS) &&
      rule->args_len > (int) arg &&
      rule->args[arg] != NULL)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                      "Argument %d matched more than once in match rule\n", key);
      goto failed;
    }

  if (!bus_match_rule_set_arg (rule, arg, value, is_path, is_namespace))
    {
     SET_OOM (error);
      goto failed;
    }

  return TRUE;

 failed:
  _DBUS_ASSERT_ERROR_IS_SET (error);
  return FALSE;
}

/*
 * The format is comma-separated with strings quoted with single quotes
 * as for the shell (to escape a literal single quote, use '\'').
 *
 * type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='Foo',
 * path='/bar/foo',destination=':452345.34'
 *
 */
MatchRule*
match_rule_parse (DBusConnection   *matches_go_to,
                      const DBusString *rule_text,
                      DBusError        *error)
{
  MatchRule *rule;
  RuleToken tokens[MAX_RULE_TOKENS+1]; /* NULL termination + 1 */
  int i;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (_dbus_string_get_length (rule_text) > DBUS_MAXIMUM_MATCH_RULE_LENGTH)
    {
      dbus_set_error (error, DBUS_ERROR_LIMITS_EXCEEDED,
                      "Match rule text is %d bytes, maximum is %d",
                      _dbus_string_get_length (rule_text),
                      DBUS_MAXIMUM_MATCH_RULE_LENGTH);
      return NULL;
    }

  memset (tokens, '\0', sizeof (tokens));

  rule = bus_match_rule_new (matches_go_to);
  if (rule == NULL)
    {
     SET_OOM (error);
      goto failed;
    }

  if (!tokenize_rule (rule_text, tokens, error))
    goto failed;

  i = 0;
  while (tokens[i].key != NULL)
    {
      DBusString tmp_str;
      int len;
      const char *key = tokens[i].key;
      const char *value = tokens[i].value;

      _dbus_string_init_const (&tmp_str, value);
      len = _dbus_string_get_length (&tmp_str);

      if (strcmp (key, "type") == 0)
        {
          int t;

          if (rule->flags & MATCH_MESSAGE_TYPE)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Key %s specified twice in match rule\n", key);
              goto failed;
            }

          t = dbus_message_type_from_string (value);

          if (t == DBUS_MESSAGE_TYPE_INVALID)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Invalid message type (%s) in match rule\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_message_type (rule, t))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "sender") == 0)
        {
          if (rule->flags & MATCH_SENDER)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Key %s specified twice in match rule\n", key);
              goto failed;
            }

          if (!_dbus_validate_bus_name (&tmp_str, 0, len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Sender name '%s' is invalid\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_sender (rule, value))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "interface") == 0)
        {
          if (rule->flags & MATCH_INTERFACE)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Key %s specified twice in match rule\n", key);
              goto failed;
            }

          if (!_dbus_validate_interface (&tmp_str, 0, len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Interface name '%s' is invalid\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_interface (rule, value))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "member") == 0)
        {
          if (rule->flags & MATCH_MEMBER)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Key %s specified twice in match rule\n", key);
              goto failed;
            }

          if (!_dbus_validate_member (&tmp_str, 0, len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Member name '%s' is invalid\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_member (rule, value))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "path") == 0 ||
          strcmp (key, "path_namespace") == 0)
        {
          dbus_bool_t is_namespace = (strcmp (key, "path_namespace") == 0);

          if (rule->flags & (MATCH_PATH | MATCH_PATH_NAMESPACE))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "path or path_namespace specified twice in match rule\n");
              goto failed;
            }

          if (!_dbus_validate_path (&tmp_str, 0, len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Path '%s' is invalid\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_path (rule, value, is_namespace))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "destination") == 0)
        {
          if (rule->flags & MATCH_DESTINATION)
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Key %s specified twice in match rule\n", key);
              goto failed;
            }

          if (!_dbus_validate_bus_name (&tmp_str, 0, len))
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "Destination name '%s' is invalid\n", value);
              goto failed;
            }

          if (!bus_match_rule_set_destination (rule, value))
            {
             SET_OOM (error);
              goto failed;
            }
        }
      else if (strcmp (key, "eavesdrop") == 0)
        {
          /* do not detect "eavesdrop" being used more than once in rule:
           * 1) it's not possible, it's only in the flags
           * 2) it might be used twice to disable eavesdropping when it's
           * automatically added (eg dbus-monitor/bustle) */

          /* we accept only "true|false" as possible values */
          if ((strcmp (value, "true") == 0))
            {
              bus_match_rule_set_client_is_eavesdropping (rule, TRUE);
            }
          else if (strcmp (value, "false") == 0)
            {
              bus_match_rule_set_client_is_eavesdropping (rule, FALSE);
            }
          else
            {
              dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                              "eavesdrop='%s' is invalid, "
                              "it should be 'true' or 'false'\n",
                              value);
              goto failed;
            }
        }
      else if (strncmp (key, "arg", 3) == 0)
        {
          if (!bus_match_rule_parse_arg_match (rule, key, &tmp_str, error))
            goto failed;
        }
      else
        {
          dbus_set_error (error, DBUS_ERROR_MATCH_RULE_INVALID,
                          "Unknown key \"%s\" in match rule",
                          key);
          goto failed;
        }

      ++i;
    }


  goto out;

 failed:
  _DBUS_ASSERT_ERROR_IS_SET (error);
  if (rule)
    {
      match_rule_unref (rule);
      rule = NULL;
    }

 out:

  i = 0;
  while (tokens[i].key || tokens[i].value)
    {
      _dbus_assert (i < MAX_RULE_TOKENS);
      dbus_free (tokens[i].key);
      dbus_free (tokens[i].value);
      ++i;
    }

  return rule;
}

typedef struct RulePool RulePool;
struct RulePool
{
  /* Maps non-NULL interface names to non-NULL (DBusList **)s */
  DBusHashTable *rules_by_iface;

  /* List of MatchRules which don't specify an interface */
  DBusList *rules_without_iface;
};

struct Matchmaker
{
  int refcount;

  /* Pools of rules, grouped by the type of message they match. 0
   * (DBUS_MESSAGE_TYPE_INVALID) represents rules that do not specify a message
   * type.
   */
  RulePool rules_by_type[DBUS_NUM_MESSAGE_TYPES];

  int last_cookie;
};

static void
rule_list_free (DBusList **rules)
{
  while (*rules != NULL)
    {
      MatchRule *rule;

      rule = (*rules)->data;
      match_rule_unref (rule);
      _dbus_list_remove_link (rules, *rules);
    }
}

static void
rule_list_ptr_free (DBusList **list)
{
  /* We have to cope with NULL because the hash table frees the "existing"
   * value (which is NULL) when creating a new table entry...
   */
  if (list != NULL)
    {
      rule_list_free (list);
      dbus_free (list);
    }
}

Matchmaker*
matchmaker_new (void)
{
  Matchmaker *matchmaker;
  int i;

  matchmaker = dbus_new0 (Matchmaker, 1);
  if (matchmaker == NULL)
    return NULL;

  matchmaker->refcount = 1;
  matchmaker->last_cookie = 0;

  for (i = DBUS_MESSAGE_TYPE_INVALID; i < DBUS_NUM_MESSAGE_TYPES; i++)
    {
      RulePool *p = matchmaker->rules_by_type + i;

      p->rules_by_iface = _dbus_hash_table_new (DBUS_HASH_STRING,
          dbus_free, (DBusFreeFunction) rule_list_ptr_free);

      if (p->rules_by_iface == NULL)
        goto nomem;
    }

  return matchmaker;

 nomem:
  for (i = DBUS_MESSAGE_TYPE_INVALID; i < DBUS_NUM_MESSAGE_TYPES; i++)
    {
      RulePool *p = matchmaker->rules_by_type + i;

      if (p->rules_by_iface == NULL)
        break;
      else
        _dbus_hash_table_unref (p->rules_by_iface);
    }
  dbus_free (matchmaker);

  return NULL;
}

DBusList **
matchmaker_get_rules (Matchmaker *matchmaker,
                          int            message_type,
                          const char    *interface,
                          dbus_bool_t    create)
{
  RulePool *p;

  _dbus_assert (message_type >= 0);
  _dbus_assert (message_type < DBUS_NUM_MESSAGE_TYPES);

  _dbus_verbose ("Looking up rules for message_type %d, interface %s\n",
                 message_type,
                 interface != NULL ? interface : "<null>");

  p = matchmaker->rules_by_type + message_type;

  if (interface == NULL)
    {
      return &p->rules_without_iface;
    }
  else
    {
      DBusList **list;

      list = _dbus_hash_table_lookup_string (p->rules_by_iface, interface);

      if (list == NULL && create)
        {
          char *dupped_interface;

          list = dbus_new0 (DBusList *, 1);
          if (list == NULL)
            return NULL;

          dupped_interface = _dbus_strdup (interface);
          if (dupped_interface == NULL)
            {
              dbus_free (list);
              return NULL;
            }

          _dbus_verbose ("Adding list for type %d, iface %s\n", message_type,
                         interface);

          if (!_dbus_hash_table_insert_string (p->rules_by_iface,
                                               dupped_interface, list))
            {
              dbus_free (list);
              dbus_free (dupped_interface);
              return NULL;
            }
        }

      return list;
    }
}

static void
bus_matchmaker_gc_rules (Matchmaker *matchmaker,
                         int            message_type,
                         const char    *interface,
                         DBusList     **rules)
{
  RulePool *p;

  if (interface == NULL)
    return;

  if (*rules != NULL)
    return;

  _dbus_verbose ("GCing HT entry for message_type %u, interface %s\n",
                 message_type, interface);

  p = matchmaker->rules_by_type + message_type;

  _dbus_assert (_dbus_hash_table_lookup_string (p->rules_by_iface, interface)
      == rules);

  _dbus_hash_table_remove_string (p->rules_by_iface, interface);
}

/* The rule can't be modified after it's added. */
dbus_bool_t
matchmaker_add_rule (Matchmaker   *matchmaker,
                         MatchRule    *rule)
{
  DBusList **rules;

  _dbus_verbose ("Adding rule with message_type %d, interface %s\n",
                 rule->message_type,
                 rule->interface != NULL ? rule->interface : "<null>");

  rules = matchmaker_get_rules (matchmaker, rule->message_type,
                                    rule->interface, TRUE);

  if (rules == NULL)
    return FALSE;

  if (!_dbus_list_append (rules, rule))
    return FALSE;

  rule->kdbus_cookie = ++(matchmaker->last_cookie);

  bus_match_rule_ref (rule);

#ifdef DBUS_ENABLE_VERBOSE_MODE
  {
    char *s = match_rule_to_string (rule);

    _dbus_verbose ("Added match rule %s to connection %p\n",
                   s, rule->matches_go_to);
    dbus_free (s);
  }
#endif

  return TRUE;
}

DBusList* matchmaker_get_rules_list (Matchmaker   *matchmaker,
                                     MatchRule    *rule)
{
  DBusList** list;

  list = matchmaker_get_rules (matchmaker, rule->message_type,
      rule->interface, FALSE);

  if(list)
    return *list;

  return NULL;
}

dbus_bool_t
match_rule_equal_lib (MatchRule *a,
                  MatchRule *b)
{
  if (a->flags != b->flags)
    return FALSE;

  if (a->matches_go_to != b->matches_go_to)
    return FALSE;

  if ((a->flags &MATCH_MESSAGE_TYPE) &&
      a->message_type != b->message_type)
    return FALSE;

  if ((a->flags &MATCH_MEMBER) &&
      strcmp (a->member, b->member) != 0)
    return FALSE;

  if ((a->flags &MATCH_PATH) &&
      strcmp (a->path, b->path) != 0)
    return FALSE;

  if ((a->flags &MATCH_INTERFACE) &&
      strcmp (a->interface, b->interface) != 0)
    return FALSE;

  if ((a->flags &MATCH_SENDER) &&
      strcmp (a->sender, b->sender) != 0)
    return FALSE;

  if ((a->flags &MATCH_DESTINATION) &&
      strcmp (a->destination, b->destination) != 0)
    return FALSE;

  /* we already compared the value of flags, and
   *MATCH_CLIENT_IS_EAVESDROPPING does not have another struct member */

  if (a->flags &MATCH_ARGS)
    {
      int i;

      if (a->args_len != b->args_len)
        return FALSE;

      i = 0;
      while (i < a->args_len)
        {
          int length;

          if ((a->args[i] != NULL) != (b->args[i] != NULL))
            return FALSE;

          if (a->arg_lens[i] != b->arg_lens[i])
            return FALSE;

          length = a->arg_lens[i] & ~MATCH_ARG_FLAGS;

          if (a->args[i] != NULL)
            {
              _dbus_assert (b->args[i] != NULL);
              if (memcmp (a->args[i], b->args[i], length) != 0)
                return FALSE;
            }

          ++i;
        }
    }

  return TRUE;
}

static void
bus_matchmaker_remove_rule_link (DBusList       **rules,
                                 DBusList        *link)
{
  MatchRule *rule = link->data;

  _dbus_list_remove_link (rules, link);

#ifdef DBUS_ENABLE_VERBOSE_MODE
  {
    char *s = match_rule_to_string (rule);

    _dbus_verbose ("Removed match rule %s for connection %p\n",
                   s, rule->matches_go_to);
    dbus_free (s);
  }
#endif

  match_rule_unref (rule);
}

/* Remove a single rule which is equal to the given rule by value */
dbus_bool_t
matchmaker_remove_rule_by_value (Matchmaker   *matchmaker,
                                     MatchRule    *value,
                                     DBusError       *error)
{
  DBusList **rules;
  DBusList *link = NULL;

  _dbus_verbose ("Removing rule by value with message_type %d, interface %s\n",
                 value->message_type,
                 value->interface != NULL ? value->interface : "<null>");

  rules = matchmaker_get_rules (matchmaker, value->message_type,
      value->interface, FALSE);

  if (rules != NULL)
    {
      /* we traverse backward because bus_connection_remove_match_rule()
       * removes the most-recently-added rule
       */
      link = _dbus_list_get_last_link (rules);
      while (link != NULL)
        {
          MatchRule *rule;
          DBusList *prev;

          rule = link->data;
          prev = _dbus_list_get_prev_link (rules, link);

          if (match_rule_equal_lib (rule, value))
            {
              bus_matchmaker_remove_rule_link (rules, link);
              break;
            }

          link = prev;
        }
    }

  if (link == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_NOT_FOUND,
                      "The given match rule wasn't found and can't be removed");
      return FALSE;
    }

  bus_matchmaker_gc_rules (matchmaker, value->message_type, value->interface,
      rules);

  return TRUE;
}

static void
rule_list_remove (DBusList **rules)
{
  DBusList *link;

  link = _dbus_list_get_first_link (rules);
  while (link != NULL)
    {
      DBusList *next;

      next = _dbus_list_get_next_link (rules, link);
      bus_matchmaker_remove_rule_link (rules, link);
      link = next;
    }
}

void
free_matchmaker (Matchmaker *matchmaker)
{
  int i;

  _dbus_verbose ("Removing all rules for connection\n");

  for (i = DBUS_MESSAGE_TYPE_INVALID; i < DBUS_NUM_MESSAGE_TYPES; i++)
    {
      RulePool *p = matchmaker->rules_by_type + i;
      DBusHashIter iter;

      rule_list_remove (&p->rules_without_iface);

      _dbus_hash_iter_init (p->rules_by_iface, &iter);
      while (_dbus_hash_iter_next (&iter))
        {
          DBusList **items = _dbus_hash_iter_get_value (&iter);

          rule_list_remove (items);

          if (*items == NULL)
            _dbus_hash_iter_remove_entry (&iter);
        }
    }
}

static dbus_bool_t
name_matches_name_rule (DBusTransport *transport,
                             const char    *name,
                             const char    *rule)
{
  if( !strncmp(rule, ":1.", 3) == !strncmp(name, ":1.", 3) )
    {
      if(!strcmp(name, rule))
        return TRUE;
    }
  else
    {
      struct nameInfo info;

      if(0 == kdbus_NameQuery(rule, transport, &info))
        {
          __u64 sender_id;

          _dbus_verbose("Owner discovered: :1.%llu\n", (unsigned long long int)info.uniqueId);
          free(info.sec_label);
          sender_id = strtoull(&name[3], NULL, 10);
          if(sender_id && (sender_id < ULLONG_MAX) && (sender_id == info.uniqueId))
            return TRUE;
        }
    }
  return FALSE;
}

static dbus_bool_t
str_has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len;
  prefix_len = strlen (prefix);
  if (strncmp (str, prefix, prefix_len) == 0)
    return TRUE;
  else
    return FALSE;
}

dbus_bool_t
match_rule_matches (DBusTransport *transport,
                    MatchRule     *rule,
                    DBusMessage   *message,
                    MatchFlags    already_matched)
{
  dbus_bool_t wants_to_eavesdrop = FALSE;
  int flags;

  /* All features of the match rule are AND'd together,
   * so FALSE if any of them don't match.
   */

  /* Don't bother re-matching features we've already checked implicitly. */
  flags = rule->flags & (~already_matched);

  if (flags & MATCH_CLIENT_IS_EAVESDROPPING)
    wants_to_eavesdrop = TRUE;

  if (flags & MATCH_MESSAGE_TYPE)
    {
      _dbus_assert (rule->message_type != DBUS_MESSAGE_TYPE_INVALID);

      if (rule->message_type != dbus_message_get_type (message))
        return FALSE;
    }

  if (flags & MATCH_INTERFACE)
    {
      const char *iface;

      _dbus_assert (rule->interface != NULL);

      iface = dbus_message_get_interface (message);
      if (iface == NULL)
        return FALSE;

      if (strcmp (iface, rule->interface) != 0)
        return FALSE;
    }

  if (flags & MATCH_MEMBER)
    {
      const char *member;

      _dbus_assert (rule->member != NULL);

      member = dbus_message_get_member (message);
      if (member == NULL)
        return FALSE;

      if (strcmp (member, rule->member) != 0)
        return FALSE;
    }

  if (flags & MATCH_SENDER)
    {
      _dbus_assert (rule->sender != NULL);

      if (!name_matches_name_rule (transport, dbus_message_get_sender(message), rule->sender))
        return FALSE;
    }

  /* Note: this part is relevant for eavesdropper rules:
   * Two cases:
   * 1) rule has a destination to be matched
   *   (flagMATCH_DESTINATION present). Rule will match if:
   *   - rule->destination matches the addressed_recipient
   *   AND
   *   - wants_to_eavesdrop=TRUE
   *
   *   Note: (the case in which addressed_recipient is the actual rule owner
   *   is handled elsewere in dispatch.c:bus_dispatch_matches().
   *
   * 2) rule has no destination. Rule will match if:
   *    - message has no specified destination (ie broadcasts)
   *      (Note: this will rule out unicast method calls and unicast signals,
   *      fixing FDO#269748)
   *    OR
   *    - wants_to_eavesdrop=TRUE (destination-catch-all situation)
   */
  if (flags & MATCH_DESTINATION)
    {
      const char *destination;

      _dbus_assert (rule->destination != NULL);

      destination = dbus_message_get_destination (message);
      if (destination == NULL)
        /* broadcast, but this rule specified a destination: no match */
        return FALSE;

      /* rule owner does not intend to eavesdrop: we'll deliver only msgs
       * directed to it, NOT MATCHING */
      if (!wants_to_eavesdrop)
        return FALSE;

      if (!name_matches_name_rule (transport, destination, rule->destination))
        return FALSE;

    }
  else /* no destination in rule */
    {
        dbus_bool_t msg_is_broadcast;

        _dbus_assert (rule->destination == NULL);

        msg_is_broadcast = (dbus_message_get_destination (message) == NULL);

        if (!wants_to_eavesdrop && !msg_is_broadcast)
          return FALSE;

        /* if we are here rule owner intends to eavesdrop
         * OR
         * message is being broadcasted */
    }

  if (flags & MATCH_PATH)
    {
      const char *path;

      _dbus_assert (rule->path != NULL);

      path = dbus_message_get_path (message);
      if (path == NULL)
        return FALSE;

      if (strcmp (path, rule->path) != 0)
        return FALSE;
    }

  if (flags & MATCH_PATH_NAMESPACE)
    {
      const char *path;
      int len;

      _dbus_assert (rule->path != NULL);

      path = dbus_message_get_path (message);
      if (path == NULL)
        return FALSE;

      if (!str_has_prefix (path, rule->path))
        return FALSE;

      len = strlen (rule->path);

      /* Check that the actual argument is within the expected
       * namespace, rather than just starting with that string,
       * by checking that the matched prefix is followed by a '/'
       * or the end of the path.
       */
      if (path[len] != '\0' && path[len] != '/')
        return FALSE;
    }

  if (flags & MATCH_ARGS)
    {
      int i;
      DBusMessageIter iter;

      _dbus_assert (rule->args != NULL);

      dbus_message_iter_init (message, &iter);

      i = 0;
      while (i < rule->args_len)
        {
          int current_type;
          const char *expected_arg;
          int expected_length;
          dbus_bool_t is_path, is_namespace;

          expected_arg = rule->args[i];
          expected_length = rule->arg_lens[i] & ~MATCH_ARG_FLAGS;
          is_path = (rule->arg_lens[i] & MATCH_ARG_IS_PATH) != 0;
          is_namespace = (rule->arg_lens[i] & MATCH_ARG_NAMESPACE) != 0;

          current_type = dbus_message_iter_get_arg_type (&iter);

          if (expected_arg != NULL)
            {
              const char *actual_arg;
              int actual_length;

              if (current_type != DBUS_TYPE_STRING &&
                  (!is_path || current_type != DBUS_TYPE_OBJECT_PATH))
                return FALSE;

              actual_arg = NULL;
              dbus_message_iter_get_basic (&iter, &actual_arg);
              _dbus_assert (actual_arg != NULL);

              actual_length = strlen (actual_arg);

              if (is_path)
                {
                  if (actual_length < expected_length &&
                      actual_arg[actual_length - 1] != '/')
                    return FALSE;

                  if (expected_length < actual_length &&
                      expected_arg[expected_length - 1] != '/')
                    return FALSE;

                  if (memcmp (actual_arg, expected_arg,
                              MIN (actual_length, expected_length)) != 0)
                    return FALSE;
                }
              else if (is_namespace)
                {
                  if (expected_length > actual_length)
                    return FALSE;

                  /* If the actual argument doesn't start with the expected
                   * namespace, then we don't match.
                   */
                  if (memcmp (expected_arg, actual_arg, expected_length) != 0)
                    return FALSE;

                  if (expected_length < actual_length)
                    {
                      /* Check that the actual argument is within the expected
                       * namespace, rather than just starting with that string,
                       * by checking that the matched prefix ends in a '.'.
                       *
                       * This doesn't stop "foo.bar." matching "foo.bar..baz"
                       * which is an invalid namespace, but at some point the
                       * daemon can't cover up for broken services.
                       */
                      if (actual_arg[expected_length] != '.')
                        return FALSE;
                    }
                  /* otherwise we had an exact match. */
                }
              else
                {
                  if (expected_length != actual_length ||
                      memcmp (expected_arg, actual_arg, expected_length) != 0)
                    return FALSE;
                }

            }

          if (current_type != DBUS_TYPE_INVALID)
            dbus_message_iter_next (&iter);

          ++i;
        }
    }

  return TRUE;
}

int
_match_rule_get_message_type (MatchRule *rule)
{
  if (rule->flags & MATCH_MESSAGE_TYPE)
    return rule->message_type;
  else
    return DBUS_MESSAGE_TYPE_INVALID;
}

const char *
_match_rule_get_interface (MatchRule *rule)
{
  if (rule->flags & MATCH_INTERFACE)
    return rule->interface;
  else
    return NULL;
}

const char *
_match_rule_get_member (MatchRule *rule)
{
  if (rule->flags & MATCH_MEMBER)
    return rule->member;
  else
    return NULL;
}

const char *
_match_rule_get_sender (MatchRule *rule)
{
  if (rule->flags & MATCH_SENDER)
    return rule->sender;
  else
    return NULL;
}

const char *
_match_rule_get_destination (MatchRule *rule)
{
  if (rule->flags & MATCH_DESTINATION)
    return rule->destination;
  else
    return NULL;
}

const char *
_match_rule_get_path (MatchRule *rule)
{
  if (rule->flags & MATCH_PATH)
    return rule->path;
  else
    return NULL;
}

const char *
_match_rule_get_path_namespace (MatchRule *rule)
{
  if (rule->flags & MATCH_PATH_NAMESPACE)
    return rule->path;
  else
    return NULL;
}

int
_match_rule_get_args_len (MatchRule *rule)
{
  return rule->args_len;
}

const char *
_match_rule_get_args (MatchRule *rule, int i)
{
  return rule->args[i];
}

unsigned int
_match_rule_get_arg_lens (MatchRule *rule, int i)
{
  return rule->arg_lens[i];
}
