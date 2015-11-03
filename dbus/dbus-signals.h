/*
 * dbus-signals.h
 *
 *  Created on: Feb 26, 2014
 *      Author: r.pajak
 */

#ifndef DBUS_SIGNALS_H_
#define DBUS_SIGNALS_H_

/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* signals.h  Bus signal connection implementation
 *
 * Copyright (C) 2003  Red Hat, Inc.
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

#include <dbus/dbus.h>
#include <dbus/dbus-string.h>
#include <dbus/dbus-sysdeps.h>
#include <dbus/dbus-transport.h>

typedef struct Matchmaker    Matchmaker;
typedef struct MatchRule     MatchRule;

#ifndef MATCH_ARG_NAMESPACE
#define MATCH_ARG_NAMESPACE   0x4000000u
#endif
#ifndef MATCH_ARG_IS_PATH
#define MATCH_ARG_IS_PATH  0x8000000u
#endif

typedef enum
{
  MATCH_MESSAGE_TYPE            = 1 << 0,
  MATCH_INTERFACE               = 1 << 1,
  MATCH_MEMBER                  = 1 << 2,
  MATCH_SENDER                  = 1 << 3,
  MATCH_DESTINATION             = 1 << 4,
  MATCH_PATH                    = 1 << 5,
  MATCH_ARGS                    = 1 << 6,
  MATCH_PATH_NAMESPACE          = 1 << 7,
  MATCH_CLIENT_IS_EAVESDROPPING = 1 << 8
} MatchFlags;

void  match_rule_unref (MatchRule   *rule);
void  match_rule_set_cookie (MatchRule *rule, dbus_uint64_t cookie);
dbus_uint64_t match_rule_get_cookie (MatchRule *rule);

/* Calling this methods a client declares that it is creating a rule which
 * needs to eavesdrop (e.g., dbus-monitor), any other created rules not
 * setting themselves as eavesdropping won't receive any message not addressed
 * to them, when eavedrop is enabled in the policy.  On the other hand, when
 * eavedrop is not enabled in policy, this method won't have any effect */
//void bus_match_rule_set_client_is_eavesdropping (BusMatchRule     *rule,
//                                                 dbus_bool_t is_eavesdropping);

DBusList ** matchmaker_get_rules (Matchmaker *matchmaker,
                          int            message_type,
                          const char    *interface,
                          dbus_bool_t    create);

MatchRule* match_rule_parse (DBusConnection   *matches_go_to,
                                    const DBusString *rule_text,
                                    DBusError        *error);

dbus_bool_t match_rule_equal_lib (MatchRule *a, MatchRule *b);


Matchmaker* matchmaker_new   (void);

dbus_bool_t matchmaker_add_rule             (Matchmaker   *matchmaker,
                                                 MatchRule    *rule);
DBusList* matchmaker_get_rules_list (Matchmaker   *matchmaker,
                                     MatchRule    *rule);
dbus_bool_t matchmaker_remove_rule_by_value (Matchmaker   *matchmaker,
                                                 MatchRule    *value,
                                                 DBusError       *error);
void        free_matchmaker                     (Matchmaker *matchmaker);

dbus_bool_t match_rule_matches (DBusTransport *transport,
                    MatchRule    *rule,
                    DBusMessage     *message,
                    MatchFlags    already_matched);

#ifdef DBUS_ENABLE_VERBOSE_MODE
char* match_rule_to_string (MatchRule *rule);
#endif

int          _match_rule_get_message_type   (MatchRule *rule);
const char * _match_rule_get_interface      (MatchRule *rule);
const char * _match_rule_get_member         (MatchRule *rule);
const char * _match_rule_get_sender         (MatchRule *rule);
const char * _match_rule_get_destination    (MatchRule *rule);
const char * _match_rule_get_path           (MatchRule *rule);
const char * _match_rule_get_path_namespace (MatchRule *rule);
int          _match_rule_get_args_len       (MatchRule *rule);
const char * _match_rule_get_args           (MatchRule *rule, int i);
unsigned int _match_rule_get_arg_lens       (MatchRule *rule, int i);

#endif /* DBUS_SIGNALS_H_ */
