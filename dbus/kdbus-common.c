/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-common.c  kdbus related utils for daemon and libdbus
 *
 * Copyright (C) 2013  Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version and under the terms of the GNU
 * Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
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
#include "kdbus.h"
#include "kdbus-common.h"
#include "dbus-transport-kdbus.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus-internals.h>
#include <dbus/dbus-shared.h>
#include "dbus-signals.h"
#include <stdio.h>
#include <sys/ioctl.h>

/*
 * Converts string with unique name into __u64 id number. If the name is not unique, sets error.
 */
__u64
sender_name_to_id(const char  *name,
                  DBusError   *error)
{
  __u64 sender_id = 0;

  if(!strncmp(name, ":1.", 3)) /*if name is unique name it must be converted to unique id*/
    sender_id = strtoull(&name[3], NULL, 10);
  else
    dbus_set_error (error, DBUS_ERROR_INVALID_ARGS, "Could not convert sender of the message into kdbus unique id");

  return sender_id;
}

static void make_item_name(const char *name, struct kdbus_item *item)
{
  size_t len = strlen(name) + 1;
  item->size = KDBUS_ITEM_HEADER_SIZE + len;
  item->type = KDBUS_ITEM_NAME;

  memcpy(item->str, name, len);
}

/**
 *
 * Asks the bus to assign the given name to the connection.
 *
 * Use same flags as original dbus version with one exception below.
 * Result flag #DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER is currently
 * never returned by kdbus, instead DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
 * is returned by kdbus.
 *
 * @param transport transport of the connection
 * @param name the name to request
 * @param flags flags
 * @returns a DBus result code on success, -errno on error
 */
int
request_kdbus_name(DBusTransport  *transport,
                   const char     *name,
                   const __u64     flags)
{
  struct kdbus_cmd *cmd_name;
  int fd;
  size_t len = strlen(name) + 1;

  __u64 size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(len);
  __u64 flags_kdbus = 0;

  if(!_dbus_transport_get_socket_fd (transport, &fd))
      return FALSE;

  cmd_name = alloca(size);
  cmd_name->size = size;

  if(flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
    flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
  if(!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
    flags_kdbus |= KDBUS_NAME_QUEUE;
  if(flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
    flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;

  cmd_name->flags = flags_kdbus;
  make_item_name(name, &(cmd_name->items[0]));

  _dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name) < 0)
    {
      _dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
      if(errno == EEXIST)
        return DBUS_REQUEST_NAME_REPLY_EXISTS;
      if(errno == EALREADY)
        return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
      return -errno;
    }
  else if ((cmd_name->return_flags & KDBUS_NAME_PRIMARY)
       && !(cmd_name->return_flags & KDBUS_NAME_ACQUIRED))
    return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;

  _dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if(cmd_name->return_flags & KDBUS_NAME_IN_QUEUE)
    return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;

  return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

/**
 *
 * Releases well-known name - the connections resign from the name
 * which can be then assigned to another connection or the connection
 * is being removed from the queue for that name
 *
 * @param fd - file descriptor of the connection
 * @param name the name to request
 * @param id unique id of the connection for which the name is being released
 * @returns a DBus result code on success, -errno on error
 */
int
release_kdbus_name(DBusTransport  *transport,
                   const char     *name)
{
  struct kdbus_cmd *cmd_name;
  int fd;

  size_t len = strlen(name)+1;
  __u64 size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(len);

  if(!_dbus_transport_get_socket_fd (transport, &fd))
      return FALSE;

  cmd_name = alloca(size);
  cmd_name->size = size;
  cmd_name->flags = 0;
  make_item_name(name, &(cmd_name->items[0]));

  if (ioctl(fd, KDBUS_CMD_NAME_RELEASE, cmd_name))
    {
      if((errno == ESRCH))
        return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EADDRINUSE)
        return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
      _dbus_verbose ("error releasing name '%s'. Error: %m, %d\n", name, errno);
      return -errno;
    }

  _dbus_verbose("Name '%s' released\n", name);

  return DBUS_RELEASE_NAME_REPLY_RELEASED;
}

dbus_bool_t
kdbus_command_free(DBusTransport  *transport,
                   __u64           offset)
{
  int result;
  int fd;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return FALSE;

  do {
    struct kdbus_cmd_free cmd = {0};
    cmd.size = sizeof(cmd);
    cmd.offset = offset;

    result = ioctl(fd, KDBUS_CMD_FREE, &cmd);

  } while (result < 0 && errno == EINTR);

  return (result == 0);
}

/**
 * Performs kdbus query of id of the given name
 *
 * @param name name to query for
 * @param transport transport
 * @param pInfo nameInfo structure address to store info about the name
 * @return 0 on success, -errno if failed
 */
int
kdbus_NameQuery(const char      *name,
                DBusTransport   *transport,
                struct nameInfo *pInfo)
{
  struct kdbus_cmd_info *cmd;
  int ret;
  int fd;
  uint64_t size;
  __u64 id = 0;

  memset(pInfo, 0, sizeof(struct nameInfo));

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return -EPERM;

  size = sizeof(*cmd);
  if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
     id = strtoull(&name[3], NULL, 10);
  if(id == 0)
    size += KDBUS_ITEM_SIZE(strlen(name) + 1);

  cmd = alloca(size);
  if (!cmd)
  {
    _dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
    return -errno;
  }
  memset(cmd, 0, sizeof(*cmd));

  cmd->size = size;
  cmd->id = id;
  if(id == 0)
  {
    make_item_name(name, &(cmd->items[0]));
  }

  cmd->attach_flags = _KDBUS_ATTACH_ALL;

  again:
  ret = ioctl(fd, KDBUS_CMD_CONN_INFO, cmd);
  if (ret < 0)
  {
    if(errno == EINTR)
      goto again;
    pInfo->uniqueId = 0;
    return -errno;
  }
  else
  {
    struct kdbus_info *info;
    struct kdbus_item *item;

    info = (struct kdbus_info *)((char*)dbus_transport_get_pool_pointer(transport) + cmd->offset);
    pInfo->uniqueId = info->id;
    pInfo->flags = info->flags;

    item = info->items;
    while((uint8_t *)(item) < (uint8_t *)(info) + info->size)
    {
	  switch (item->type)
	  {
		  case KDBUS_ITEM_PIDS:
			  pInfo->processId = item->pids.pid;
			  break;
		  case KDBUS_ITEM_CREDS:
			  pInfo->userId = item->creds.uid;
			  break;
		  case KDBUS_ITEM_SECLABEL:
			  pInfo->sec_label_len = item->size - KDBUS_ITEM_HEADER_SIZE - 1;
			  if(pInfo->sec_label_len != 0)
			  {
				  pInfo->sec_label = malloc(pInfo->sec_label_len);
				  if(pInfo->sec_label == NULL)
					  ret = -1;
				  else
					  memcpy(pInfo->sec_label, item->data, pInfo->sec_label_len);
			  }
			  break;
	  }

      item = KDBUS_ITEM_NEXT(item);
    }

    if (!kdbus_command_free (transport, cmd->offset))
    {
      _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
      free(pInfo->sec_label);
      pInfo->sec_label = NULL;
      return -errno;
    }
  }

  return ret;
}

/*
 *  Asks kdbus for uid of the owner of the name given in the message
 */
dbus_bool_t
kdbus_connection_get_unix_user(DBusTransport  *transport,
                               const char     *name,
                               unsigned long  *uid,
                               DBusError      *error)
{
  struct nameInfo info;
  int inter_ret;
  dbus_bool_t ret = FALSE;

  inter_ret = kdbus_NameQuery(name, transport, &info);
  if(inter_ret == 0) //name found
  {
    _dbus_verbose("User id:%llu\n", (unsigned long long) info.userId);
    *uid = info.userId;
    free(info.sec_label);
    return TRUE;
  }
  else if((inter_ret == -ESRCH) || (inter_ret == -ENXIO)) //name has no owner
    {
      _dbus_verbose ("Name %s has no owner.\n", name);
      dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not get UID of name '%s': no such name", name);
    }

  else
  {
    _dbus_verbose("kdbus error determining UID: err %d (%m)\n", errno);
    dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not determine UID for '%s'", name);
  }

  return ret;
}

/*
 *  Asks kdbus for pid of the owner of the name given in the message
 */
dbus_bool_t
kdbus_connection_get_unix_process_id(DBusTransport  *transport,
                                     const char     *name,
                                     unsigned long  *pid,
                                     DBusError      *error)
{
  struct nameInfo info;
  int inter_ret;
  dbus_bool_t ret = FALSE;

  inter_ret = kdbus_NameQuery(name, transport, &info);
  if(inter_ret == 0) //name found
    {
      _dbus_verbose("Process id:%llu\n", (unsigned long long) info.processId);
      *pid = info.processId;
      free(info.sec_label);
      return TRUE;
    }
  else if((inter_ret == -ESRCH) || (inter_ret == -ENXIO)) //name has no owner
    dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get PID of name '%s': no such name", name);
  else
    {
      _dbus_verbose("kdbus error determining PID: err %d (%m)\n", errno);
      dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine PID for '%s'", name);
    }

  return ret;
}

/**
 * Opposing to dbus, in kdbus removes all match rules with given
 * cookie, which in this implementation is equal to uniqe id.
 *
 * @param transport transport
 * @param id connection id for which rules are to be removed
 * @param cookie cookie of the rules to be removed
 */
static dbus_bool_t
remove_match_kdbus (DBusTransport *transport,
                    __u64          cookie)
{
  struct kdbus_cmd_match cmd;
  int fd;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return FALSE;

  cmd.cookie = cookie;
  cmd.size = sizeof(struct kdbus_cmd_match);
  cmd.flags = 0;

  if(ioctl(fd, KDBUS_CMD_MATCH_REMOVE, &cmd))
    {
      _dbus_verbose("Failed removing match rule %llu, error: %d, %m\n", cookie, errno);
      return FALSE;
    }
  else
    {
      _dbus_verbose("Match rule %llu removed correctly.\n", cookie);
      return TRUE;
    }
}

/*
 *  Removes match rule in kdbus on behalf of sender of the message
 */
dbus_bool_t
kdbus_remove_match (DBusTransport *transport,
                    DBusList      *rules,
                    const char    *sender,
                    MatchRule     *rule_to_remove,
                    DBusError     *error)
{
  __u64 cookie = 0;
  DBusList *link = NULL;

  if (rules != NULL)
    {
      /* we traverse backward because bus_connection_remove_match_rule()
       * removes the most-recently-added rule
       */
      link = _dbus_list_get_last_link (&rules);
      while (link != NULL)
        {
          MatchRule *rule;
          DBusList *prev;

          rule = link->data;
          prev = _dbus_list_get_prev_link (&rules, link);

          if (match_rule_equal_lib (rule, rule_to_remove))
            {
              cookie = match_rule_get_cookie(rule);
              break;
            }

          link = prev;
        }
    }

  if(cookie == 0)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_NOT_FOUND,
                      "The given match rule wasn't found and can't be removed");
      return FALSE;
    }

  if(!remove_match_kdbus (transport, cookie))
    {
      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not remove match rule");
      return FALSE;
    }

  return TRUE;
}
