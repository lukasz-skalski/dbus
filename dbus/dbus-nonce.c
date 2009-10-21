/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-nonce.c  Nonce handling functions used by nonce-tcp (internal to D-Bus implementation)
 *
 * Copyright (C) 2009 Klaralvdalens Datakonsult AB, a KDAB Group company, info@kdab.net
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

// major sections of this file are modified code from libassuan, (C) FSF
#include "dbus-nonce.h"
#include "dbus-internals.h"
#include "dbus-protocol.h"
#include "dbus-sysdeps.h"

#include <stdio.h>

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

static dbus_bool_t
do_check_nonce (int fd, const DBusString *nonce, DBusError *error)
{
  DBusString buffer;
  DBusString p;
  size_t nleft;
  dbus_bool_t result;
  int n;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  nleft = 16;

  if (   !_dbus_string_init (&buffer)
      || !_dbus_string_init (&p) ) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        _dbus_string_free (&p);
        _dbus_string_free (&buffer);
        return;
      }

  while (nleft)
    {
      n = _dbus_read_socket (fd, &p, nleft);
      if (n == -1 && _dbus_get_is_errno_eintr())
        ;
      else if (n == -1 && _dbus_get_is_errno_eagain_or_ewouldblock())
        _dbus_sleep_milliseconds (100);
      else if (n==-1)
        {
          dbus_set_error (error, DBUS_ERROR_IO_ERROR, "Could not read nonce from socket (fd=%d)", fd );
          _dbus_string_free (&p);
          _dbus_string_free (&buffer);
          return FALSE;
        }
      else if (!n)
        {
          _dbus_string_free (&p);
          _dbus_string_free (&buffer);
          dbus_set_error (error, DBUS_ERROR_IO_ERROR, "Could not read nonce from socket (fd=%d)", fd );
          return FALSE;
        }
      else
        {
          _dbus_string_append_len(&buffer, _dbus_string_get_const_data (&p), n);
          nleft -= n;
        }
    }

  result =  _dbus_string_equal_len (&buffer, nonce, 16);
  if (!result)
    dbus_set_error (error, DBUS_ERROR_ACCESS_DENIED, "Nonces do not match, access denied (fd=%d)", fd );

  _dbus_string_free (&p);
  _dbus_string_free (&buffer);

  return result;
}

//PENDING(kdab) document
dbus_bool_t
_dbus_read_nonce (const DBusString *fname, DBusString *nonce, DBusError* error)
{
  //PENDING(kdab) replace errno by DBusError
  FILE *fp;
  char buffer[17];
  buffer[sizeof buffer - 1] = '\0';
  size_t nread;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  _dbus_verbose ("reading nonce from file: %s\n", _dbus_string_get_const_data (fname));


  fp = fopen (_dbus_string_get_const_data (fname), "rb");
  if (!fp)
    return FALSE;
  nread = fread (buffer, 1, sizeof buffer - 1, fp);
  fclose (fp);
  if (!nread)
    {
      dbus_set_error (error, DBUS_ERROR_FILE_NOT_FOUND, "Could not read nonce from file %s", _dbus_string_get_const_data (fname));
      return FALSE;
    }

  if (!_dbus_string_append_len (nonce, buffer, sizeof buffer - 1 ))
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      return FALSE;
    }
  return TRUE;
}

static int
accept_with_nonce (int listen_fd, const DBusString *nonce)
{

}

int
_dbus_accept_with_noncefile (int listen_fd, const DBusNonceFile *noncefile)
{
  int fd;
  DBusString nonce;

  _dbus_assert (noncefile != NULL);
  _dbus_string_init (&nonce);
  //PENDING(kdab): set better errors
  if (_dbus_read_nonce (_dbus_noncefile_get_path(noncefile), &nonce, NULL) != TRUE)
    return -1;
  fd = _dbus_accept (listen_fd);
  if (_dbus_socket_is_invalid (fd))
    return fd;
  if (do_check_nonce(fd, &nonce, NULL) != TRUE) {
    _dbus_verbose ("nonce check failed. Closing socket.\n");
    _dbus_close_socket(fd, NULL);
    return -1;
  }

  return fd;
}

dbus_bool_t
_dbus_generate_noncefilename (DBusString *buf, DBusError *error)
{
  dbus_bool_t ret;
  DBusString randomStr;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  ret = _dbus_string_init (&randomStr);
  if (!ret)
    goto oom;
  ret = _dbus_generate_random_ascii (&randomStr, 8);
  if (!ret)
    goto oom;
  if (!_dbus_string_append (buf, _dbus_get_tmpdir())
      || !_dbus_string_append (buf, DBUS_DIR_SEPARATOR "dbus_nonce-")
      || !_dbus_string_append (buf, _dbus_string_get_const_data (&randomStr)) )
    goto oom;

  _dbus_string_free (&randomStr);
  return TRUE;
oom:
  dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
  _dbus_string_free (&randomStr);
  return FALSE;
}

static dbus_bool_t
generate_and_write_nonce (const DBusString *filename, DBusError *error)
{
  DBusString nonce;
  dbus_bool_t ret;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  _dbus_string_init (&nonce);

  if (!_dbus_generate_random_bytes (&nonce, 16))
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      _dbus_string_free (&nonce);
      return FALSE;
    }

  ret = _dbus_string_save_to_file (&nonce, filename, error);

  _dbus_string_free (&nonce);

  return ret;
}

dbus_bool_t
_dbus_send_nonce(int fd, const DBusString *noncefile, DBusError *error)
{
  dbus_bool_t read_result;
  int send_result;
  size_t sendLen;
  DBusString nonce;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (_dbus_string_get_length (noncefile) == 0)
    return FALSE;

  if ( !_dbus_string_init (&nonce) )
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      return FALSE;
  }

  read_result = _dbus_read_nonce (noncefile, &nonce, NULL);

  if (!read_result)
    {
      dbus_set_error (error,
                      _dbus_error_from_errno (errno),
                      "Could not read nonce from file %s (%s)",
                      _dbus_string_get_const_data (noncefile), _dbus_strerror(errno));
      _dbus_string_free (&nonce);
      return FALSE;
    }

  send_result = _dbus_write_socket (fd, &nonce, 0, _dbus_string_get_length (&nonce));

  _dbus_string_free (&nonce);

  if (send_result == -1)
  {
    dbus_set_error (error,
                    _dbus_error_from_errno (errno),
                    "Failed to send nonce (fd=%d): %s",
                    fd, _dbus_strerror(errno));
    return FALSE;
  }

  return TRUE;
}

static dbus_bool_t
do_noncefile_create (DBusNonceFile *noncefile,
                     DBusError *error,
                     dbus_bool_t use_subdir)
{
    dbus_bool_t ret;
    DBusString randomStr;

    _DBUS_ASSERT_ERROR_IS_CLEAR (error);

    _dbus_assert (noncefile);

    if (!_dbus_string_init (&randomStr))
      {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto on_error;
      }

    if (!_dbus_generate_random_ascii (&randomStr, 8))
      {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto on_error;
      }

    if (!_dbus_string_init (&noncefile->dir)
        || !_dbus_string_append (&noncefile->dir, _dbus_get_tmpdir()))
      {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto on_error;
      }
    if (use_subdir)
      {
        if (!_dbus_string_append (&noncefile->dir, DBUS_DIR_SEPARATOR "dbus_nonce-")
            || !_dbus_string_append (&noncefile->dir, _dbus_string_get_const_data (&randomStr)) )
          {
            dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
            goto on_error;
          }
        if (!_dbus_string_init (&noncefile->path)
            || !_dbus_string_copy (&noncefile->dir, 0, &noncefile->path, 0)
            || !_dbus_string_append (&noncefile->dir, DBUS_DIR_SEPARATOR "nonce"))
          {
            dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
            goto on_error;
          }
        if (!_dbus_create_directory (&noncefile->dir, error))
          {
            goto on_error;
          }

      }
    else
      {
        if (!_dbus_string_init (&noncefile->path)
            || !_dbus_string_copy (&noncefile->dir, 0, &noncefile->path, 0)
            || !_dbus_string_append (&noncefile->path, DBUS_DIR_SEPARATOR "dbus_nonce-")
            || !_dbus_string_append (&noncefile->path, _dbus_string_get_const_data (&randomStr)))
          {
            dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
            goto on_error;
          }

      }

    if (!generate_and_write_nonce (&noncefile->path, error))
      {
        if (use_subdir)
          _dbus_delete_directory (&noncefile->dir, NULL); //we ignore possible errors deleting the dir and return the write error instead
        goto on_error;
      }

    _dbus_string_free (&randomStr);

    return TRUE;
  on_error:
    if (use_subdir)
      _dbus_delete_directory (&noncefile->dir, NULL);
    _dbus_string_free (&noncefile->dir);
    _dbus_string_free (&noncefile->path);
    _dbus_string_free (&randomStr);
    return FALSE;
}

#ifdef DBUS_WIN
dbus_bool_t
_dbus_noncefile_create (DBusNonceFile *noncefile,
                        DBusError *error)
{
    return do_noncefile_create (noncefile, error, /*use_subdir=*/FALSE);
}

dbus_bool_t
_dbus_noncefile_delete (DBusNonceFile *noncefile,
                        DBusError *error)
{
    _DBUS_ASSERT_ERROR_IS_CLEAR (error);

    _dbus_delete_file (&noncefile->path, error);
    _dbus_string_free (&noncefile->dir);
    _dbus_string_free (&noncefile->path);
}

#else
dbus_bool_t
_dbus_noncefile_create (DBusNonceFile *noncefile,
                        DBusError *error)
{
    return do_noncefile_create (noncefile, error, /*use_subdir=*/TRUE);
}

dbus_bool_t
_dbus_noncefile_delete (DBusNonceFile *noncefile,
                        DBusError *error)
{
    _DBUS_ASSERT_ERROR_IS_CLEAR (error);

    _dbus_delete_directory (&noncefile->dir, error);
    _dbus_string_free (&noncefile->dir);
    _dbus_string_free (&noncefile->path);
}
#endif


const DBusString*
_dbus_noncefile_get_path (const DBusNonceFile *noncefile)
{
    _dbus_assert (noncefile);
    return &noncefile->path;
}

dbus_bool_t
_dbus_noncefile_check_nonce (int fd,
                             const DBusNonceFile *noncefile,
                             DBusError* error)
{
    return do_check_nonce (fd, _dbus_noncefile_get_path (noncefile), error);
}


/** @} end of nonce */