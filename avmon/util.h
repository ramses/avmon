/*
 *  AVMON
 *  Copyright (C) 2007, 2008, 2009 Ramses Morales
 *
 *  This file is part of AVMON.
 *
 *  AVMON is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  AVMON is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with AVMON.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *  Neither the names of Distributed Protocols Research Group, University of
 *  Illinois at Urbana-Champaign, nor the names of its contributors may be used
 *  to endorse or promote products derived from this Software without specific
 *  prior written permission.
 */

/**
 * \file util.h
 * \author Ramses Morales
 * \version
 */

#ifndef __AVMON_UTIL_H__
#define __AVMON_UTIL_H__

#include <avmon/common.h>

AVMON_BEGIN_DECLS

#define UTIL_ERROR       util_error_quark()
#define UTIL_ERROR_FCOPY 1

typedef struct _UtilCounter UtilCounter;

UtilCounter *util_counter_new(void);
void util_counter_free(UtilCounter *c);
void util_counter_inc(UtilCounter *c);
void util_counter_dec(UtilCounter *c);
int util_counter_count(UtilCounter *c);
// blocks until counter reaches zero
void util_counter_wait_for_zero(UtilCounter *c);

void util_set_error_errno(GError **gerror, GQuark domain, int code, const char *str);

GPtrArray *util_g_hash_table_to_array(GHashTable *table);

/**
 * Creates a partial or complete copy of a file.
 *
 * \param src_filename[in] Source file name.
 * \param dest_filenam[in] Destination file name.
 * \param bytes[in] Number of bytes to copy. If 0, then the whole file is copied.
 * \param tail[in] If TRUE, the bytes to copy are taken from the end of the file. If
 * FALSE, the bytes to copy are taken from the start of the file.
 * \param gerror[in, out] If the operation cannot be completed, *gerror will be non-NULL.
 * \return number of bytes copied, 0 on error.
 */
guint32 util_fcopy(const char *src_filename, const char *dest_filename, guint32 bytes,
		   gboolean tail, GError **gerror);

void util_eliminate_newline(char *s);

AVMON_END_DECLS

#endif /* __AVMON_UTIL_H__ */
