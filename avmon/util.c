/*
 *  AVMON
 *  Copyright (C) 2007, 2008 Ramses Morales
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
 * \file util.c
 * \author Ramses Morales
 * \version $Id: util.c,v 1.3 2008/06/04 16:41:06 ramses Exp $
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "util.h"

struct _UtilCounter {
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

GQuark
util_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
	quark = g_quark_from_static_string("util-error-quark");
    
    return quark;
}

UtilCounter *
util_counter_new(void)
{
    UtilCounter *c = g_new0(UtilCounter, 1);

    pthread_mutex_init(&c->mutex, NULL);
    pthread_cond_init(&c->cond, NULL);

    return c;
}

void
util_counter_free(UtilCounter *c)
{
    if ( pthread_mutex_destroy(&c->mutex) )
	return; /* TODO: this function must return an error if
		   the mutex is locked */
    if ( pthread_cond_destroy(&c->cond) )
	return; /* TODO: same as before */
    
    g_free(c);
}

void
util_counter_inc(UtilCounter *c)
{
    pthread_mutex_lock(&c->mutex);
    c->count++;    
    pthread_mutex_unlock(&c->mutex);
}

void
util_counter_dec(UtilCounter *c)
{
    pthread_mutex_lock(&c->mutex);
    
    c->count--;
    
    if ( !c->count )
        pthread_cond_signal(&c->cond);
    
    pthread_mutex_unlock(&c->mutex);
}

void
util_counter_wait_for_zero(UtilCounter *c)
{    
    pthread_mutex_lock(&c->mutex);
    
    while ( c->count )
        pthread_cond_wait(&c->cond, &c->mutex);
    
    pthread_mutex_unlock(&c->mutex);   
}

int
util_counter_count(UtilCounter *c)
{    
    return c->count;   
}

void
util_set_error_errno(GError **gerror, GQuark domain, int code, const char *str)
{
    g_set_error(gerror, domain, code, "%s: %s", str, strerror(errno));
}

static void
_table_to_array(gpointer key, gpointer value, gpointer _array)
{
    g_ptr_array_add((GPtrArray *) _array, value);
}

GPtrArray *
util_g_hash_table_to_array(GHashTable *table)
{
    GPtrArray *array = g_ptr_array_new();
    g_hash_table_foreach(table, _table_to_array, array);
    return array;
}

#define UTIL_BLOCK 65536

guint32
util_fcopy(const char *src_filename, const char *dest_filename, guint32 bytes,
	   gboolean tail, GError **gerror)
{
    int src_fd = -1, dest_fd = -1;
    struct stat f_stat;
    unsigned char buff[UTIL_BLOCK];
    size_t actual_bytes, count, out_count;
    guint32 actual_bytes_saved, res = 0;
    off_t offset;

    g_assert(src_filename && dest_filename);

    if ( (src_fd = open(src_filename, O_RDONLY)) == -1 ) {
	util_set_error_errno(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
			     "can't open src file");
	goto bye;
    }

    if ( (dest_fd = open(dest_filename, O_RDWR | O_CREAT | O_TRUNC,
			 S_IRUSR | S_IWUSR )) == -1 ) {
	util_set_error_errno(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
			     "can't open dst file");
	goto bye;
    }
    
    fstat(src_fd, &f_stat);
    if ( !bytes )
	bytes = f_stat.st_size;

    actual_bytes_saved = actual_bytes = 
	bytes > f_stat.st_size ? f_stat.st_size : bytes;
    offset = tail ? f_stat.st_size - actual_bytes : 0;

    if ( lseek(src_fd, offset, SEEK_SET) != offset ) {
	util_set_error_errno(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
			     "couldn't change src offset");
	goto bye;
    }

    while ( actual_bytes ) {
	count = actual_bytes > UTIL_BLOCK ? UTIL_BLOCK : actual_bytes;
	if ( (out_count = read(src_fd, buff, count)) == -1 ) {
	    util_set_error_errno(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
				 "problem reading");
	    goto bye;
	}

	if ( out_count != count ) {
	    g_set_error(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
			"couldn't read enough bytes");
	    goto bye;
	}

	actual_bytes -= count;
	
	if ( (out_count = write(dest_fd, buff, count)) == -1 ) {
	    util_set_error_errno(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
				 "problem writing");
	    goto bye;
	}

	if ( out_count != count ) {
	    g_set_error(gerror, UTIL_ERROR, UTIL_ERROR_FCOPY,
			"couldn't write enough bytes");
	    goto bye;
	}
    }

    res = actual_bytes_saved;
    
bye:
    if ( src_fd != -1 )
	close(src_fd);
    if ( dest_fd != -1 )
	close(dest_fd);
    
    return res;
}

void
util_eliminate_newline(char *s)
{
    char *p = NULL;

    g_assert( s != NULL );

    p = strchr(s, '\n');
    if ( p )
        *p = '\0';
}
