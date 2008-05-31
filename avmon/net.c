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
 */

/**
 * \file net.c
 * \author Ramses Morales
 * \version $Id: net.c,v 1.3 2008/05/31 00:23:38 ramses Exp $
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include "net.h"
#include "util.h"

GQuark
net_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
	quark = g_quark_from_static_string("net-error-quark");
    
    return quark;
}

static gboolean INIT = FALSE;

void
net_init(void)
{
    if ( INIT )
	return;
    INIT = TRUE;
    
    signal(SIGPIPE, SIG_IGN);
}

/************************************************
 * count (value-result argument) 
 * gets decremented as bytes are read, so the caller can know
 * how many bytes where left after the function returns
 */
int 
net_read(int fd, void *buff, size_t *count, GError **gerror)
{
    ssize_t bytes_read;
    uint8_t *buff_pointer = buff;

    while ( *count ) {
	if ( (bytes_read = read(fd, buff_pointer, *count)) == -1 ) {
	    if ( errno == EINTR ) {
		util_set_error_errno(gerror, NET_ERROR, NET_ERROR_EINTR, "net_read");
		return -1;
	    } if ( errno == EAGAIN ) {
		util_set_error_errno(gerror, NET_ERROR, NET_ERROR_EAGAIN, "net_read");
		return -1;
	    } else {
		util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN, "net_read");
		return -1;
	    }
	} else if ( bytes_read == 0 ) {
	    g_set_error(gerror, NET_ERROR, NET_ERROR_ZERO, "net_read");
	    return 0;
	} else {
	    *count -= bytes_read;
	    buff_pointer += bytes_read;
	}
    }

    return 0;
}

/**
 * writes exactly count bytes
 * returns -1 on error 0 on success
 */
int
net_write(int fd, const void *buff, size_t count, GError **gerror)
{
    ssize_t bytes_written;
    uint8_t *buff_pointer = (uint8_t *) buff;
    
    while ( count ) {
	if ( (bytes_written = write(fd, buff_pointer, count)) == -1 ) {
	    util_set_error_errno(gerror, NET_ERROR, errno == EPIPE ? 
				 NET_ERROR_SIGPIPE:NET_ERROR_WRITE, "net_write");
	    return -1;
	} else {
	    count -= bytes_written;
	    buff_pointer += bytes_written;
	}
    }

    return 0;
}

/**
 * \return 1 on timeout, -1 on error, 0 OK
 */
int
net_connect_nb(int socketfd, struct sockaddr *peer_addr, int peer_addr_size,
	       int timeout, int timeoutfd, GError **gerror)
{
    socklen_t len;
    fd_set rset, wset;
    int flags, maxfd, sel, result = -1, error = 0;
    struct timeval tv;

    g_assert( (timeout >= 0) && (timeoutfd >= 0) && socketfd && peer_addr);

    if ( (flags = fcntl(socketfd, F_GETFL)) == -1 ) {
	util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN, "connect_nb");
	return -1;
    }

    if ( fcntl(socketfd, F_SETFL, flags | O_NONBLOCK) == -1 ) {
	util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN, "connect_nb");
	return -1;
    }

    if ( connect(socketfd, peer_addr, peer_addr_size) ) {
	if ( errno != EINPROGRESS ) {
	    util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN, "connect_nb");
	    goto bye;
	}

	FD_ZERO(&rset);
	FD_SET(socketfd, &rset);
	if ( timeoutfd ) {
	    FD_SET(timeoutfd, &rset);
	    maxfd = timeoutfd > socketfd ? timeoutfd : socketfd;
	} else
	    maxfd = socketfd;
	maxfd++;
	wset = rset;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
	sel = select(maxfd, &rset, &wset, NULL, &tv);
	if ( !sel ) {
	    result = 1;
	    goto bye;
	}
	if ( sel == -1 ) {
	    util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN, "connect_nb");
	    goto bye;
	}

	if ( timeoutfd )
	    if ( FD_ISSET(timeoutfd, &rset) ) {
		result = 1;
		goto bye;
	    }

	if ( FD_ISSET(socketfd, &rset) || FD_ISSET(socketfd, &wset) ) {
	    len = sizeof(error);
	    if ( getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ) {
		g_set_error(gerror, NET_ERROR, NET_ERROR_GEN,
			    "pending socket error: %d", error);
		goto bye;
	    }
	} else {
	    g_set_error(gerror, NET_ERROR, NET_ERROR_GEN, "nothing set");
	    goto bye;
	}
    }

    result = 0;

bye:
    fcntl(socketfd, F_SETFL, flags);
    
    return result;
}

int
net_read_byte(int socketfd, uint8_t *buff, GError **gerror)
{
    size_t size = 1;
    return net_read(socketfd, (void *) buff, &size, gerror);
}

int
net_read_32bit(int socketfd, uint32_t *u32, GError **gerror)
{
    size_t size = 4;
    int result = net_read(socketfd, u32, &size, gerror);
    
    *u32 = ntohl(*u32);

    return result;
}

int
net_read_16bit(int socketfd, uint16_t *u16, GError **gerror)
{
    size_t size = 2;
    int result = net_read(socketfd, u16, &size, gerror);
    
    *u16 = ntohs(*u16);
    
    return result;
}

struct addrinfo *
net_char_to_addrinfo(const char *name_or_ip, const char *port, GError **gerror)
{
    struct addrinfo hints, *res = NULL;
    int err;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_CANONNAME | AI_NUMERICSERV;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if ( (err = getaddrinfo(name_or_ip, port, &hints, &res)) ) {
	g_set_error(gerror, NET_ERROR, NET_ERROR_GEN, gai_strerror(err));
	return NULL;
    }

    return res;
}

#define IPSIZE 16
static char _myIP[IPSIZE + 1] = { '\0' };

const char *
net_my_ip(GError **gerror)
{
    struct addrinfo hints, *ai = NULL, *p = NULL;
    struct sockaddr_in *sain;
    char hostname[128];
    int error;

    if ( _myIP[0] )
        return _myIP;
    
    if ( gethostname(hostname, 127) ) {
	util_set_error_errno(gerror, NET_ERROR, NET_ERROR_GEN,
			     "Trying to get this host's name");
	goto exit_with_error;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_INET;
    if ( (error = getaddrinfo(hostname, NULL, &hints, &ai)) ) {
	g_set_error(gerror, NET_ERROR, NET_ERROR_GEN, "%s", gai_strerror(error));
	goto exit_with_error;
    }

    for ( p = ai; ai; ai = ai->ai_next ) {
	sain = (struct sockaddr_in *) ai->ai_addr;

	inet_ntop(AF_INET, &sain->sin_addr, _myIP, sizeof(_myIP));

	if ( strstr(_myIP, "127.0.0.1") == NULL )
	    break;
    }

    if ( !ai ) {
	g_set_error(gerror, NET_ERROR, NET_ERROR_GEN, "Didn't find non-local IP for %s", hostname);
	goto exit_with_error;
    }

    freeaddrinfo(p);

    return _myIP;

exit_with_error:
    if ( p )
	freeaddrinfo(p);

    return NULL;
}
