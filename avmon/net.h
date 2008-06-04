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
 * \file net.h
 * \author Ramses Morales
 * \version $Id: net.h,v 1.4 2008/06/04 16:41:06 ramses Exp $
 */

#ifndef __AVMON_NET_H__
#define __AVMON_NET_H__

#include <avmon/common.h>
#include <netinet/in.h>

AVMON_BEGIN_DECLS

#define NET_ERROR         net_error_quark()
#define NET_ERROR_GEN     1
#define NET_ERROR_ZERO    2
#define NET_ERROR_EINTR   3
#define NET_ERROR_EAGAIN  4
#define NET_ERROR_WRITE   5
#define NET_ERROR_CV      6
#define NET_ERROR_SIGPIPE 7

#define NET_IP_CHAR_SIZE 16

void net_init(void);
int net_read(int fd, void *buff, size_t *count, GError **gerror);
int net_read_byte(int fd, uint8_t *buff, GError **gerror);
int net_write(int fd, const void *buff, size_t count, GError **gerror);
int net_connect_nb(int socketfd, struct sockaddr *peer_addr, int peer_addr_size,
		   int timeout, int timeoutfd, GError **gerror);

/**
 * \param[in] name_or_ip hostname or ip address.
 * \param[in] port numeric port
 * \param[out] gerror *gerror will be non-NULL if an error occurs.
 * \return A SOCK_STREAM addrinfo or NULL if error.
 */
struct addrinfo *net_char_to_addrinfo(const char *name_or_ip, const char *port,
				      GError **gerror);
const char *net_my_ip(GError **gerror);
int net_read_32bit(int socketfd, uint32_t *u32, GError **gerror);
int net_read_16bit(int socketfd, uint16_t *u16, GError **gerror);

AVMON_END_DECLS

#endif /* __AVMON_NET_H__ */
