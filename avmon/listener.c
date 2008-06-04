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
 * \file listener.c
 * \author Ramses Morales
 * \version $Id: listener.c,v 1.7 2008/06/04 16:41:07 ramses Exp $
 */

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>

#include "listener.h"
#include "util.h"
#include "avmon.h"
#include "messages.h"

struct _AVMONListener {
    uint16_t tcp_port;
    uint16_t udp_port;
    
    int tcp_read_pipe;
    int tcp_write_pipe;
    int udp_read_pipe;
    int udp_write_pipe;

    int tcp_fd;
    int udp_fd;

    pthread_t tcp_listener_thread;
    pthread_t udp_listener_thread;

    UtilCounter *tcp_thread_count;
    UtilCounter *udp_thread_count;

    AVMONNode *node;
};

typedef struct {
    AVMONListener *al;
    socklen_t peer_len;
    int connection_fd;
    struct sockaddr_in peer_addr;
} PacketHandlerArgs;

#define BUFFSIZE 128

typedef struct {
    uint8_t buff[BUFFSIZE];
    socklen_t clilen;
    ssize_t bytes_received;
    struct sockaddr_in cliaddr;
    AVMONListener *al;
} DatagramHandlerArgs;

GQuark
avmon_listener_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
        quark = g_quark_from_static_string("avmon-listener-error-quark");
    
    return quark;
}

extern void avmon_receive_join(AVMONNode *node, int socketfd, const char *peer_ip);

static void *
handle_join(void *args)
{
    PacketHandlerArgs *pargs = (PacketHandlerArgs *) args;
    char ip[NET_IP_CHAR_SIZE + 1];

    pthread_detach(pthread_self());

#ifdef DEBUG
    g_debug("handle_join");
#endif

    inet_ntop(AF_INET, &pargs->peer_addr.sin_addr, ip, NET_IP_CHAR_SIZE);
    avmon_receive_join(pargs->al->node, pargs->connection_fd, ip);

    util_counter_dec(pargs->al->tcp_thread_count);

    g_free(args);

    pthread_exit(NULL);
}

extern void avmon_receive_cv_fetch(AVMONNode *node, int socketfd);

static void *
handle_cv_fetch(void *args)
{
    PacketHandlerArgs *pargs = (PacketHandlerArgs *) args;
    
    pthread_detach(pthread_self());

#ifdef DEBUG
    g_debug("handle_cv_fetch");
#endif

    avmon_receive_cv_fetch(pargs->al->node, pargs->connection_fd);

    util_counter_dec(pargs->al->tcp_thread_count);

    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_get_ps(AVMONNode *node, int socketfd);

static void *
handle_get_ps(void *args)
{
    PacketHandlerArgs *pargs = (PacketHandlerArgs *) args;
    
    pthread_detach(pthread_self());

#ifdef DEBUG
    g_debug("handle_get_ps");
#endif

    avmon_receive_get_ps(pargs->al->node, pargs->connection_fd);
    
    util_counter_dec(pargs->al->tcp_thread_count);

    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_get_ts(AVMONNode *node, int socketfd);

static void *
handle_get_ts(void *args)
{
    PacketHandlerArgs *pargs = (PacketHandlerArgs *) args;
    
    pthread_detach(pthread_self());
    
    avmon_receive_get_ts(pargs->al->node, pargs->connection_fd);
    
    util_counter_dec(pargs->al->tcp_thread_count);
    
    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_get_raw_availability(AVMONNode *node, int socketfd);

static void *
handle_get_raw_availability(void *args)
{
    PacketHandlerArgs *pargs = (PacketHandlerArgs *) args;
    
    pthread_detach(pthread_self());

#ifdef DEBUG
    g_debug("handle_get_raw_availability");
#endif
    
    avmon_receive_get_raw_availability(pargs->al->node, pargs->connection_fd);
    
    util_counter_dec(pargs->al->tcp_thread_count);

    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_monitoring_ping(AVMONNode *node, const uint8_t *buff,
					  struct sockaddr_in *cliaddr);

static void *
handle_monitoring_ping(void *args)
{
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;
    
    pthread_detach(pthread_self());

    avmon_receive_monitoring_ping(dhargs->al->node, dhargs->buff, &dhargs->cliaddr);

    util_counter_dec(dhargs->al->udp_thread_count);

    g_free(args);

    pthread_exit(NULL);
}

extern void avmon_receive_cv_ping(AVMONNode *node, uint8_t *buff,
				  struct sockaddr_in *cliaddr);

static void *
handle_cv_ping(void *args)
{
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;

    pthread_detach(pthread_self());
    
    avmon_receive_cv_ping(dhargs->al->node, dhargs->buff, &dhargs->cliaddr);
    
    util_counter_dec(dhargs->al->udp_thread_count);

    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_monitoring_pong(AVMONNode *node, const char *ip,
					  const uint8_t *buff);

static void *
handle_monitoring_pong(void *args)
{
    char ip[NET_IP_CHAR_SIZE + 1];
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;
    
    pthread_detach(pthread_self());

    inet_ntop(AF_INET, &dhargs->cliaddr.sin_addr, ip, NET_IP_CHAR_SIZE);

    avmon_receive_monitoring_pong(dhargs->al->node, ip, dhargs->buff);

    util_counter_dec(dhargs->al->udp_thread_count);

    g_free(args);
    
    pthread_exit(NULL);
}

extern void avmon_receive_cv_pong(AVMONNode *node, const char *ip,
				  const uint8_t *buff);

static void *
handle_cv_pong(void *args)
{
    char ip[NET_IP_CHAR_SIZE + 1];
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;
    
    pthread_detach(pthread_self());

    inet_ntop(AF_INET, &dhargs->cliaddr.sin_addr, ip, NET_IP_CHAR_SIZE);

    avmon_receive_cv_pong(dhargs->al->node, ip, dhargs->buff);

    util_counter_dec(dhargs->al->udp_thread_count);

    g_free(args);    

    pthread_exit(NULL);
}


extern void avmon_receive_notify(AVMONNode *node, const uint8_t *buff);

static void *
handle_notify(void *args)
{
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;

    avmon_receive_notify(dhargs->al->node, dhargs->buff);
    
    util_counter_dec(dhargs->al->udp_thread_count);

    g_free(args);

    pthread_exit(NULL);
}

extern void avmon_receive_forward(AVMONNode *node, const uint8_t *buff);

static void *
handle_forward(void *args)
{
    DatagramHandlerArgs *dhargs = (DatagramHandlerArgs *) args;
    
    avmon_receive_forward(dhargs->al->node, dhargs->buff);
    
    util_counter_dec(dhargs->al->udp_thread_count);
    
    g_free(args);
    
    pthread_exit(NULL);
}

typedef void *(*hp)(void *);

static hp datagram_handlers[6] = {
    handle_monitoring_ping,
    handle_monitoring_pong,
    handle_cv_ping,
    handle_cv_pong,
    handle_notify,
    handle_forward
};

static hp packet_handlers[5] = {
    handle_join,
    handle_cv_fetch,
    handle_get_ps,
    handle_get_raw_availability,
    handle_get_ts
};

static void *
tcp_listener(void *_al)
{
    PacketHandlerArgs *pack_args = NULL;
    AVMONListener *al = (AVMONListener *) _al;
    struct sockaddr_in peer;
    socklen_t connection_len;
    int connection_fd;
    pthread_t tid;
    uint8_t type;
    fd_set rset;
    int flags, biggest_fd;
    GError *gerror = NULL;
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    
    biggest_fd =
	al->tcp_fd > al->tcp_read_pipe ? al->tcp_fd : al->tcp_read_pipe;
    biggest_fd++;

    flags = fcntl(al->tcp_fd, F_GETFL);
    fcntl(al->tcp_fd, F_SETFL, flags | O_NONBLOCK);
    
    for ( ; ; ) {
	connection_len = sizeof(peer);
	
	FD_ZERO(&rset);
	FD_SET(al->tcp_fd, &rset);
	FD_SET(al->tcp_read_pipe, &rset);
	if ( select(biggest_fd, &rset, NULL, NULL, NULL) == -1 )
	    continue;

	if ( FD_ISSET(al->tcp_read_pipe, &rset) )
	    break;
	
	if ( !FD_ISSET(al->tcp_fd, &rset) )
	    continue;

	if ( (connection_fd = accept(al->tcp_fd, (struct sockaddr *) &peer,
				     &connection_len)) == -1 ) {
	    if ( errno == EWOULDBLOCK || errno == ECONNABORTED ||
		 errno == EPROTO || errno == EINTR )
		//peer aborted before I reached accept
		continue;
	} else {
	    if ( msg_read_head(connection_fd, &gerror) ) {
		if ( gerror ) {
		    g_warning("tcp_listener: %s\n", gerror->message);
		    g_error_free(gerror);
		    gerror = NULL;
		}
		close(connection_fd);
		continue;
	    }
	    if ( msg_read_type(connection_fd, &type, &gerror) ) {
		if ( gerror ) {
		    g_warning("tcp_listener: %s\n", gerror->message);
		    g_error_free(gerror);
		    gerror = NULL;
		}
		close(connection_fd);
		continue;
	    }
#ifdef DEBUG
	    g_debug("tcp_listener received %u", type);
#endif
	    
	    pack_args = g_new0(PacketHandlerArgs, 1);
	    pack_args->peer_len = connection_len;
	    pack_args->connection_fd = connection_fd;
	    pack_args->peer_addr = peer;
	    pack_args->al = al;

	    util_counter_inc(al->tcp_thread_count);
	    if ( pthread_create(&tid, &thread_attr, packet_handlers[type - 1],
				(void *) pack_args) ) {
		close(connection_fd);
		g_free(pack_args);
		util_counter_dec(al->tcp_thread_count);
	    }
	}
    }

    util_counter_wait_for_zero(al->tcp_thread_count);
    
    close(al->tcp_read_pipe);
    close(al->tcp_fd);

#ifdef DEBUG
    g_debug("tcp_listener out");
#endif
    
    pthread_exit(NULL);
}

static int
tcp_listener_start(AVMONListener *al, GError **error)
{
    struct sockaddr_in servaddr;
    int on = 1;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = al->tcp_port;

    al->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( al->tcp_fd < 0 ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_TCP,
			     "problem creating socket");
	goto exit_error;
    }

    if ( setsockopt(al->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_TCP,
			     "error setting SO_REUSEADDR");
	goto exit_error;
    }
    
    if ( bind(al->tcp_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_TCP, "error binding");
	goto exit_error;
    }

    if ( listen(al->tcp_fd, 512) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_TCP, "error listening");
	goto exit_error;
    }

    if ( pthread_create(&al->tcp_listener_thread, NULL, &tcp_listener,
			(void *) al) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_TCP,
			     "couldn't create listener thread");
	goto exit_error;
    }

    return 0;

exit_error:
    if ( al->tcp_fd )
	close(al->tcp_fd);
    return -1;
}

static void *
udp_listener(void *_al) 
{
    fd_set rset;
    socklen_t clilen;
    struct sockaddr_in cliaddr;
    DatagramHandlerArgs *dhargs;
    uint8_t buffer[BUFFSIZE];
    pthread_t tid;
    int biggest_fd;
    pthread_attr_t thread_attr;
    AVMONListener *al = (AVMONListener *) _al;

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    
    biggest_fd =
	al->udp_fd > al->udp_read_pipe ? al->udp_fd : al->udp_read_pipe;
    biggest_fd++;
    
    for ( ; ; ) {
	FD_ZERO(&rset);
	FD_SET(al->udp_fd, &rset);
	FD_SET(al->udp_read_pipe, &rset);
	if ( select(biggest_fd, &rset, NULL, NULL, NULL) == -1 )
	    continue;
	
	if ( FD_ISSET(al->udp_read_pipe, &rset) )
	    break;

	if ( !FD_ISSET(al->udp_fd, &rset) )
	    continue;

	clilen = sizeof(cliaddr);
	dhargs = g_new0(DatagramHandlerArgs, 1);
	dhargs->bytes_received = recvfrom(al->udp_fd, buffer, BUFFSIZE, 0,
					  (struct sockaddr *) &cliaddr, 
					  &clilen);
	if ( dhargs->bytes_received <= 0 ) {
	    g_free(dhargs);
	    continue;
	}

	if ( !msg_is_valid_datagram(buffer, dhargs->bytes_received) ) {
	    g_free(dhargs);
	    continue;
	}

	dhargs->clilen = clilen;
	memcpy(dhargs->buff, buffer, dhargs->bytes_received);
	dhargs->cliaddr = cliaddr;
	dhargs->al = al;
	
	util_counter_inc(al->udp_thread_count);
	if ( pthread_create(&tid, &thread_attr, 
			    datagram_handlers[msg_datagram_type(buffer) - 1],
			    (void *) dhargs)) {
	    g_free(dhargs);
	    util_counter_dec(al->udp_thread_count);
	}
    }

    util_counter_wait_for_zero(al->udp_thread_count);

    close(al->udp_fd);
    close(al->udp_read_pipe);

#ifdef DEBUG
    g_debug("udp_listener out");
#endif

    pthread_exit(NULL);
}

static int
udp_listener_start(AVMONListener *al, GError **error)
{
    struct sockaddr_in servaddr;
    
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = al->udp_port;
    
    al->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(al->udp_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

    if ( pthread_create(&al->udp_listener_thread, NULL, udp_listener,
			(void *) al) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START_UDP,
			     "couldn't crete UDP server thread");
	close(al->udp_fd);
	return -1;
    }

    return 0;
}

static void
avmon_listener_free(AVMONListener *al)
{
    g_assert(al != NULL);
    
    if ( al->tcp_thread_count )
	util_counter_free(al->tcp_thread_count);
    if ( al->udp_thread_count )
	util_counter_free(al->udp_thread_count);
    
    g_free(al);
    al = NULL;
}

AVMONListener *
avmon_listener_start(AVMONNode *node, Conf *conf, GError **error)
{
    AVMONListener *al = g_new0(AVMONListener, 1);
    int tcp_pipe[2], udp_pipe[2];
    int tcp_port, udp_port;
    gboolean pipes = FALSE;
    
    al->node = node;

    al->tcp_thread_count = util_counter_new();
    al->udp_thread_count = util_counter_new();
    
    if ( pipe(udp_pipe) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START, "creating udp pipe");
	goto exit_error;
    }

    if ( pipe(tcp_pipe) ) {
	util_set_error_errno(error, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_START, "creating tcp pipe");
	goto exit_error;
    }

    al->tcp_read_pipe = tcp_pipe[0];
    al->tcp_write_pipe = tcp_pipe[1];
    al->udp_read_pipe = udp_pipe[0];
    al->udp_write_pipe = udp_pipe[1];
    pipes = TRUE;

    tcp_port = conf_get_listener_tcp_udp_port(conf);
    udp_port = conf_get_listener_tcp_udp_port(conf);

    if ( tcp_port > 65535 || udp_port > 65535 
	 || tcp_port < 1 || udp_port < 1 ) {
	g_set_error(error, AVMON_LISTENER_ERROR, AVMON_LISTENER_ERROR_START,
		    "bad tcp/udp port: %d/%d", tcp_port, udp_port);
	goto exit_error;
    }
    al->tcp_port = htons(tcp_port);
    al->udp_port = htons(udp_port);

    if ( tcp_listener_start(al, error) )
	goto exit_error;
    if ( udp_listener_start(al, error) )
	goto exit_error;

    return al;

exit_error:
    avmon_listener_free(al);
    if ( pipes ) {
	close(tcp_pipe[0]);
	close(tcp_pipe[1]);
	close(udp_pipe[0]);
	close(udp_pipe[1]);
    }
    return NULL;
}

int
avmon_listener_stop(AVMONListener *al, GError **gerror)
{
    if ( write(al->udp_write_pipe, "stop", 4) == -1 ) {
	util_set_error_errno(gerror, AVMON_LISTENER_ERROR, 
			     AVMON_LISTENER_ERROR_STOP_UDP, "writing to pipe");
	return -1;
    }
    close(al->udp_write_pipe);
    
    if ( pthread_join(al->udp_listener_thread, NULL) ) {
	util_set_error_errno(gerror, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_STOP_UDP, "joining thread");
	return -1;
    }
    
    if ( write(al->tcp_write_pipe, "stop", 4) == -1 ) {
	util_set_error_errno(gerror, AVMON_LISTENER_ERROR, 
			     AVMON_LISTENER_ERROR_STOP_TCP, "writing to pipe");
	return -1;
    }
    close(al->udp_write_pipe);
    
    if ( pthread_join(al->tcp_listener_thread, NULL) ) {
	util_set_error_errno(gerror, AVMON_LISTENER_ERROR,
			     AVMON_LISTENER_ERROR_STOP_TCP, "joining thread");
	return -1;
    }

    avmon_listener_free(al);

    return 0;
}
