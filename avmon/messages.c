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
 * \file messages.c
 * \author Ramses Morales
 * \version
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef BACKGROUND_OVERHEAD_COUNTER
#include <pthread.h>
#include <errno.h>
#endif

#include "messages.h"
#include "util.h"
#include "avmon.h"

const char *MSG_HEAD="AVMON|01";

GQuark
msg_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
	quark = g_quark_from_static_string("msg-error-quark");
    
    return quark;
}

#ifdef BACKGROUND_OVERHEAD_COUNTER
typedef struct {
    char message_name[1024];
    guint32 size;
} BocMessage;

typedef struct {
    char *message_name;
    guint32 i;
    guint64 bytes;
} MessageCount;

static void
message_count_free(gpointer mc)
{
    g_free(((MessageCount *) mc)->message_name);
    g_free(mc);
}

struct _MsgBOC {
    int boc_write_pipe;
    int boc_read_pipe;
    pthread_t boc_tid;
};

//TODO: this feature cannot be used if a single process wants to start multiple AVMON instances.
//To do that, all the message calls would require an extra parameter, and I don't have time
//for that right now.
static MsgBOC *_msgboc;
//<<<<<<<<------------

static void *
message_counter(void *_msgboc)
{
    int err_count, boc_read_pipe = ((MsgBOC *) _msgboc)->boc_read_pipe;
    fd_set rset;
    BocMessage *bm = g_new(BocMessage, 1);
    MessageCount *mc = NULL;
    GHashTable *mtable =
	g_hash_table_new_full(g_str_hash, g_str_equal, NULL, message_count_free);
    
    for ( err_count = 0; ; ) {
	FD_ZERO(&rset);
	FD_SET(boc_read_pipe, &rset);
	
	if ( select(boc_read_pipe + 1, &rset, NULL, NULL, NULL) == -1 ) {
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    g_warning("message counter system-level error: %s", buff);
	    err_count++;
	    if ( err_count == 3 )
		exit(1);
	    continue;
	} else {
	    err_count = 0;
	}

	if ( !FD_ISSET(boc_read_pipe, &rset) )
	    g_error("message counter wtf");

	if ( read(boc_read_pipe, bm, sizeof(BocMessage)) < sizeof(BocMessage) )
	    g_error("message counter received a bad message");

	if ( bm->message_name[0] == '\0' )
	    break;

	if ( !(mc = g_hash_table_lookup(mtable, bm->message_name)) ) {
	    mc = g_new(MessageCount, 1);
	    mc->message_name = g_strdup(bm->message_name);
	    mc->i = 0;
	    mc->bytes = bm->size;
	    
	    g_hash_table_insert(mtable, mc->message_name, mc);
	} else {
	    mc->i++;
	    mc->bytes += bm->size;
	}
	mc = NULL;
    }

    g_free(bm);
    g_hash_table_destroy(mtable);

    close(boc_read_pipe);
    
    pthread_exit(NULL);
}

MsgBOC *
msg_background_overhead_counter_start(GError **gerror)
{
    g_assert(_msgboc == NULL); //see comment at _msgboc's definition
    
    MsgBOC *msgboc = g_new0(MsgBOC, 1);
    int boc_pipe[2];

    if ( pipe(boc_pipe) ) {
	util_set_error_errno(gerror, MSG_ERROR, MSG_ERROR_BACKGROUND_OVERHEAD_COUNTER,
			     "couldn't create pipe");
	goto exit_error;
    }

    msgboc->boc_read_pipe = boc_pipe[0];
    msgboc->boc_write_pipe = boc_pipe[1];

    if ( pthread_create(&msgboc->boc_tid, NULL, message_counter, (void *) msgboc) ) {
	close(msgboc->boc_read_pipe);
	close(msgboc->boc_write_pipe);
	goto exit_error;
    }

    _msgboc = msgboc;
    
    return msgboc;
    
exit_error:
    return NULL;
}

int
msg_background_overhead_counter_quit(MsgBOC *msgboc, GError **gerror)
{
    BocMessage bm;

    bm.message_name[0] = '\0';

    if ( write(msgboc->boc_write_pipe, &bm, sizeof(BocMessage)) == -1 ) {
	util_set_error_errno(gerror, MSG_ERROR, MSG_ERROR_BACKGROUND_OVERHEAD_COUNTER,
			     "overhead counter pipe");
	return -1;
    }

    pthread_join(msgboc->boc_tid, NULL);
    
    //this function is called by avmon_stop after all possible message generation has been stopped
    close(msgboc->boc_write_pipe);

    g_free(msgboc);
    msgboc = NULL;

    return 0;
}

void
msg_boc_count(const char *msg_name, guint32 size)
{
    BocMessage bm;
    strncpy(bm.message_name, msg_name, 1023);
    bm.message_name[1024] ='\0';
    bm.size = size;

    write(_msgboc->boc_write_pipe, &bm, sizeof(BocMessage));
}
#endif

void
msg_send_cv_ping(const char *peer_ip, const char *peer_port, uint16_t my_port)
{
    struct sockaddr_in pinged_peer;
    int pingfd;
    uint8_t cv_ping_msg[MSG_CV_PING_SIZE];
    my_port = htons(my_port);
    	
    memset(&pinged_peer, 0, sizeof(struct sockaddr_in));
    pinged_peer.sin_family = AF_INET;
    pinged_peer.sin_port = htons(atoi(peer_port));
    inet_pton(AF_INET, peer_ip, &pinged_peer.sin_addr);
    pingfd = socket(AF_INET, SOCK_DGRAM, 0);

    memcpy(&cv_ping_msg[0], MSG_HEAD, MSG_HEAD_SIZE);
    cv_ping_msg[MSG_HEAD_SIZE] = MSG_CV_PING;
    memcpy(&cv_ping_msg[MSG_HEAD_SIZE + 1], &my_port, 2);
    sendto(pingfd, (void *) cv_ping_msg, MSG_CV_PING_SIZE, 0,
	   (struct sockaddr *) &pinged_peer, sizeof(pinged_peer));
    close(pingfd);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_CV_PING", MSG_CV_PING_SIZE);
#endif
}

void
msg_send_forward(const char *forward_ip, const char *forward_port, 
		 uint16_t joiner_port, const char *joiner_ip, uint8_t weight)
{
    int ffd, size;
    struct sockaddr_in forward;
    uint8_t *forward_msg = NULL;
    
    memset(&forward, 0, sizeof(struct sockaddr_in));
    forward.sin_family = AF_INET;
    forward.sin_port = htons(atoi(forward_port));
    inet_pton(AF_INET, forward_ip, &forward.sin_addr);
    ffd = socket(AF_INET, SOCK_DGRAM, 0);

    size = MSG_HEAD_SIZE + 1 + 1 + 2 + 1 + strlen(joiner_ip);
    forward_msg = (uint8_t *) g_malloc(size);
    
    memcpy(forward_msg, MSG_HEAD, MSG_HEAD_SIZE);
    forward_msg[MSG_HEAD_SIZE] = MSG_FORWARD;
    forward_msg[MSG_HEAD_SIZE + 1] = weight;
    joiner_port = htons(joiner_port);
    memcpy(&forward_msg[MSG_HEAD_SIZE + 1 + 1], &joiner_port, 2);
    forward_msg[MSG_HEAD_SIZE + 1 + 1 + 2] = (uint8_t) strlen(joiner_ip);
    memcpy(&forward_msg[MSG_HEAD_SIZE + 1 + 1 + 2 + 1], joiner_ip, strlen(joiner_ip));
    sendto(ffd, (void *) forward_msg, size, 0, (struct sockaddr *) &forward,
	   sizeof(forward));

    close(ffd);
    g_free(forward_msg);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_FORWARD", size);
#endif
}

MsgForwardData *
msg_data_from_forward_buff(const uint8_t *buff, GError **gerror)
{
    MsgForwardData *mfd = g_new(MsgForwardData, 1);
    uint8_t ip_char_len;
    
    mfd->weight = buff[MSG_HEAD_SIZE + 1];

    memcpy(&mfd->port, &buff[MSG_HEAD_SIZE + 1 + 1], 2);
    mfd->port = ntohs(mfd->port);

    ip_char_len = buff[MSG_HEAD_SIZE + 1 + 1 + 2];
    if ( ip_char_len > NET_IP_CHAR_SIZE ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_BAD_FORWARD, "ip size %d", ip_char_len);
	g_free(mfd);
	return NULL;
    }

    memcpy(mfd->ip, &buff[MSG_HEAD_SIZE + 1 + 1 + 2 + 1], ip_char_len);
    mfd->ip[ip_char_len] = '\0';
    
    return mfd;
}

void
msg_forward_data_free(MsgForwardData *mfd)
{
    g_free(mfd);
}

int
msg_send_cv_fetch(int socketfd, GError **gerror)
{
    uint8_t fetch_msg[MSG_CV_FETCH_SIZE];

    memcpy(&fetch_msg[0], MSG_HEAD, MSG_HEAD_SIZE);
    fetch_msg[MSG_HEAD_SIZE] = MSG_CV_FETCH;

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_CV_FETCH", MSG_CV_FETCH_SIZE);
#endif

    return net_write(socketfd, &fetch_msg, MSG_CV_FETCH_SIZE, gerror);
}

int
msg_send_join(int socketfd, uint8_t weight, uint16_t my_port, GError **gerror)
{
    uint8_t join_msg[MSG_JOIN_SIZE];
    
    memcpy(&join_msg[0], MSG_HEAD, MSG_HEAD_SIZE);
    join_msg[MSG_HEAD_SIZE] = MSG_JOIN;
    join_msg[MSG_HEAD_SIZE + 1] = weight;
    my_port = htons(my_port);
    memcpy(&join_msg[MSG_HEAD_SIZE + 2], &my_port, 2);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_JOIN", MSG_JOIN_SIZE);
#endif

    return net_write(socketfd, &join_msg, MSG_JOIN_SIZE, gerror);
}

void
msg_send_notify(const char *i_ip, const char *i_port, const char *j_ip,
		const char *j_port)
{
    struct sockaddr_in i, j;
    int fd, size;
    uint8_t *msg_notify;
    uint16_t payload_size;
    char *ids = g_strconcat(i_ip, MSG_DELIMITER_S, i_port, MSG_DELIMITER_S, j_ip,
			    MSG_DELIMITER_S, j_port, NULL);

    memset(&i, 0, sizeof(struct sockaddr_in));
    memset(&j, 0, sizeof(struct sockaddr_in));

    i.sin_family = AF_INET;
    j.sin_family = AF_INET;
    i.sin_port = htons(atoi(i_port));
    j.sin_port = htons(atoi(j_port));
    inet_pton(AF_INET, i_ip, &i.sin_addr);
    inet_pton(AF_INET, j_ip, &j.sin_addr);

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    size = MSG_HEAD_SIZE + 1 + 2 + strlen(ids);
    msg_notify = (uint8_t *) g_malloc(size);
    memcpy(msg_notify, MSG_HEAD, MSG_HEAD_SIZE);
    msg_notify[MSG_HEAD_SIZE] = MSG_NOTIFY;
    payload_size = (uint16_t) strlen(ids);
    payload_size = htons(payload_size);
    memcpy(&msg_notify[MSG_HEAD_SIZE + 1], &payload_size, sizeof(uint16_t));
    memcpy(&msg_notify[MSG_HEAD_SIZE + 3], ids, strlen(ids));

    sendto(fd, (void *) msg_notify, size, 0, (struct sockaddr *) &i, sizeof(i));
    sendto(fd, (void *) msg_notify, size, 0, (struct sockaddr *) &j, sizeof(j));

    close(fd);

    g_free(msg_notify);
    g_free(ids);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_NOTIFY", size);
    msg_boc_count("MSG_NOTIFY", size);
#endif
}

int
msg_send_monitoring_ping(const char *ip, const char *port, uint16_t my_port,
			 GError **gerror)
{
    struct sockaddr_in ping_addr;
    int pingfd;
    uint8_t ping_msg[MSG_PING_SIZE];
    
    my_port = htons(my_port);
    
    memset(&ping_addr, 0, sizeof(ping_addr));
    ping_addr.sin_family = AF_INET;
    ping_addr.sin_port = htons(atoi(port));
    if ( !inet_pton(AF_INET, ip, &ping_addr.sin_addr) ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_IP, "%s is not an IP", ip);
	return -1;
    }
    pingfd = socket(AF_INET, SOCK_DGRAM, 0);

    memcpy(&ping_msg[0], MSG_HEAD, MSG_HEAD_SIZE);
    ping_msg[MSG_HEAD_SIZE] = MSG_PING;
    memcpy(&ping_msg[MSG_HEAD_SIZE + 1], &my_port, 2);
    sendto(pingfd, (void *) ping_msg, MSG_PING_SIZE, 0,
	   (struct sockaddr *) &ping_addr, sizeof(ping_addr));
    close(pingfd);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_PING", MSG_PING_SIZE);
#endif

    return 0;
}

void
msg_send_monitoring_pong(struct sockaddr_in *peer_addr, uint16_t peer_port,
			 uint16_t my_port, GError **gerror)
{
    int pongfd;
    uint8_t pong_msg[MSG_PONG_SIZE];
    my_port = htons(my_port);

    peer_addr->sin_port = htons(peer_port);
    pongfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    memcpy(&pong_msg[0], MSG_HEAD, MSG_HEAD_SIZE);
    pong_msg[MSG_HEAD_SIZE] = MSG_PONG;
    memcpy(&pong_msg[MSG_HEAD_SIZE + 1], &my_port, 2);
    sendto(pongfd, (void *) pong_msg, MSG_PONG_SIZE, 0,
	   (struct sockaddr *) peer_addr, sizeof(struct sockaddr_in));
    close(pongfd);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_PONG", MSG_PONG_SIZE);
#endif
}

void
msg_send_cv_pong(struct sockaddr_in *peer_addr, uint16_t peer_port,
		 uint16_t my_port, GError **gerror)
{
    int pongfd;
    uint8_t pong_msg[MSG_CV_PONG_SIZE];
    my_port = htons(my_port);

    peer_addr->sin_port = htons(peer_port);
    pongfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    memcpy(&pong_msg, MSG_HEAD, MSG_HEAD_SIZE);
    pong_msg[MSG_HEAD_SIZE] = MSG_CV_PONG;
    memcpy(&pong_msg[MSG_HEAD_SIZE + 1], &my_port, 2);
    sendto(pongfd, (void *) pong_msg, MSG_CV_PONG_SIZE, 0,
	   (struct sockaddr *) peer_addr, sizeof(struct sockaddr_in));
    close(pongfd);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_boc_count("MSG_CV_PONG", MSG_CV_PONG_SIZE);
#endif
}

GPtrArray *
msg_extract_ids(int socketfd, GError **gerror)
{
    uint16_t bytes;
    size_t count;
    char *buff, **split, **p, *ip_c, *port_c;
    GPtrArray *numbers = g_ptr_array_new();
    
    if ( net_read_16bit(socketfd, &bytes, gerror) )
	return NULL;

    if ( !bytes ) 
	return numbers;

    buff = g_malloc0(sizeof(char) * bytes + 1);

    count = bytes;
    if ( net_read(socketfd, buff, &count, gerror) ) {
	g_free(buff);
	return NULL;
    }

    p = split = g_strsplit(buff, MSG_DELIMITER_S, 0);
    g_free(buff);

    do {
	ip_c = *p;
	p++;
	port_c = *p;
	p++;

	if ( !ip_c || !port_c ) {
	    g_strfreev(split);
	    g_set_error(gerror, MSG_ERROR, MSG_ERROR_IDS, "malformed incoming IDS");
	    return NULL;
	}
	
	g_ptr_array_add(numbers, g_strdup(ip_c));
	g_ptr_array_add(numbers, g_strdup(port_c));
    } while ( *p );

    g_strfreev(split);

    return numbers;
}

GPtrArray *
msg_read_cv(int socketfd, GError **gerror)
{
    return msg_extract_ids(socketfd, gerror);
}

typedef struct {
    uint8_t *msg;
    int size;
} MsgIPPortList;

static void
msg_ip_port_list_free(MsgIPPortList *mipl)
{
    g_free(mipl->msg);
    g_free(mipl);
}

static MsgIPPortList *
msg_ip_port_list_reply(uint8_t msg_type, const GPtrArray *peer_array)
{
    char *ip, *port;
    AVMONPeer *peer = NULL;
    int i;
    uint16_t list_bytes;
    GString *string = g_string_new("");
    MsgIPPortList *mipl = g_new(MsgIPPortList, 1);

    if ( peer_array->len ) {
	peer = g_ptr_array_index(peer_array, 0);
	ip = avmon_peer_get_ip(peer);
	port = avmon_peer_get_port(peer);
	string = g_string_new(ip);
	g_string_append_printf(string, "%c%s", MSG_DELIMITER_C, port);
	g_free(ip);
	g_free(port);
    }

    for ( i = 1; i < peer_array->len; i++ ) {
	peer = g_ptr_array_index(peer_array, i);
	ip = avmon_peer_get_ip(peer);
	port = avmon_peer_get_port(peer);
	g_string_append_printf(string, "%c%s%c%s",
			       MSG_DELIMITER_C, ip, MSG_DELIMITER_C, port);
	g_free(ip);
	g_free(port);
    }

    mipl->size = 1 + 2;
    if ( peer_array->len ) {
	list_bytes = string->len;
	list_bytes = htons(list_bytes);
	mipl->size += string->len;
    } else {
	list_bytes = 0;
    }

    mipl->msg = (uint8_t *) g_malloc(mipl->size);
    mipl->msg[0] = msg_type;
    memcpy(&mipl->msg[1], &list_bytes, 2);
    if ( string->len )
	memcpy(&mipl->msg[1 + 2], string->str, string->len);

    g_string_free(string, TRUE);
    
    return mipl;
}

int
msg_write_join_reply(int socketfd, const GPtrArray *cv_array, GError **gerror)
{
    MsgIPPortList *mipl = msg_ip_port_list_reply(MSG_JOIN_REPLY, cv_array);
    int res = net_write(socketfd, mipl->msg, mipl->size, gerror) ? 1 : 0;

#ifdef BACKGROUND_OVERHEAD_COUNTER
    if ( !res )
	msg_boc_count("MSG_JOIN_REPLY", mipl->size);
#endif

    msg_ip_port_list_free(mipl);
    
    return res;
}

int
msg_write_fetch_reply(int socketfd, const GPtrArray *cv_array, GError **gerror)
{
    MsgIPPortList *mipl = msg_ip_port_list_reply(MSG_FETCH_REPLY, cv_array);
    int res = net_write(socketfd, mipl->msg, mipl->size, gerror) ? 1 : 0;

#ifdef BACKGROUND_OVERHEAD_COUNTER
    if ( !res )
	msg_boc_count("MSG_FETCH_REPLY", mipl->size);
#endif
    
    msg_ip_port_list_free(mipl);
    
    return res;
}

uint16_t
msg_port_from_ping_buff(const uint8_t *buff, GError **gerror)
{
    uint16_t port;
    
    memcpy(&port, &buff[MSG_HEAD_SIZE + 1], 2);
    
    return ntohs(port);
}

uint16_t
msg_port_from_pong_buff(const uint8_t *buff, GError **gerror)
{
    return msg_port_from_ping_buff(buff, gerror);
}

GPtrArray *
msg_ids_from_notify_buff(const uint8_t *buff, GError **gerror)
{
    uint16_t bytes;
    char **p, **split, *ip_c, *port_c;
    GPtrArray *numbers = g_ptr_array_new();
    
    memcpy(&bytes, &buff[MSG_HEAD_SIZE + 1], 2);
    bytes = ntohs(bytes);
    
    p = split = g_strsplit(&((const char *)buff)[MSG_HEAD_SIZE + 1 + 2], MSG_DELIMITER_S, 0);

    do {
	ip_c = *p;
	p++;
	port_c = *p;
	p++;

	if ( !ip_c || !port_c ) {
	    g_strfreev(split);
	    g_set_error(gerror, MSG_ERROR, MSG_ERROR_IDS, "malformed incoming IDS");
	    return NULL;
	}
	
	g_ptr_array_add(numbers, g_strdup(ip_c));
	g_ptr_array_add(numbers, g_strdup(port_c));
    } while ( *p );

    g_strfreev(split);

    return numbers;
}

int
msg_read_head(int socketfd, GError **gerror) 
{
    char buff[MSG_HEAD_SIZE + 1];
    unsigned int count = MSG_HEAD_SIZE;
    
    if ( net_read(socketfd, buff, &count, gerror) )
	return 1;
    buff[MSG_HEAD_SIZE] = '\0';

    if ( g_str_equal(buff, MSG_HEAD) )
	return 0;

    g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_HEAD, "%s <> %s", buff, MSG_HEAD);
    
    return 1;
}

int
msg_read_join_reply(int socketfd, GError **gerror)
{
    uint8_t octet;
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_JOIN_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_JOIN_REPLY, 
		    "expecting %u, received %u", MSG_JOIN_REPLY, octet);
	return 1;
    }
    return 0;
}

int
msg_read_fetch_reply(int socketfd, GError **gerror) 
{
    uint8_t octet;
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_FETCH_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_FETCH_REPLY,
		    "expecting %u, received %u", MSG_FETCH_REPLY, octet);
	return 1;
    }
    return 0;
}

int
msg_read_join_payload(int socketfd, uint16_t *peer_port, uint8_t *weight,
		      GError **gerror)
{
    if ( net_read_byte(socketfd, weight, gerror) )
	return 1;
    if ( net_read_16bit(socketfd, peer_port, gerror) )
	return 1;

    return 0;
}

gboolean
msg_is_valid_datagram(const uint8_t *buffer, int bytes)
{
    char head[MSG_HEAD_SIZE + 1];
    head[MSG_HEAD_SIZE] = '\0';

    if ( bytes < (MSG_HEAD_SIZE + 1) )
	return FALSE;
    
    memcpy(head, buffer, MSG_HEAD_SIZE);
    if ( !g_str_equal(head, MSG_HEAD) )
	return FALSE;
    
    if ( (buffer[MSG_HEAD_SIZE] >= MSG_NOT_A_DATAGRAM) 
	 || (buffer[MSG_HEAD_SIZE] == 0) )
	return FALSE;
    
    return TRUE;
}

int
msg_datagram_type(const uint8_t *buffer)
{
    return buffer[MSG_HEAD_SIZE];
}

int
msg_send_get_ps(int socketfd, GError **gerror)
{
    uint8_t msg[MSG_GET_PS_SIZE];

    memcpy(msg, MSG_HEAD, MSG_HEAD_SIZE);
    msg[MSG_HEAD_SIZE] = MSG_GET_PS;

    return net_write(socketfd, msg, MSG_GET_PS_SIZE, gerror);
}

int
msg_write_get_ps_reply(int socketfd, const GPtrArray *ps_array, GError **gerror)
{
    MsgIPPortList *mipl = msg_ip_port_list_reply(MSG_GET_PS_REPLY, ps_array);
    int res = net_write(socketfd, mipl->msg, mipl->size, gerror) ? 1 : 0;
    
    msg_ip_port_list_free(mipl);
    
    return res;
}

int
msg_read_get_ps_reply(int socketfd, GError **gerror)
{
    uint8_t octet;
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_GET_PS_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_GET_PS_REPLY,
		    "expecting %u, received %u", MSG_GET_PS_REPLY, octet);
	return 1;
    }
    return 0;
}

GPtrArray *
msg_read_ps(int socketfd, GError **gerror)
{
    return msg_extract_ids(socketfd, gerror);
}

int
msg_read_get_raw_availability_reply(int socketfd, GError **gerror)
{
    uint8_t octet;
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_GET_RAW_AVAILABILITY_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_GET_RAW_AVAILABILITY_REPLY,
		    "expecting %u, received %u", MSG_GET_RAW_AVAILABILITY_REPLY, octet);
	return 1;
    }
    return 0;
}

#define MSG_BUFFSIZE 2048
#define MSG_GET_RAW_AVAILABILITY_MAX 131072

static void
write_file(int socketfd, const char *filename, uint32_t bytes, GError **gerror)
{
    uint32_t count;
    uint8_t header[4], buff[MSG_BUFFSIZE];
    char *copy_name = g_strconcat(filename, "_msg_tmp", NULL);
    FILE *file = NULL;

    if ( !(bytes = util_fcopy(filename, copy_name, bytes, TRUE, gerror)) )
	goto bye;
    
    bytes = htonl(bytes);
    memcpy(&header[0], &bytes, 4);
    bytes = ntohl(bytes);

    if ( net_write(socketfd, &header, 4, gerror) )
	goto bye;

    if ( !(file = fopen(copy_name, "r")) )
	goto bye;
    for ( ; bytes; bytes -= count ) {
	count = bytes > MSG_BUFFSIZE ? MSG_BUFFSIZE : bytes;
	if ( fread(buff, count, 1, file) != 1 ) {
	    if ( ferror(file) ) {
		g_set_error(gerror, MSG_ERROR, MSG_ERROR_GET_RAW_AVAILABILITY_REPLY,
			    "problem reading %s", copy_name);
		goto bye;
	    }
	}
	if ( net_write(socketfd, buff, count, gerror) )
	    goto bye;
    }
    
bye:
    if ( file )
	fclose(file);
    g_free(copy_name);
}

int
msg_write_get_raw_availability_reply(int socketfd, const char *filename,
				     const char *sessions_filename,
				     GError **gerror)
{
    int res = -1;
    uint8_t msg_head[MSG_GET_RAW_AVAILABILITY_REPLY_HEAD_SIZE];
    uint32_t bytes = MSG_GET_RAW_AVAILABILITY_MAX; //TODO: do not have a max, but a variable number of bytes.

    msg_head[0] = MSG_GET_RAW_AVAILABILITY_REPLY;
    msg_head[1] = filename ? 0X01 : 0X00;

    if ( net_write(socketfd, &msg_head, MSG_GET_RAW_AVAILABILITY_REPLY_HEAD_SIZE,
		   gerror) )
	goto bye;
    
    if ( filename ) {
	write_file(socketfd, filename, bytes, gerror);
	if ( *gerror )
	    goto bye;

	write_file(socketfd, sessions_filename, bytes, gerror);
	if ( *gerror )
	    goto bye;
    }

    res = 0;

bye:
    return res;
}

static void
read_file(int socketfd, FILE *file, int timeout, GError **gerror)
{
    uint32_t bytes, count;
    char buff[MSG_BUFFSIZE];
    fd_set rset;
    struct timeval tv;
    
    if ( net_read_32bit(socketfd, &bytes, gerror) )
	return;

    while ( bytes ) {
	FD_ZERO(&rset);
	FD_SET(socketfd, &rset);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if ( select(socketfd + 1, &rset, NULL, NULL, &tv) == -1 )
	    return;
	    
	count = bytes > MSG_BUFFSIZE ? MSG_BUFFSIZE : bytes;
	bytes -= count;
	buff[count] = '\0';
	if ( net_read(socketfd, buff, &count, gerror) )
	    return;
	    
	fprintf(file, "%s", buff);
    }
}

int
msg_read_get_raw_availability_reply_data(int socketfd, const char *filename,
					 const char *filename_session,
					 int timeout, GError **gerror)
{
    int result = 1;
    fd_set rset;
    FILE *file = NULL, *s_file = NULL;
    uint8_t known = 0;
    struct timeval tv;

    if ( !(file = fopen(filename, "w")) ) {
	util_set_error_errno(gerror, MSG_ERROR, MSG_ERROR_GET_RAW_AVAILABILITY_REPLY,
			     "couldn't open output file");
	goto bye;
    }
    if ( !(s_file = fopen(filename_session, "w")) ) {
	util_set_error_errno(gerror, MSG_ERROR, MSG_ERROR_GET_RAW_AVAILABILITY_REPLY,
			     "couldn't open output file");
	goto bye;
    }

    FD_ZERO(&rset);
    FD_SET(socketfd, &rset);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if ( select(socketfd + 1, &rset, NULL, NULL, &tv) == -1 )
	goto bye;
    if ( !FD_ISSET(socketfd, &rset) )
	goto bye;
    
    if ( net_read_byte(socketfd, &known, gerror) )
	goto bye;
    
    if ( known ) {
	read_file(socketfd, file, timeout, gerror);
	if ( *gerror )
	    goto bye;
	read_file(socketfd, s_file, timeout, gerror);
	if ( *gerror )
	    goto bye;
    } else {
	fprintf(file, "UNKNOWN\n");
    }

    result = 0;
    
bye:
    if ( file )
	fclose(file);
    if ( s_file )
	fclose(s_file);

    return result;
}

int
msg_send_get_raw_availability(int socketfd, const char *target_ip,
			      const char *target_port, GError **gerror)
{
    uint8_t *msg;
    uint16_t target_bytes;
    int size, res;
    GString *string = g_string_new(target_ip);
    g_string_append_printf(string, "%c%s", MSG_DELIMITER_C, target_port);
    
    size = MSG_HEAD_SIZE + 1 + 2 + string->len;
    msg = (uint8_t *) g_malloc(size);

    memcpy(msg, MSG_HEAD, MSG_HEAD_SIZE);
    msg[MSG_HEAD_SIZE] = MSG_GET_RAW_AVAILABILITY;
    target_bytes = string->len;
    target_bytes = htons(target_bytes);
    memcpy(&msg[MSG_HEAD_SIZE + 1], &target_bytes, 2);
    memcpy(&msg[MSG_HEAD_SIZE + 1 + 2], string->str, string->len);
    
    res = net_write(socketfd, msg, size, gerror);
    
    g_string_free(string, TRUE);
    g_free(msg);

    return res;
}

GPtrArray *
msg_read_target(int socketfd, GError **gerror)
{
    return msg_extract_ids(socketfd, gerror);
}

int
msg_read_type(int socketfd, uint8_t *buff, GError **gerror)
{
    int res = net_read_byte(socketfd, buff, gerror);
    if ( *gerror || res )
	return res;

    if ( (*buff >= MSG_NOT_A_PACKET) || (*buff == 0) ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_INVALID_PACKET_TYPE,
		    "invalid packet type %u", *buff);
	return -1;
    }

    return 0;
}

int
msg_send_get_ts(int socketfd, GError **gerror)
{
    uint8_t msg[MSG_GET_TS_SIZE];

    memcpy(msg, MSG_HEAD, MSG_HEAD_SIZE);
    msg[MSG_HEAD_SIZE] = MSG_GET_TS;

    return net_write(socketfd, msg, MSG_GET_TS_SIZE, gerror);
}

int
msg_read_get_ts_reply(int socketfd, GError **gerror)
{
    uint8_t octet;
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_GET_TS_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_GET_TS_REPLY,
		    "expecting %u, received %u", MSG_GET_TS_REPLY, octet);
	return 1;
    }
    return 0;
}

GPtrArray *
msg_read_ts(int socketfd, GError **gerror)
{
    return msg_extract_ids(socketfd, gerror);
}

int
msg_write_get_ts_reply(int socketfd, const GPtrArray *ts_array, GError **gerror)
{
    MsgIPPortList *mipl = msg_ip_port_list_reply(MSG_GET_TS_REPLY, ts_array);
    int res = net_write(socketfd, mipl->msg, mipl->size, gerror) ? 1 : 0;
    
    msg_ip_port_list_free(mipl);
    
    return res;
}

int
msg_send_get_last_heard_of_ts(int socketfd, GError **gerror)
{
    uint8_t msg[MSG_GET_LAST_HEARD_OF_TS_SIZE];
    
    memcpy(msg, MSG_HEAD, MSG_HEAD_SIZE);
    msg[MSG_HEAD_SIZE] = MSG_GET_LAST_HEARD_OF_TS;
    
    return net_write(socketfd, msg, MSG_GET_LAST_HEARD_OF_TS_SIZE, gerror);
}

int
msg_read_get_last_heard_of_ts_reply(int socketfd, GError **gerror)
{
    uint8_t octet;
    
    if ( net_read_byte(socketfd, &octet, gerror) )
	return 1;
    if ( octet != MSG_GET_LAST_HEARD_OF_TS_REPLY ) {
	g_set_error(gerror, MSG_ERROR, MSG_ERROR_NOT_GET_LAST_HEARD_OF_TS_REPLY,
		    "expecting %u, received %u", MSG_GET_LAST_HEARD_OF_TS_REPLY, octet);
	return 1;
    }

    return 0;
}

GPtrArray *
msg_extract_ids_data(int socketfd, GError **gerror)
{
    uint16_t bytes;
    size_t count;
    char *buff, **split, **p, *ip_c, *port_c, *data_c;
    GPtrArray *ids_data = g_ptr_array_new();
    
    if ( net_read_16bit(socketfd, &bytes, gerror) )
	return NULL;

    if ( !bytes )
	return ids_data;
    
    buff = g_malloc0(sizeof(char) * bytes + 1);
    
    count = bytes;
    if ( net_read(socketfd, buff, &count, gerror) ) {
	g_free(buff);
	return NULL;
    }

    p = split = g_strsplit(buff, MSG_DELIMITER_S, 0);
    g_free(buff);

    do {
	ip_c = *p;
	p++;
	port_c = *p;
	p++;
	data_c = *p;
	p++;
	
	if ( !ip_c || !port_c || !data_c ) {
	    g_strfreev(split);
	    g_set_error(gerror, MSG_ERROR, MSG_ERROR_IDS_DATA, "malformed incoming IDS+data");
	    return NULL;
	}

	g_ptr_array_add(ids_data, g_strdup(ip_c));
	g_ptr_array_add(ids_data, g_strdup(port_c));
	g_ptr_array_add(ids_data, g_strdup(data_c));
    } while ( *p );
    
    g_strfreev(split);

    return ids_data;
}

GPtrArray *
msg_read_last_heard_of_ts(int socketfd, GError **gerror)
{
    return msg_extract_ids_data(socketfd, gerror);
}

typedef struct {
    uint8_t *msg;
    int size;
} MsgIPPortDataList;

static void
msg_ip_port_data_list_free(MsgIPPortDataList *mipdl)
{
    g_free(mipdl->msg);
    g_free(mipdl);
}

static MsgIPPortList *
msg_ip_port_data_list_reply(uint8_t msg_type, const GPtrArray *peer_array, const GPtrArray *data_array)
{
    char *ip, *port, *data;
    AVMONPeer *peer = NULL;
    int i;
    uint16_t list_bytes;
    GString *string = g_string_new("");
    MsgIPPortDataList *mipdl = g_new(MsgIPPortDataList, 1);
    
    if ( peer_array->len ) {
        peer = g_ptr_array_index(peer_array, 0);
	data = g_ptr_array_index(data_array, 0);
        ip = avmon_peer_get_ip(peer);
        port = avmon_peer_get_port(peer);
        string = g_string_new(ip);
        g_string_append_printf(string, "%c%s%c%s", MSG_DELIMITER_C, port, MSG_DELIMITER_C, data);
        g_free(ip);
        g_free(port);
    }
    
    for ( i = 1; i < peer_array->len; i++ ) {
        peer = g_ptr_array_index(peer_array, i);
	data = g_ptr_array_index(data_array, i);
        ip = avmon_peer_get_ip(peer);
        port = avmon_peer_get_port(peer);
        g_string_append_printf(string, "%c%s%c%s%c%s",
                               MSG_DELIMITER_C, ip, MSG_DELIMITER_C, port,
			       MSG_DELIMITER_C, data);
        g_free(ip);
        g_free(port);
    }

    mipdl->size = 1 + 2;
    if ( peer_array->len ) {
        list_bytes = string->len;
        list_bytes = htons(list_bytes);
        mipdl->size += string->len;
    } else {
        list_bytes = 0;
    }

    mipdl->msg = (uint8_t *) g_malloc(mipdl->size);
    mipdl->msg[0] = msg_type;
    memcpy(&mipdl->msg[1], &list_bytes, 2);
    if ( string->len )
        memcpy(&mipdl->msg[1 + 2], string->str, string->len);

    g_string_free(string, TRUE);

    return mipdl;
}

int
msg_write_get_last_heard_of_ts_reply(int socketfd, const GPtrArray *ts_array, 
				     const GPtrArray *data_array, GError **gerror)
{
    MsgIPPortDataList *mipdl =
	msg_ip_port_data_list_reply(MSG_GET_LAST_HEARD_OF_TS_REPLY, ts_array, data_array);
    int res = net_write(socketfd, mipdl->msg, mipdl->size, gerror) ? 1 : 0;
    
    msg_ip_port_data_list_free(mipdl);
    
    return res;
}
