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
 * \file avmon.c
 * \author Ramses Morales
 * \version $Id: avmon.c,v 1.8 2008/05/30 01:21:59 ramses Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>

#include <openssl/evp.h>

#include "avmon.h"
#include "conf.h"
#include "util.h"
#include "messages.h"
#include "net.h"
#include "listener.h"

GQuark
avmon_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
	quark = g_quark_from_static_string("avmon-error-quark");
    
    return quark;
}

static const EVP_MD *md;
static EVP_MD_CTX mdctx;
static unsigned char md_value[EVP_MAX_MD_SIZE]; //here for speed :-p
static guint64 *md_int;
static const long double max_64bit = 18446744073709551615.0;
static gboolean evp_set = FALSE;
static pthread_mutex_t mutex_evp = PTHREAD_MUTEX_INITIALIZER;

enum JoinStatus {
    JOIN_STATUS_JOINING = 0,
    JOIN_STATUS_IN,
    JOIN_STATUS_ALONE,
    JOIN_STATUS_OUT
};

struct _AVMONPeer {
    char ip[NET_IP_CHAR_SIZE + 1];
    char *port;
    char *key;
    gboolean answered_ping;
    FILE *default_output;
    char *default_output_name;
    gboolean peer_cv; //flag to avoid leaks during shuffle
};

struct _AVMONNode {
    int K, N;
    long double condition;
    GHashTable *cv;
    int CVS;
    AVMONPeer *pinged_peer;

    GHashTable *ps;
    GHashTable *ts;

    AVMONFunc avmon_func;
    AVMONReplyFunc avmon_reply_func;
    AVMONAvOutputFunc avmon_av_output_func;
    char *default_av_output_prefix;

    enum JoinStatus join_status;

    Conf *conf;
    pthread_t tid;
    pthread_t m_tid;

    AVMONListener *listener;

    int main_pipe[2];
    int monitoring_pipe[2];

    pthread_mutex_t mutex_pinged_peer;
    pthread_mutex_t mutex_cv;
    pthread_mutex_t mutex_ps;
    pthread_mutex_t mutex_ts;

    time_t latest_iteration;

    GRand *grand;

    const char *ip_c;
    const char *port_c;
    const char *key;
    int port;
    
    GPtrArray *peer_trash;
    time_t peer_trash_last_collection;
};

static inline int
cv_size(AVMONNode *node)
{
    return g_hash_table_size(node->cv);
}

static inline char *
cv_key(const char *ip, const char *port)
{
    return g_strconcat(ip, "|", port, NULL);
}

static inline void
cv_init(AVMONNode *node)
{
    node->cv = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
}

static void
cv_add(AVMONNode *node, AVMONPeer *peer)
{
    pthread_mutex_lock(&node->mutex_cv);
    g_hash_table_insert(node->cv, peer->key, peer);
    pthread_mutex_unlock(&node->mutex_cv);
}

static gboolean
_cv_random_peer(gpointer _key, gpointer _peer, gpointer _i)
{
    int *i = (int *) _i;
    if ( *i ) {
	(*i)--;
	return FALSE;
    }
    return TRUE;
}

static AVMONPeer *
cv_random_peer(AVMONNode *node)
{
    int i;
    AVMONPeer *peer = NULL;

    pthread_mutex_lock(&node->mutex_cv);
    if ( g_hash_table_size(node->cv) ) {
	i = g_rand_int_range(node->grand, 0, g_hash_table_size(node->cv));
	peer = g_hash_table_find(node->cv, _cv_random_peer, &i);
    }
    pthread_mutex_unlock(&node->mutex_cv);

    return peer;
}

static AVMONPeer *
cv_lookup(AVMONNode *node, const char *ip, const char *port)
{
    char *key = cv_key(ip, port);
    AVMONPeer *peer;

    pthread_mutex_lock(&node->mutex_cv);
    peer = g_hash_table_lookup(node->cv, key);
    pthread_mutex_unlock(&node->mutex_cv);
    
    g_free(key);
    return peer;
}

static void
cv_delete(AVMONNode *node, AVMONPeer *peer)
{
    pthread_mutex_lock(&node->mutex_cv);
    g_hash_table_remove(node->cv, peer->key);
    pthread_mutex_unlock(&node->mutex_cv);
}

static GPtrArray *
cv_to_array(AVMONNode *node)
{
    GPtrArray *array = NULL;
    
    pthread_mutex_lock(&node->mutex_cv);
    array = util_g_hash_table_to_array(node->cv);
    pthread_mutex_unlock(&node->mutex_cv);

    return array;
}

static AVMONPeer *
peer_new(const char *ip, const char *port)
{
    //TODO: verify that ips received from messages are indeed ips
    g_assert( strlen(ip) <= NET_IP_CHAR_SIZE );

    AVMONPeer *p = g_new(AVMONPeer, 1);
    strncpy(p->ip, ip, strlen(ip));
    p->ip[strlen(ip)] = '\0';
    p->port = g_strdup(port);
    p->key = cv_key(ip, port);
    p->answered_ping = FALSE;
    p->default_output = NULL;
    p->default_output_name = NULL;
    p->peer_cv = FALSE;
    return p;
}

static void
peer_free(AVMONPeer *p)
{
    g_assert( p != NULL );
    
    g_free(p->port);
    g_free(p->key);
    if ( p->default_output )
	fclose(p->default_output);
    if ( p->default_output_name )
	g_free(p->default_output_name);
    
    g_free(p);
}

static void
avmon_node_peer_trash_dump(AVMONNode *node)
{
    while ( node->peer_trash->len )
	peer_free(g_ptr_array_remove_index(node->peer_trash, 
					   node->peer_trash->len - 1));
    node->peer_trash_last_collection = time(NULL);
}

//TODO: get rid of this trash thingy and use reference counters
static void
avmon_peer_trash_add(AVMONNode *node, AVMONPeer *peer)
{
    g_ptr_array_add(node->peer_trash, peer);
    if ( (node->peer_trash->len >= 100) 
	 && ((time(NULL) - node->peer_trash_last_collection) > 300) )
	avmon_node_peer_trash_dump(node);
}

char *
avmon_peer_get_ip(const AVMONPeer *peer)
{
    return g_strdup(peer->ip);
}

char *
avmon_peer_get_port(const AVMONPeer *peer)
{
    return g_strdup(peer->port);
}

static gboolean
ps_add(AVMONNode *node, AVMONPeer *peer)
{
    gboolean result = FALSE;
    
    pthread_mutex_lock(&node->mutex_ps);
    if ( g_hash_table_lookup(node->ps, peer->key) )
	result = FALSE;
    else {
	result = TRUE;
	g_hash_table_insert(node->ps, peer->key, peer);
    }
    pthread_mutex_unlock(&node->mutex_ps);

    return result;
}

static GPtrArray *
ps_to_array(AVMONNode *node)
{
    GPtrArray *array = NULL;
    
    pthread_mutex_lock(&node->mutex_ps);
    array = util_g_hash_table_to_array(node->ps);
    pthread_mutex_unlock(&node->mutex_ps);

    return array;
}

static void
_ps_destroy(gpointer _peer)
{
    peer_free((AVMONPeer *) _peer);
}

static gboolean
ts_add(AVMONNode *node, AVMONPeer *peer)
{
    gboolean result = FALSE;
    
    pthread_mutex_lock(&node->mutex_ts);
    if ( g_hash_table_lookup(node->ts, peer->key) )
	result = FALSE;
    else {
	result = TRUE;
	g_hash_table_insert(node->ts, peer->key, peer);
    }
    pthread_mutex_unlock(&node->mutex_ts);

    return result;
}

static AVMONPeer *
ts_lookup(AVMONNode *node, const char *ip, const char *port)
{
    char *key = cv_key(ip, port);
    AVMONPeer *peer;
    
    pthread_mutex_lock(&node->mutex_ts);
    peer = g_hash_table_lookup(node->ts, key);
    pthread_mutex_unlock(&node->mutex_ts);

    g_free(key);
    return peer;
}

static inline int
ts_size(AVMONNode *node)
{
    return g_hash_table_size(node->ts);
}

static void
_ts_destroy(gpointer _peer)
{
    peer_free((AVMONPeer *) _peer);
}

static void
avmon_default_monitor(AVMONNode *node, const char *ip, const char *port)
{
    GError *gerror = NULL;

    if ( msg_send_monitoring_ping(ip, port, node->port, &gerror) ) {
	g_critical("%s\n", gerror->message);
	g_error_free(gerror);
    }
}

static void
avmon_default_av_output_function(AVMONNode *node, AVMONPeer *peer)
{
    if ( peer->default_output == NULL ) {
	peer->default_output_name = 
	    g_strconcat(node->default_av_output_prefix, peer->ip, "_",
			peer->port, ".txt", NULL);
	peer->default_output = fopen(peer->default_output_name, "a+");
    }

    if ( peer->default_output ) {
	fprintf(peer->default_output, "%u %s %s\n", (unsigned int) time(NULL), 
		peer->ip, peer->port);
    }
}

static void
avmon_default_monitor_reply(AVMONNode *node, AVMONPeer *peer)
{
    node->avmon_av_output_func(node, peer);
}

static void
_ts_foreach(gpointer _key, gpointer _peer, gpointer _node)
{
    AVMONPeer *peer = (AVMONPeer *) _peer;
    AVMONNode *node = (AVMONNode *) _node;
    
    node->avmon_func((AVMONNode *) _node, peer->ip, peer->port);
}

static void
ts_foreach(AVMONNode *node)
{
    pthread_mutex_lock(&node->mutex_ts);
    g_hash_table_foreach(node->ts, _ts_foreach, node);
    pthread_mutex_unlock(&node->mutex_ts);
}

static void
avmon_node_free(AVMONNode *node)
{
    avmon_node_peer_trash_dump(node);
    g_ptr_array_free(node->peer_trash, TRUE);
    
    if ( node->main_pipe[0] != -1 ) {
	close(node->main_pipe[0]);
	close(node->main_pipe[1]);
    }
    if ( node->monitoring_pipe[0] != -1 ) {
	close(node->monitoring_pipe[0]);
	close(node->monitoring_pipe[1]);
    }

    g_free(node->ip_c);
    g_free(node->port_c);
    g_free(node->key);
    g_free(node->default_av_output_prefix);
    g_rand_free(node->grand);

    g_hash_table_destroy(node->cv);

    conf_free(node->conf);

    g_hash_table_destroy(node->ps);
    g_hash_table_destroy(node->ts);

    g_free(node);
}

static AVMONNode *
avmon_node_new(int K, int N, Conf *conf, GError **gerror)
{
    AVMONNode *node = g_new0(AVMONNode, 1);
    int flags;

    node->conf = conf;

    node->join_status = JOIN_STATUS_OUT;
    node->K = K;
    node->N = N;
    node->condition = (long double) K / (long double) N;

    //TODO: make configurable
    node->avmon_func = avmon_default_monitor;
    node->avmon_reply_func = avmon_default_monitor_reply;
    node->avmon_av_output_func = avmon_default_av_output_function;
    node->default_av_output_prefix = conf_get_default_av_output_prefix(conf);

    node->ps = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _ps_destroy);
    node->ts = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _ts_destroy);

    node->CVS = 4 * ((int) pow((double) N, 0.25));

    pthread_mutex_init(&node->mutex_pinged_peer, NULL);
    pthread_mutex_init(&node->mutex_cv, NULL);
    pthread_mutex_init(&node->mutex_ps, NULL);
    pthread_mutex_init(&node->mutex_ts, NULL);

    node->grand = g_rand_new();

    node->ip_c = conf_get_host_ip(conf);
    if ( !node->ip_c ) {
	node->ip_c = g_strdup(net_my_ip(gerror));
	if ( *gerror )
	    g_error("%s\nPlease use host_ip option in configuration file",
		    (*gerror)->message); //aborts
    }
    node->port_c = g_strdup_printf("%d", conf_get_listener_tcp_udp_port(conf));
    node->port = conf_get_listener_tcp_udp_port(conf);
    if ( node->port > 65535 )
	g_error("bad port number %d", node->port); //aborts
    node->key = cv_key(node->ip_c, node->port_c);

    //non-blocking pipes
    node->main_pipe[0] = node->main_pipe[1] = node->monitoring_pipe[0] = 
	node->monitoring_pipe[1] = -1;

    if ( pipe(node->main_pipe) ) {
	util_set_error_errno(gerror, AVMON_ERROR,
			     AVMON_ERROR_NODE, "creating pipe");
	goto exit_with_error;
    }
    if ( (flags = fcntl(node->main_pipe[0], F_GETFL)) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
			     "creating pipe");
        goto exit_with_error;
    }
    if ( fcntl(node->main_pipe[0], F_SETFL, flags | O_NONBLOCK) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
			     "creating pipe");
        goto exit_with_error;
    }

    if ( pipe(node->monitoring_pipe) ) {
	util_set_error_errno(gerror, AVMON_ERROR,
			     AVMON_ERROR_NODE, "creating pipe");
	goto exit_with_error;
    }
    if ( (flags = fcntl(node->monitoring_pipe[0], F_GETFL)) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
			     "creating pipe");
        goto exit_with_error;
    }
    if ( fcntl(node->monitoring_pipe[0], F_SETFL, flags | O_NONBLOCK) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
			     "creating pipe");
        goto exit_with_error;
    }

    node->peer_trash = g_ptr_array_new();
    node->peer_trash_last_collection = time(NULL);

    return node;

exit_with_error:
    avmon_node_free(node);
    
    return NULL;
}

typedef void (*PIPAFunc) (const char *ip, const char *port, void *data);

static void
process_ip_port_array(GPtrArray *array, gboolean destroy, PIPAFunc pipa_func,
		      void *data)
{
    int i;
    char *ip, *port;
    
    for ( i = 0; i < array->len; i += 2 ) {
	ip = g_ptr_array_index(array, i);
	port = g_ptr_array_index(array, i + 1);
	
	pipa_func(ip, port, data);

	if ( destroy ) {
	    g_free(ip);
	    g_free(port);
	}
    }

    if ( destroy )
	g_ptr_array_free(array, TRUE);
}

//static GHashTable *tmp_cvx_cvw = NULL;

static void
hash(const char *i, const char *j)
{
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, i, strlen(i));
    EVP_DigestUpdate(&mdctx, j, strlen(j));
    EVP_DigestFinal_ex(&mdctx, md_value, NULL);

    md_int = (guint64 *) md_value;
}

static gboolean
avmon_condition(AVMONNode *node, const char *key_i, const char *key_j)
{
    long double normalized;
    
    hash(key_i, key_j);
    normalized = (long double) *md_int / max_64bit;
    if ( normalized <= node->condition )
	return TRUE;
    return FALSE;
}

typedef struct {
    GHashTable *tmp_cvx_cvw;
    GHashTable *cv;
    AVMONPeer *i;
    AVMONNode *node;
    gboolean check;
    GPtrArray *incoming_duplicate;
} CCData;

static void
check_condition_j(gpointer key, gpointer value, gpointer data)
{
    CCData *ccd = (CCData *) data;
    AVMONPeer *j = (AVMONPeer *) value;
    
    if ( g_str_equal(ccd->i->key, j->key) )
	return;

    if ( avmon_condition(ccd->node, ccd->i->key, j->key) )
	msg_send_notify(ccd->i->ip, ccd->i->port, j->ip, j->port);
}

static void
check_condition_i(gpointer key, gpointer value, gpointer data)
{
    AVMONPeer *peer = (AVMONPeer *) value;
    CCData *ccd = (CCData *) data;

    if ( ccd->check ) {
	if ( !g_hash_table_lookup(ccd->tmp_cvx_cvw, peer->key) )
	    g_hash_table_insert(ccd->tmp_cvx_cvw, peer->key, peer);
	else
	    g_ptr_array_add(ccd->incoming_duplicate, peer);
    } else {
	if ( peer->peer_cv )
	    g_hash_table_insert(ccd->tmp_cvx_cvw, peer->key, peer);
    }
    ccd->i = value;
    g_hash_table_foreach(ccd->cv, check_condition_j, ccd);
}

static void
_avmon_compute_and_shuffle(const char *ip, const char *port, void *_peer_cv)
{
    AVMONPeer *peer = peer_new(ip, port);
    peer->peer_cv = TRUE;
    g_hash_table_insert((GHashTable *) _peer_cv, peer->key, peer);
}

static void
avmon_compute_and_shuffle(AVMONNode *node, GPtrArray *incoming_cv,
			  AVMONPeer *peer)
{
    AVMONPeer *self = peer_new(node->ip_c, node->port_c);
    AVMONPeer *tmp_peer = NULL;
    int i, ii, i_rand;
    GHashTable *peer_cv = 
	g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    GHashTable *tmp_cvx_cvw = NULL;
    GPtrArray *tmp_blah = NULL, *incoming_duplicate = NULL;
    CCData ccd;

    process_ip_port_array(incoming_cv, TRUE, _avmon_compute_and_shuffle,
			  peer_cv);

    pthread_mutex_lock(&node->mutex_cv);
    pthread_mutex_lock(&mutex_evp);

    g_hash_table_insert(node->cv, self->key, self);
    if ( !g_hash_table_lookup(peer_cv, self->key) )
	g_hash_table_insert(peer_cv, self->key, self);
    if ( !g_hash_table_lookup(peer_cv, peer->key) )
	g_hash_table_insert(peer_cv, peer->key, peer);
    tmp_cvx_cvw = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    ccd.node = node;
    ccd.tmp_cvx_cvw = tmp_cvx_cvw;
    ccd.cv = peer_cv;
    ccd.check = FALSE;
    g_hash_table_foreach(node->cv, check_condition_i, &ccd);
    ccd.cv = node->cv;
    ccd.check = TRUE;
    incoming_duplicate = g_ptr_array_new();
    ccd.incoming_duplicate = incoming_duplicate;
    g_hash_table_foreach(peer_cv, check_condition_i, &ccd);

    pthread_mutex_unlock(&mutex_evp);

    g_hash_table_remove(tmp_cvx_cvw, self->key);
    peer_free(self);
    tmp_blah = util_g_hash_table_to_array(tmp_cvx_cvw);
    g_hash_table_destroy(tmp_cvx_cvw);

    for ( i = incoming_duplicate->len - 1; i >= 0; i-- ) {
	tmp_peer = g_ptr_array_remove_index_fast(incoming_duplicate, i);
	peer_free(tmp_peer);
    }
    g_ptr_array_free(incoming_duplicate, TRUE);
    g_hash_table_destroy(peer_cv);

    g_hash_table_destroy(node->cv);
    cv_init(node);

    ii = node->CVS < tmp_blah->len ? node->CVS : tmp_blah->len;
    for ( i = 0; i < ii; i++ ) {
	i_rand = g_rand_int_range(node->grand, 0, tmp_blah->len);
	tmp_peer = g_ptr_array_index(tmp_blah, i_rand);
	g_hash_table_insert(node->cv, tmp_peer->key, tmp_peer);
	g_ptr_array_remove_index_fast(tmp_blah, i_rand);

	tmp_peer->peer_cv = FALSE;
    }
    for ( i = tmp_blah->len - 1; i >= 0 ; i-- ) {
	tmp_peer = g_ptr_array_remove_index(tmp_blah, i);
	if ( tmp_peer->peer_cv )
	    peer_free(tmp_peer);
	else
	    avmon_peer_trash_add(node, tmp_peer);
    }
    g_ptr_array_free(tmp_blah, TRUE);

    pthread_mutex_unlock(&node->mutex_cv);
}

void
avmon_receive_monitoring_pong(AVMONNode *node, const char *ip, const uint8_t *buff)
{
    AVMONPeer *peer = NULL;
    GError *gerror = NULL;
    uint16_t peer_port = msg_port_from_pong_buff(buff, &gerror);
    char *peer_port_c;
    if ( gerror ) {
	//TODO: log
	g_error_free(gerror);
	return;
    }

    peer_port_c = g_strdup_printf("%d", peer_port);
    peer = ts_lookup(node, ip, peer_port_c);
    g_free(peer_port_c);
    if ( !peer ) {
	//TODO: log something
	return;
    }

    node->avmon_reply_func(node, peer);
}

void
avmon_receive_cv_pong(AVMONNode *node, const char *ip, const uint8_t *buff)
{
    AVMONPeer *peer = NULL;
    GError *gerror = NULL;
    uint16_t peer_port = msg_port_from_pong_buff(buff, &gerror);
    char *peer_port_c;
    if ( gerror ) {
	//TODO: log
	g_error_free(gerror);
	return;
    }

    peer_port_c = g_strdup_printf("%d", peer_port);
    peer = cv_lookup(node, ip, peer_port_c);
    g_free(peer_port_c);
    if ( !peer ) {
	//TODO: log something
	return;
    }

    if ( g_str_equal(peer->key, node->pinged_peer->key) ) {
	peer->answered_ping = TRUE;
    } else {
	//TODO: log something
    }
}

void
avmon_receive_monitoring_ping(AVMONNode *node, const uint8_t *buff,
			      struct sockaddr_in *peer_addr)
{
    GError *gerror = NULL;
    uint16_t peer_port = msg_port_from_ping_buff(buff, &gerror);

    //TODO? verify that this is a valid ping?
    
    //TODO: add to PS if valid and not there

    if ( gerror ) {
	g_warning("Couldn't get port from a monitoring ping: %s", gerror->message);
	g_error_free(gerror);
	return;
    }

    msg_send_monitoring_pong(peer_addr, peer_port, node->port, &gerror);
    //TODO: log error
}

void
avmon_receive_cv_ping(AVMONNode *node, const uint8_t *buff,
		      struct sockaddr_in *peer_addr)
{
    GError *gerror = NULL;
    uint16_t peer_port = msg_port_from_ping_buff(buff, &gerror);

    //TODO: count to compare with expected indegree

    if ( gerror ) {
	g_warning("Couldn't get port from a cv-ping: %s", gerror->message);
	g_error_free(gerror);
	return;
    }

    msg_send_cv_pong(peer_addr, peer_port, node->port, &gerror);
    //TODO: log error
}

void
avmon_receive_notify(AVMONNode *node, const uint8_t *buff)
{
    GError *gerror = NULL;
    GPtrArray *ids = msg_ids_from_notify_buff(buff, &gerror);
    char *ip_c, *port_c;
    AVMONPeer *peer_u, *peer_v;

    if ( gerror ) {
	//TODO: log this
	g_error_free(gerror);
	return;
    }

    ip_c = g_ptr_array_index(ids, 0);
    port_c = g_ptr_array_index(ids, 1);
    peer_u = peer_new(ip_c, port_c);
    g_free(ip_c);
    g_free(port_c);

    ip_c = g_ptr_array_index(ids, 2);
    port_c = g_ptr_array_index(ids, 3);
    peer_v = peer_new(ip_c, port_c);
    g_free(ip_c);
    g_free(port_c);

    g_ptr_array_free(ids, TRUE);

    pthread_mutex_lock(&mutex_evp);
    if ( !avmon_condition(node, peer_u->key, peer_v->key) ) {
	pthread_mutex_unlock(&mutex_evp);
	peer_free(peer_v);
	peer_free(peer_u);
	return;
    }
    pthread_mutex_unlock(&mutex_evp);
    
    if ( g_str_equal(peer_v->key, node->key) ) {
	if ( !ps_add(node, peer_u) )
	    peer_free(peer_u);
	peer_free(peer_v);
    } else {
	if ( !ts_add(node, peer_v) )
	    peer_free(peer_v);
	peer_free(peer_u);
    }
}

static void
do_forward(AVMONNode *node, uint8_t weight, uint16_t joiner_port,
	   const char *joiner_ip)
{
    uint8_t w_f, w_c;
    AVMONPeer *forward_peer;

    weight--;
    if ( weight < 1 )
	return;
    
    w_f = (uint8_t) floor((double) weight / (double) 2.0);
    w_c = (uint8_t) ceil((double) weight / (double) 2.0);
	
    forward_peer = cv_random_peer(node);
    if ( !forward_peer )
	return; //TODO: inform that this node could not forward

    msg_send_forward(forward_peer->ip, forward_peer->port, joiner_port,
		     joiner_ip, w_c);

    if ( w_f ) {
	forward_peer = cv_random_peer(node);
	msg_send_forward(forward_peer->ip, forward_peer->port, joiner_port,
			 joiner_ip, w_f);
    }
}

static gboolean
do_add_joiner(AVMONNode *node, const char *joiner_ip, uint16_t joiner_port)
{
    char *joiner_port_c = g_strdup_printf("%u", joiner_port);

    // blah
    if ( !cv_lookup(node, joiner_ip, joiner_port_c) )
	cv_add(node, peer_new(joiner_ip, joiner_port_c));
    g_free(joiner_port_c);
    
    if ( node->join_status == JOIN_STATUS_ALONE ) {
	node->join_status = JOIN_STATUS_IN;

	return TRUE;
    }
    return FALSE;
}

void
avmon_receive_join(AVMONNode *node, int socketfd, const char *peer_ip)
{
    GPtrArray *peer_array = NULL;
    uint16_t peer_port;
    uint8_t weight;
    GError *gerror = NULL;

    if ( msg_read_join_payload(socketfd, &peer_port, &weight, &gerror) ) {
	if ( gerror ) 
	    g_error_free(gerror);
	return;
    }

    if ( !do_add_joiner(node, peer_ip, peer_port) )
	do_forward(node, weight, peer_port, peer_ip);

    peer_array = cv_to_array(node);
    msg_write_join_reply(socketfd, peer_array, &gerror);
    g_ptr_array_free(peer_array, TRUE);
}

void
avmon_receive_cv_fetch(AVMONNode *node, int socketfd)
{
    /* TODO: the fetch message should include avmon's port number
     * so that it can be used to populate the CV
     */
    GError *gerror = NULL;
    GPtrArray *array = cv_to_array(node);

    msg_write_fetch_reply(socketfd, array, &gerror);
    if ( gerror ) {
	g_debug("avmon_receive_cv_fetch: %s", gerror->message);
	g_error_free(gerror);
    }
    g_ptr_array_free(array, TRUE);
}

void
avmon_receive_forward(AVMONNode *node, const uint8_t *buff)
{
    GError *gerror = NULL;
    MsgForwardData *data = msg_data_from_forward_buff(buff, &gerror);
    if ( !data ) {
	if ( gerror ) {
	    g_debug("avmon_receive_forward: %s", gerror->message);
	    g_error_free(gerror);
	}
	return;
    }

    if ( !do_add_joiner(node, data->ip, data->port))
	do_forward(node, data->weight, data->port, data->ip);

    msg_forward_data_free(data);
}

static void *
monitoring_loop(void *_node)
{
    AVMONNode *node = (AVMONNode *) _node;
    fd_set rset;
    struct timeval tv;
    const int period = conf_get_monitoring_period(node->conf);

    for ( ; ; ) {
	FD_ZERO(&rset);
	FD_SET(node->monitoring_pipe[0], &rset);
	tv.tv_sec = period;
	tv.tv_usec = 0;
	
	if ( select(node->monitoring_pipe[0] + 1, &rset, NULL, NULL, &tv) 
	     == -1 ) {
	    //TODO: use g_log
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    fprintf(stderr, "monitoring_loop: %s\n", buff);
	    exit(1); //TODO: just stop avmon, and use a callback to inform main
	}
	if ( FD_ISSET(node->monitoring_pipe[0], &rset) ) {
	    //TODO: no need to read it, only one message possible: shut down
	    break;
	}

	if ( node->join_status == JOIN_STATUS_ALONE )
	    continue;
	
	//TODO: count monitoring pings received to determine if rejoin needed

	//TODO: add suport for any user provided monitor
	ts_foreach(node);
    }

#ifdef DEBUG
    g_debug("monitoring_loop out");
#endif

    pthread_exit(NULL);
}

static void *
main_loop(void *_node)
{
    AVMONNode *node = (AVMONNode *) _node;
    fd_set rset;
    struct timeval tv;
    const int period = conf_get_protocol_period(node->conf);
    int sockfd, elapsed;
    AVMONPeer *random_peer = NULL;
    struct addrinfo *peer_info = NULL;
    GError *gerror = NULL;
    GPtrArray *incoming_cv = NULL;

    for ( tv.tv_sec = period; ; ) {
	FD_ZERO(&rset);
	FD_SET(node->main_pipe[0], &rset);
	if ( node->latest_iteration ) {
	    elapsed = time(NULL) - node->latest_iteration;

	    tv.tv_sec = elapsed ? (elapsed < period ? period - elapsed : 0)
		: period;
	}
	tv.tv_usec = 0;
	if ( select(node->main_pipe[0] + 1, &rset, NULL, NULL, &tv) == -1 ) {
	    //TODO: use g_log
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    fprintf(stderr, "main_loop: %s\n", buff);
	    exit(1); //TODO: just stop avmon, and use a callback to inform main
	}

	if ( FD_ISSET(node->main_pipe[0], &rset) ) {
	    //TODO: no need to read it, only one "message" possible: shut down
	    break;
	}

	node->latest_iteration = time(NULL);

	if ( node->join_status == JOIN_STATUS_ALONE )
	    continue;
	
	//cv_ping
	node->pinged_peer = cv_random_peer(node);
	if ( node->pinged_peer ) {
	    node->pinged_peer->answered_ping = FALSE;
	    msg_send_cv_ping(node->pinged_peer->ip, node->pinged_peer->port,
			     node->port);
	    sleep(5); //TODO: make configurable
	
	    if ( !node->pinged_peer->answered_ping ) {
		cv_delete(node, node->pinged_peer);
		peer_free(node->pinged_peer); //TODO
	    }

	    node->pinged_peer = NULL;
	}

	//contact random
	random_peer = cv_random_peer(node);
	if ( !random_peer )
	    continue;
	if ( peer_info )
	    freeaddrinfo(peer_info);
	if ( !(peer_info = net_char_to_addrinfo(random_peer->ip,
						random_peer->port, &gerror))) {
	    //TODO: use g_log
	    fprintf(stderr, "main_loop: %s\n", gerror->message);
	    g_error_free(gerror);
	    gerror = NULL;
	    continue;
	}
	if ( (sockfd = socket(peer_info->ai_family, peer_info->ai_socktype, 
			   peer_info->ai_protocol)) == -1 ) {
	    //TODO: use g_log
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    fprintf(stderr, "main_loop: %s\n", buff);
	    continue;
	}
	if ( net_connect_nb(sockfd, peer_info->ai_addr, peer_info->ai_addrlen,
			    5 /* TODO */, 0, &gerror) ) {
	    //TODO: use g_log
	    close(sockfd);
	    fprintf(stderr, "main_loop: %s\n", gerror->message);
	    g_error_free(gerror);
	    gerror = NULL;
	    continue;
	}
	freeaddrinfo(peer_info);
	peer_info = NULL;
	
	if ( msg_send_cv_fetch(sockfd, &gerror) ) {
	    fprintf(stderr, "main_loop: %s\n", gerror->message);
	    g_error_free(gerror);
	    gerror = NULL;
	    close(sockfd);
	    continue;
	}
	
	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	tv.tv_sec = 5; //TODO
	tv.tv_usec = 0;
	if ( select(sockfd + 1, &rset, NULL, NULL, &tv) == -1 ) { //TODO: listen to pipe
	    //TODO: use g_log
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    fprintf(stderr, "main_loop: %s\n", buff);
	    close(sockfd);
	    continue;
	}
	if ( !FD_ISSET(sockfd, &rset) ) {
	    //TODO: use g_log
	    fprintf(stderr, "main_loop: could not fetch\n");
	    close(sockfd);
	    continue;
	}
	if ( msg_read_fetch_reply(sockfd, &gerror) ) {
	    //TOOD: use g_log
	    if ( gerror ) {
		fprintf(stderr, "main loop: %s\n", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
	    }
	    close(sockfd);
	    continue;
	}
	if ( !(incoming_cv = msg_read_cv(sockfd, &gerror)) ) {
	    //TODO: use g_log
	    if ( gerror ) {
		fprintf(stderr, "main_loop: %s\n", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
	    }
	    close(sockfd);
	    continue;
	}
	
	close(sockfd);
	
	//compute & shuffle
	if ( incoming_cv->len ) {
	    avmon_compute_and_shuffle(node, incoming_cv, random_peer);
	} else {
	    g_ptr_array_free(incoming_cv, TRUE);
	}
    }

#ifdef DEBUG
    g_debug("main_loop out");
#endif

    pthread_exit(NULL);
}

static void
_avmon_join(const char *ip, const char *port, void *_node)
{
    AVMONNode *node = (AVMONNode *) _node;
    
    if ( g_str_equal(ip, node->ip_c) && g_str_equal(port, node->port_c) )
	return; // introducer only knows me

    if ( !cv_lookup(node, ip, port) )
	cv_add((AVMONNode *) _node, peer_new(ip, port));
}

static int
avmon_join(AVMONNode *node, GError **gerror)
{
    struct addrinfo *ai = NULL;
    int sockfd = -1, result = 1;
    GPtrArray *incoming_cv = NULL;
    char *i_port_c = NULL;
    fd_set rset;

    i_port_c = g_strdup_printf("%d", conf_get_introducer_port(node->conf));
    if ( !(ai = net_char_to_addrinfo(conf_get_introducer_name(node->conf), i_port_c,
				      gerror)) )
	goto bye;
    if ( (sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_JOIN, "creating socket");
	goto bye;
    }
    if ( net_connect_nb(sockfd, ai->ai_addr, ai->ai_addrlen,
			conf_get_introducer_timeout(node->conf), 0, gerror) ) {
	goto bye;
    }

    //TODO: not sure, but something
    if ( node->CVS > 255 )
	g_error("Currently join's weight is limited to 8bit"); //this abort()s
    //TODO
    if ( msg_send_join(sockfd, node->CVS, node->port, gerror) )
	goto bye;

    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    if ( select(sockfd + 1, &rset, NULL, NULL, NULL) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_JOIN, "sending join");
	goto bye;
    }
    
    if ( !FD_ISSET(sockfd, &rset) ) {
	g_set_error(gerror, AVMON_ERROR, AVMON_ERROR_JOIN, "no answer");
	goto bye;
    }

    if ( msg_read_join_reply(sockfd, gerror) )
	goto bye;

    if ( !(incoming_cv = msg_read_cv(sockfd, gerror)) )
	goto bye;

    process_ip_port_array(incoming_cv, TRUE, _avmon_join, node);
    if ( !cv_size(node) ) {
	char i_ip[INET_ADDRSTRLEN + 1];
	
	inet_ntop(AF_INET, &((struct sockaddr_in *) ai->ai_addr)->sin_addr, i_ip,
		  INET_ADDRSTRLEN);
	cv_add(node, peer_new(i_ip, i_port_c));
    }

    result = 0;

bye:
    if ( i_port_c )
	g_free(i_port_c);
    if ( sockfd != -1 )
	close(sockfd);
    if ( ai )
	freeaddrinfo(ai);

    return result;
}

/**
 * Use to create an AVMON node.
 *
 * \param[in] conf_file Name of file holding configuration parameters.
 * \param[in] K System-wide constant.
 * \param[in] N System-wide constant.
 * \param[out] gerror If something goes wrong gerror will be non-NULL.
 * \return 0 if OK.
 */
AVMONNode *
avmon_start(const char *conf_file, int K, int N, GError **gerror)
{
    AVMONNode *node = NULL;
    Conf *conf = NULL;

    net_init();

    //configuration:
#ifdef DEBUG
    g_debug("loading configuration");
#endif
    conf = conf_load(conf_file, gerror);
    if ( *gerror )
	goto exit_with_error;

    //node:
#ifdef DEBUG
    g_debug("creating node");
#endif
    node = avmon_node_new(K, N, conf, gerror);
    if ( *gerror )
	goto exit_with_error;

    //evp:
#ifdef DEBUG
    g_debug("setting up openssl");
#endif
    if ( !evp_set ) {
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha1");
	EVP_MD_CTX_init(&mdctx);

	evp_set = TRUE;
    }

    //listener
#ifdef DEBUG
    g_debug("starting listener");
#endif
    node->join_status = JOIN_STATUS_OUT;
    node->listener = avmon_listener_start(node, conf, gerror);
    if ( !node->listener )
	goto exit_with_error;

    //Coarse View:
#ifdef DEBUG
    g_debug("initializing coarser view");
#endif
    cv_init(node);

    //JOIN:
#ifdef DEBUG
    g_debug("joining the overlay");
#endif
    if ( !g_ascii_strncasecmp(conf_get_introducer_name(node->conf), 
			      AVMON_INTRODUCER_NONE, strlen(AVMON_INTRODUCER_NONE)) ) {
	//this must be the first node to join
	node->join_status = JOIN_STATUS_ALONE;
    } else {
	node->join_status = JOIN_STATUS_JOINING;
	if ( avmon_join(node, gerror) ) {
	    node->join_status = JOIN_STATUS_OUT;
	    goto exit_with_error;
	}
	node->join_status = JOIN_STATUS_IN;
    }

    //main protocol loop
#ifdef DEBUG
    g_debug("starting protocol loop");
#endif
    pthread_create(&node->tid, NULL, main_loop, (void *) node);

    //monitoring loop
#ifdef DEBUG
    g_debug("starting monitoring loop");
#endif
    pthread_create(&node->m_tid, NULL, monitoring_loop, (void *) node);

    return node;

exit_with_error:
    if ( node )
	avmon_node_free(node);

    return NULL;
}

int
avmon_stop(AVMONNode *node, GError **gerror)
{
    if ( avmon_listener_stop(node->listener, gerror) )
	return -1;
   
    if ( write(node->monitoring_pipe[1], "stop", 4) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_STOP, "monitor pipe");
	return -1;
    }
    pthread_join(node->m_tid, NULL);

    if ( write(node->main_pipe[1], "stop", 4) == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_STOP, "main pipe");
	return -1;
    }
    pthread_join(node->tid, NULL);
    
    avmon_node_free(node);

    return 0;
}

static void
_avmon_get_ping_set(const char *ip, const char *port, void *_array)
{
    g_ptr_array_add((GPtrArray *) _array, peer_new(ip, port));
}

GPtrArray *
avmon_get_ping_set(const char *target, const char *target_port, GError **gerror)
{
    g_assert(target != NULL);
    g_assert(target_port != NULL);

    GPtrArray *array = NULL, *ip_port_array;
    int socketfd;
    struct addrinfo *ai = net_char_to_addrinfo(target, target_port, gerror);
    if ( !ai )
	return NULL;
    
    if ( (socketfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
	 == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_PS, 
			     "couldn't create socket");
	socketfd = 0;
	goto bye;
    }
    
    if ( net_connect_nb(socketfd, ai->ai_addr, ai->ai_addrlen, 5, 0, gerror) ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_PS,
			     "couldn't connect");
	goto bye;
    }
    
    if ( msg_send_get_ps(socketfd, gerror) )
	goto bye;

    if ( msg_read_get_ps_reply(socketfd, gerror) )
	goto bye;

    if ( !(ip_port_array = msg_read_ps(socketfd, gerror)) )
	goto bye;
    
    array = g_ptr_array_new();
    process_ip_port_array(ip_port_array, TRUE, _avmon_get_ping_set, array);

bye:
    if ( socketfd )
	close(socketfd);
    if ( ai )
	freeaddrinfo(ai);

    return array;
}

void
avmon_receive_get_ps(AVMONNode *node, int socketfd)
{
    GError *gerror = NULL;
    GPtrArray *ps_array = ps_to_array(node);

    msg_write_get_ps_reply(socketfd, ps_array, &gerror);
}

typedef struct {
    int timeout;
    char *monitor_ip;
    char *monitor_port;
    const char *target;
    const char *target_port;
} AVMONGetRawAvailabilityData;

static void *
_avmon_get_raw_availability(void *_agrad)
{
    AVMONGetRawAvailabilityData *agrad = (AVMONGetRawAvailabilityData *) _agrad;
    GError *gerror = NULL;
    struct addrinfo *ai = NULL;
    char *result = g_strdup_printf("%s_%s_from_%s_%s.raw", agrad->target, 
				   agrad->target_port, agrad->monitor_ip,
				   agrad->monitor_port);
    int socketfd;
    gboolean ok = FALSE;
    fd_set rset;
    struct timeval tv;

    ai = net_char_to_addrinfo(agrad->monitor_ip, agrad->monitor_port, &gerror);
    if ( !ai )
	goto bye;

    if ( (socketfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
	 == -1 ) {
	socketfd = 0;
	goto bye;
    }

    if ( net_connect_nb(socketfd, ai->ai_addr, ai->ai_addrlen, agrad->timeout, 0,
			&gerror) )
	goto bye;

    if ( msg_send_get_raw_availability(socketfd, agrad->target,
				       agrad->target_port, &gerror) )
	goto bye;

    FD_ZERO(&rset);
    FD_SET(socketfd, &rset);
    tv.tv_sec = agrad->timeout;
    tv.tv_usec = 0;
    if ( select(socketfd + 1, &rset, NULL, NULL, &tv) == -1 )
	goto bye;

    if ( !FD_ISSET(socketfd, &rset) )
	goto bye;
    
    if ( msg_read_get_raw_availability_reply(socketfd, &gerror) )
	goto bye;

    if ( msg_read_get_raw_availability_reply_data(socketfd, result, agrad->timeout,
						  &gerror) )
	goto bye;
    
    ok = TRUE;

bye:
    if ( ai )
	freeaddrinfo(ai);
    if ( gerror )
	g_error_free(gerror);
    g_free(agrad->monitor_ip);
    g_free(agrad->monitor_port);
    g_free(agrad);

    if ( socketfd )
	close(socketfd);

    if ( !ok )
	result[0] = '\0';

    pthread_exit(result);
}

GPtrArray *
avmon_get_raw_availability(const GPtrArray *monitors, int timeout,
			   const char *target, const char *target_port,
			   GError **gerror)
{
    g_assert(monitors != NULL); 
    g_assert(timeout > 0);
    g_assert(target != NULL);
    g_assert(target_port != NULL);

    int i;
    char *result, target_ip[INET_ADDRSTRLEN + 1];
    GPtrArray *results;
    pthread_t t_ids[monitors->len + 1];
    AVMONGetRawAvailabilityData *agrad;
    AVMONPeer *monitor;
    struct addrinfo *ai = net_char_to_addrinfo(target, target_port, gerror);
    if ( !ai )
	return NULL;
    inet_ntop(AF_INET, &((struct sockaddr_in *) ai->ai_addr)->sin_addr, target_ip,
	      INET_ADDRSTRLEN);
    freeaddrinfo(ai);

    for ( i = 0; i < monitors->len; i++ ) {
	agrad = g_new(AVMONGetRawAvailabilityData, 1);
	agrad->timeout = timeout;
	agrad->target = target_ip;
	agrad->target_port = target_port;

	monitor = g_ptr_array_index(monitors, i);
	agrad->monitor_ip = avmon_peer_get_ip(monitor);
	agrad->monitor_port = avmon_peer_get_port(monitor);
	
	pthread_create(&t_ids[i], NULL, _avmon_get_raw_availability, agrad);
    }

    results = g_ptr_array_new();
    for ( i = 0; i < monitors->len; i++ ) {
	result = NULL;
	pthread_join(t_ids[i], (void **) &result);

	if ( result[0] == '\0' ) {
	    g_ptr_array_add(results, NULL);
	    g_free(result);
	} else
	    g_ptr_array_add(results,  result);
    }

    return results;
}

void 
avmon_receive_get_raw_availability(AVMONNode *node, int socketfd)
{
    GError *gerror = NULL;
    GPtrArray *arr = msg_read_target(socketfd, &gerror);
    AVMONPeer *target;

    if ( gerror || !arr->len )
	goto bye;

    if ( !(target = ts_lookup(node, g_ptr_array_index(arr, 0), 
			      g_ptr_array_index(arr, 1))) ) {
	msg_write_get_raw_availability_reply(socketfd, NULL, &gerror);
    } else {
	if ( target->default_output_name ) {
	    fflush(target->default_output); //TODO: instead of flushing, use a checkpoint
	    msg_write_get_raw_availability_reply(socketfd, target->default_output_name,
						 &gerror);
	} else {
	    //TODO: send some warning instead of "UNKNOWN"
	    msg_write_get_raw_availability_reply(socketfd, NULL, &gerror);
	}
    }

bye:
    if ( gerror )
	g_error_free(gerror);
    if ( arr ) {
	if ( arr->len ) {
	    g_free(g_ptr_array_index(arr, 0));
	    g_free(g_ptr_array_index(arr, 1));
	}
	g_ptr_array_free(arr, TRUE);
    }
}
