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
 * \file avmon.c
 * \author Ramses Morales
 * \version
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
#include <sys/stat.h>
#include <pwd.h>

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
    GTimeVal last_mon_ping_answered;
    GTimeVal last_mon_ping;
    GTimeVal first_session_ping;
    glong unresponsive;
    glong last_heard_of;
};

struct _AVMONNode {
    int K, N;
    long double condition;
    GHashTable *cv;
    int CVS;
    
    int periods_uncontacted;
    int periods_till_contacted;
    gboolean contacted_this_period;

    GHashTable *ps;
    GHashTable *ts;

    AVMONFunc avmon_func;
    AVMONReplyFunc avmon_reply_func;
    AVMONAvOutputFunc avmon_av_output_func;
    char *default_av_output_prefix;

    int monitoring_period;

    enum JoinStatus join_status;

    Conf *conf;
    pthread_t tid;
    pthread_t m_tid;
    pthread_t p_tid;

    AVMONListener *listener;

    int main_pipe[2];
    int monitoring_pipe[2];
    int pp_write_pipe;
    int pp_read_pipe;
    int pp_write_answer_pipe;
    int pp_read_answer_pipe;

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

    gboolean enable_forgetful_pinging;
    gboolean session_first_ts_ping;
    glong unresponsive_threshold;

    GTimeVal session_started;
    GTimeVal previous_session_end;

#ifdef BACKGROUND_OVERHEAD_COUNTER
    MsgBOC *msgboc;
#endif
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
    p->last_mon_ping_answered.tv_sec = 0;
    p->last_mon_ping_answered.tv_usec = 0;
    p->last_mon_ping.tv_sec = 0;
    p->last_mon_ping.tv_usec = 0;
    p->first_session_ping.tv_sec = 0;
    p->first_session_ping.tv_usec = 0;
    p->unresponsive = 0;
    p->last_heard_of = 0;
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

glong
avmon_peer_last_heard_of(const AVMONPeer *peer)
{
    return peer->last_heard_of;
}

glong
avmon_peer_mon_last_heard_of(const AVMONPeer *peer)
{
    GTimeVal tv;
    
    g_get_current_time(&tv);
    return tv.tv_sec - peer->last_mon_ping_answered.tv_sec;
}

static inline int
ps_size(AVMONNode *node)
{
    return g_hash_table_size(node->ps);
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

static GPtrArray *
ts_to_array(AVMONNode *node)
{
    GPtrArray *array = NULL;
    
    pthread_mutex_lock(&node->mutex_ts);
    array = util_g_hash_table_to_array(node->ts);
    pthread_mutex_unlock(&node->mutex_ts);

    return array;
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

#define AV_OUTPUT_SEPARATOR "|" 

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
	fprintf(peer->default_output, "%u%s%d\n", (unsigned int) time(NULL),
		AV_OUTPUT_SEPARATOR, node->monitoring_period);
    }
}

static void
avmon_default_monitor_reply(AVMONNode *node, AVMONPeer *peer)
{
    g_get_current_time(&peer->last_mon_ping_answered);

    if ( node->enable_forgetful_pinging ) {
	if ( peer->unresponsive ) {
	    peer->unresponsive = 0;
	    peer->first_session_ping.tv_sec = peer->last_mon_ping.tv_sec;
	    peer->first_session_ping.tv_usec = 0;
	}
    }

    node->avmon_av_output_func(node, peer);
}

static gboolean
forgetful_ping_dec(AVMONNode *node, AVMONPeer *peer)
{
    double session_time;
    GTimeVal tv;
    
    if ( peer->last_mon_ping.tv_sec == 0 )
	return TRUE;

    if ( peer->last_mon_ping.tv_sec < peer->last_mon_ping_answered.tv_sec )
	return TRUE;
    
    g_get_current_time(&tv);
    peer->unresponsive += tv.tv_sec - peer->last_mon_ping.tv_sec;
    
    if ( !(peer->unresponsive > node->unresponsive_threshold) )
	return TRUE;
    
    if ( peer->last_mon_ping_answered.tv_sec == 0 )
	return FALSE;
    
    session_time = (double) (peer->last_mon_ping_answered.tv_sec 
			     - peer->first_session_ping.tv_sec);
    if ( ( ( 1.0 /*TODO*/ * session_time)
	   / (session_time + (double) peer->unresponsive) ) 
	 > g_rand_double(node->grand) )
	return FALSE;

    return TRUE;
}

static void
do_monitor_peer(gpointer _key, gpointer _peer, gpointer _node)
{
    AVMONPeer *peer = (AVMONPeer *) _peer;
    AVMONNode *node = (AVMONNode *) _node;
    
    if ( node->enable_forgetful_pinging ) {
	if ( !node->session_first_ts_ping )
	    if ( !forgetful_ping_dec(node, peer) )
		return;
    }
    
    node->avmon_func((AVMONNode *) _node, peer->ip, peer->port);
    if ( node->enable_forgetful_pinging ) {
	g_get_current_time(&peer->last_mon_ping);
	if ( peer->first_session_ping.tv_sec == 0 )
	    g_get_current_time(&peer->first_session_ping);
    }
}

typedef void (*TSFOREACHFunc) (gpointer _key, gpointer _peer, gpointer _node);

static void
ts_foreach(AVMONNode *node, TSFOREACHFunc func)
{
    pthread_mutex_lock(&node->mutex_ts);
    g_hash_table_foreach(node->ts, func, node);
    pthread_mutex_unlock(&node->mutex_ts);
    
    node->session_first_ts_ping = FALSE;
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
    if ( node->pp_write_pipe != -1 ) {
	close(node->pp_write_pipe);
	close(node->pp_read_pipe);
    }
    if ( node->pp_read_answer_pipe != -1 ) {
	close(node->pp_write_answer_pipe);
	close(node->pp_read_answer_pipe);
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
    node->periods_till_contacted = (int) ceil(sqrt((double) N) / 16.0);
    node->periods_uncontacted = 0;
    node->contacted_this_period = FALSE;

    pthread_mutex_init(&node->mutex_cv, NULL);
    pthread_mutex_init(&node->mutex_ps, NULL);
    pthread_mutex_init(&node->mutex_ts, NULL);

    node->grand = g_rand_new();

    node->ip_c = conf_get_host_ip(conf);
    if ( !node->ip_c ) {
	node->ip_c = g_strdup(net_my_ip(conf_use_public_ip(conf), gerror));
	if ( *gerror )
	    g_error("%s\nPlease use host_ip option in configuration file",
		    (*gerror)->message); //aborts
    }
    node->port_c = g_strdup_printf("%d", conf_get_listener_tcp_udp_port(conf));
    node->port = conf_get_listener_tcp_udp_port(conf);
    if ( node->port > 65535 )
	g_error("bad port number %d", node->port); //aborts
    node->key = cv_key(node->ip_c, node->port_c);

    node->pp_read_pipe = node->pp_write_pipe = node->pp_read_answer_pipe =
	node->pp_write_answer_pipe = -1;

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

    //
    {
	int pp_pipes[2];
	if ( pipe(pp_pipes) ) {
	    util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
				 "creating pipe");
	    goto exit_with_error;
	}
	node->pp_read_pipe = pp_pipes[0];
	node->pp_write_pipe = pp_pipes[1];

	if ( pipe(pp_pipes) ) {
	    util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_NODE,
				 "creating pipe");
	    goto exit_with_error;
	}
	node->pp_read_answer_pipe = pp_pipes[0];
	node->pp_write_answer_pipe = pp_pipes[1];
    }

    node->peer_trash = g_ptr_array_new();
    node->peer_trash_last_collection = time(NULL);

    node->enable_forgetful_pinging = conf_enable_forgetful_pinging(conf);
    node->session_first_ts_ping = TRUE;

    g_get_current_time(&node->session_started);

#ifdef BACKGROUND_OVERHEAD_COUNTER
    node->msgboc = NULL;
#endif

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
	else if ( peer->peer_cv )
	    g_ptr_array_add(ccd->incoming_duplicate, peer);
    } else {
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
	goto bye;
    }

    peer_port_c = g_strdup_printf("%d", peer_port);
    peer = ts_lookup(node, ip, peer_port_c);
    if ( !peer ) {
	g_warning("received monitoring pong from %s:%s. It is not in TS", ip,
		  peer_port_c);
	goto bye;
    }

    node->avmon_reply_func(node, peer);

bye:
    if ( gerror )
	g_error_free(gerror);
    g_free(peer_port_c);
}

enum PingedPeerMessageType {
    PP_PINGED = 0,
    PP_PONG,
    PP_ANSWERED,
    PP_EXIT
};

typedef struct {
    char *key;
    enum PingedPeerMessageType t;
} PingedPeerMessage;

typedef struct {
    gboolean answered;
} PingedPeerAnswer;

typedef struct {
    char *key;
    gboolean answered;
} PingedPeer;

static void *
pinged_peer_loop(void *_node) 
{
    AVMONNode *node = (AVMONNode *) _node;
    fd_set rset;
    PingedPeerMessage *ppm = g_new(PingedPeerMessage, 1);
    PingedPeer pp;
    PingedPeerAnswer pa;
    pp.key = NULL;
    pp.answered = FALSE;
    
    for ( ; ; ) {
	FD_ZERO(&rset);
	FD_SET(node->pp_read_pipe, &rset);

	if ( select(node->pp_read_pipe + 1, &rset, NULL, NULL, NULL) == -1 ) {
	    char buff[128];
	    strerror_r(errno, buff, 127);
	    g_critical("%s", buff);
	    exit(1);
	}

	if ( !FD_ISSET(node->pp_read_pipe, &rset) )
	    g_error("pinged_peer_loop wtf");

	if ( read(node->pp_read_pipe, ppm, sizeof(PingedPeerMessage))
	     < sizeof(PingedPeerMessage) )
	    g_error("pinged_peer_loop received a bad message");

	switch ( ppm->t ) {
	case PP_EXIT:
	    if ( pp.key )
		g_free(pp.key);
	    
	    goto exit;
	    break;
	case PP_PINGED:
	    if ( pp.key )
		g_free(pp.key);
	    
	    pp.key = g_strdup(ppm->key);
	    pp.answered = FALSE;
	    break;
	case PP_PONG:
	    if ( pp.key ) {
		if ( !strcmp(pp.key, ppm->key) )
		    pp.answered = TRUE;
	    }
	    break;
	case PP_ANSWERED:
	    if ( pp.key ) {
		if ( !strcmp(pp.key, ppm->key) ) {
		    pa.answered = pp.answered;

		    g_free(pp.key);
		    pp.key = NULL;
		    pp.answered = FALSE;
		} else {
		    pa.answered = FALSE;
		}
	    } else {
		pa.answered = FALSE;
	    }
	    write(node->pp_write_answer_pipe, &pa, sizeof(PingedPeerAnswer));
	    break;
	}

	g_free(ppm->key);
	ppm->key = NULL;
    }

exit:
    if ( ppm->key )
	g_free(ppm->key);
    g_free(ppm);
    
    close(node->pp_write_answer_pipe);
    close(node->pp_read_pipe);

    pthread_exit(NULL);
}

static void
pinged_peer_pong(AVMONNode *node, const char *key)
{
    PingedPeerMessage ppm;
    ppm.key = g_strdup(key);
    ppm.t = PP_PONG;
    write(node->pp_write_pipe, &ppm, sizeof(PingedPeerMessage));
}

static void
pinged_peer_pinged(AVMONNode *node, const char *key)
{
    PingedPeerMessage ppm;
    ppm.key = g_strdup(key);
    ppm.t = PP_PINGED;
    write(node->pp_write_pipe, &ppm, sizeof(PingedPeerMessage));
}

static gboolean
pinged_peer_answered(AVMONNode *node, const char *key)
{
    PingedPeerMessage ppm;
    PingedPeerAnswer ppa;
    memset(&ppa, 0, sizeof(PingedPeerAnswer));

    ppm.key = g_strdup(key);
    ppm.t = PP_ANSWERED;
    write(node->pp_write_pipe, &ppm, sizeof(PingedPeerMessage));

    read(node->pp_read_answer_pipe, &ppa, sizeof(PingedPeerAnswer));

    return ppa.answered;
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

    pinged_peer_pong(node, peer->key);
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
    if ( gerror ) {
	//TODO: log error
	g_error_free(gerror);
    }
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
    if ( gerror ) {
	//TODO: log error
	g_error_free(gerror);
    }
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
    if ( gerror ) {
	//TODO: log?
	g_error_free(gerror);
    }
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

    node->contacted_this_period = TRUE;
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
    
    node->monitoring_period = conf_get_monitoring_period(node->conf);

    if ( node->enable_forgetful_pinging ) 
	node->unresponsive_threshold = 3 * node->monitoring_period; //TODO: conf?

    for ( ; ; ) {
	FD_ZERO(&rset);
	FD_SET(node->monitoring_pipe[0], &rset);
	tv.tv_sec = node->monitoring_period;
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
	ts_foreach(node, do_monitor_peer);
    }

#ifdef DEBUG
    g_debug("monitoring_loop out");
#endif

    pthread_exit(NULL);
}

static void *
_send_fake_join(void *_node)
{
    int i, sockfd = -1;
    fd_set rset;
    struct addrinfo *ai = NULL;
    struct timeval tv;
    GError *gerror = NULL;
    GPtrArray *incoming_cv = NULL;
    AVMONNode *node = (AVMONNode *) _node;
    AVMONPeer *peer = NULL;

    pthread_detach(pthread_self());

    if ( !(peer = cv_random_peer(node)) )
	goto bye;

    if ( !(ai = net_char_to_addrinfo(peer->ip, peer->port, &gerror)) )
	goto bye;
    if ( (sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
	 == -1 )
	goto bye;
    if ( net_connect_nb(sockfd, ai->ai_addr, ai->ai_addrlen, 5 /* TODO? */, 0,
			&gerror) )
	goto bye;

    if ( msg_send_join(sockfd, node->CVS, node->port, TRUE, &gerror) )
	goto bye;
    
    tv.tv_sec = 5; /*TODO?*/
    tv.tv_usec = 0;
    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    if ( select(sockfd + 1, &rset, NULL, NULL, &tv) == -1 ) 
	goto bye;
    if ( !FD_ISSET(sockfd, &rset) )
	goto bye;
    
    if ( msg_read_join_reply(sockfd, &gerror) )
	goto bye;
    incoming_cv = msg_read_cv(sockfd, &gerror);
    //TODO: use this to fill empty spaces in the CV

    if ( incoming_cv ) {
	for ( i = 0; i < incoming_cv->len; i++ )
	    g_free(g_ptr_array_index(incoming_cv, i));
	g_ptr_array_free(incoming_cv, TRUE);
    }

bye:
    if ( sockfd > 0 )
	close(sockfd);
    if ( ai )
	freeaddrinfo(ai);
    if ( gerror )
	g_error_free(gerror);

    pthread_exit(NULL);
}

static void
send_fake_join(AVMONNode *node)
{
    pthread_t tid;
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    
    pthread_create(&tid, &thread_attr, _send_fake_join, (void *) node);
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
	{
	    AVMONPeer *pinged_peer = cv_random_peer(node);
	    if ( pinged_peer ) {
		pinged_peer_pinged(node, pinged_peer->key);
		msg_send_cv_ping(pinged_peer->ip, pinged_peer->port, node->port);
		sleep(5); //TODO: make configurable?

		if ( !pinged_peer_answered(node, pinged_peer->key) ) {
		    cv_delete(node, pinged_peer);
		    peer_free(pinged_peer);
		}
	    }
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

	if ( node->contacted_this_period ) {
	    node->periods_uncontacted = 0;
	    node->contacted_this_period = FALSE;
	} else {
	    node->periods_uncontacted++;
	    if ( node->periods_uncontacted > node->periods_till_contacted ) {
		send_fake_join(node);
		node->periods_uncontacted = 0;
	    }
	}

#ifdef BACKGROUND_OVERHEAD_COUNTER
	msg_background_overhead_counter_log();
#endif
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
    if ( msg_send_join(sockfd, node->CVS, node->port, FALSE, gerror) )
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

#define CACHE_SEPARATOR "|"

static char *
avmon_hidden_dir_name(void)
{
    struct passwd *spwd = getpwuid(getuid());
    
    return g_strdup_printf("%s/.avmon/", spwd->pw_dir);
}


static char *
avmon_cache_dir_name(AVMONNode *node)
{
    char *hdir = avmon_hidden_dir_name();
    char *cdir = NULL;
    
    cdir = g_strdup_printf("%s%s_%s/", hdir, node->ip_c, node->port_c);
    g_free(hdir);
    return cdir;
}

static gboolean
prepare_cache_dir(AVMONNode *node)
{
    gboolean result = FALSE;
    char *cache_dir = NULL, *hdir = NULL;
    struct stat statbuff;

    hdir = avmon_hidden_dir_name();
    if ( !stat(hdir, &statbuff) ) {
	if ( !S_ISDIR(statbuff.st_mode) ) {
	    g_warning("%s is not a directory", hdir);
	    goto bye;
	}
    } else if ( errno == ENOENT ) {
	if ( mkdir(hdir, S_IRWXU) ) {
	    g_warning("couldn't create directory (%s): %s", hdir,
		      strerror(errno));
	    goto bye;
	}
    }
    
    cache_dir = avmon_cache_dir_name(node);
    if ( !stat(cache_dir, &statbuff) ) {
	if ( !S_ISDIR(statbuff.st_mode) ) {
	    g_warning("%s is not a directory", cache_dir);
	    goto bye;
	}
    } else if ( errno == ENOENT ) {
	if ( mkdir(cache_dir, S_IRWXU) ) {
	    g_warning("couldn't create directory (%s): %s", cache_dir,
		      strerror(errno));
	    goto bye;
	}
    }

    result = TRUE;
    
bye:
    if ( hdir )
	g_free(hdir);
    if ( cache_dir )
	g_free(cache_dir);
    
    return result;
}

static char **
avmon_psts_cache_file_names(AVMONNode *node)
{
    char *cache_dir = NULL, **ps_ts_name = NULL;

    cache_dir = avmon_cache_dir_name(node);

    ps_ts_name = (char **) g_malloc(4 * sizeof(char *));
    ps_ts_name[0] = g_strconcat(cache_dir, "ps_cache.txt", NULL);
    ps_ts_name[1] = g_strconcat(cache_dir, "ts_cache.txt", NULL);
    ps_ts_name[2] = g_strconcat(ps_ts_name[1], ".timestamp", NULL);
    ps_ts_name[3] = NULL;

    g_free(cache_dir);

    return ps_ts_name;
}

static void
load_cached_sets(AVMONNode *node)
{
    char *line = NULL, **split = NULL, **ps_ts_name = NULL;
    GIOChannel *ps_cache = NULL, *ts_cache = NULL, *ts_cache_timestamp = NULL;
    GIOStatus status;
    GError *gerror = NULL;
    AVMONPeer *peer = NULL;
    GTimeVal t_tv;
    
    ps_ts_name = avmon_psts_cache_file_names(node);

    if ( !(ps_cache = g_io_channel_new_file(ps_ts_name[0], "r", &gerror)) ) {
	if ( !g_error_matches(gerror, G_FILE_ERROR, G_FILE_ERROR_NOENT) )
	    g_warning("couldn't open ps-cache: %s", gerror->message);
	g_error_free(gerror);
	gerror = NULL;
    } else {
	for ( ; ; ) {
	    status = g_io_channel_read_line(ps_cache, &line, NULL, NULL, &gerror);
	    if ( gerror ) {
		g_warning("error reading ps-cache: %s", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
		break;
	    }
	    if ( status != G_IO_STATUS_NORMAL )
		break;
		
	    split = g_strsplit(line, CACHE_SEPARATOR, -1);
	    if ( split[0] == NULL || split[1] == NULL || split[2] != NULL ) {
		g_strfreev(split);
		g_warning("ps-cache is br0k3n");
		break;
	    }
	    util_eliminate_newline(split[1]);
	    ps_add(node, peer_new(split[0], split[1])); //TODO: validate ip and port

	    g_free(line);
	    g_strfreev(split);
	}
    }

    if ( !(ts_cache = g_io_channel_new_file(ps_ts_name[1], "r", &gerror)) ) {
	if ( !g_error_matches(gerror, G_FILE_ERROR, G_FILE_ERROR_NOENT) )
	    g_warning("couldn't open ts-cache: %s", gerror->message);
	g_error_free(gerror);
	gerror = NULL;
    } else {
	if ( !(ts_cache_timestamp =
	       g_io_channel_new_file(ps_ts_name[2], "r", &gerror)) ) {
	    g_warning("ts-cache timestamp lost: %s", gerror->message);
	    g_error_free(gerror);
	    gerror = NULL;
	    goto bye;
	}
	status = g_io_channel_read_line(ts_cache_timestamp, &line, NULL, NULL, &gerror);
	if ( gerror || status != G_IO_STATUS_NORMAL ) {
	    if ( gerror ) {
		g_warning("problem reading ts-cache timestamp: %s", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
	    } else {
		g_warning("problem reading ts-cache timestamp");
	    }
	    goto bye;
	}
	t_tv.tv_sec = (glong) g_ascii_strtod(line, NULL);
	g_free(line);
	
	if ( node->previous_session_end.tv_sec != t_tv.tv_sec ) {
	    g_warning("bad ts-cache timestamp");
	    goto bye;
	}

	for ( ; ; ) {
	    status = g_io_channel_read_line(ts_cache, &line, NULL, NULL, &gerror);
	    if ( gerror ) {
		g_warning("error reading ts-cache: %s", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
		break;
	    }
	    if ( status != G_IO_STATUS_NORMAL )
		break;

	    split = g_strsplit(line, CACHE_SEPARATOR, -1);
	    if ( split[0] == NULL || split[1] == NULL || split[2] == NULL
		 || split[3] == NULL || split[4] == NULL || split[5] != NULL ) {
		g_strfreev(split);
		g_warning("ts-cache is br0k3n");
		break;
	    }
	    peer = peer_new(split[0], split[1]);
	    peer->last_mon_ping_answered.tv_sec = (glong) g_strtod(split[2], NULL);
	    peer->last_mon_ping_answered.tv_usec = 0;
	    peer->last_mon_ping.tv_sec = (glong) g_strtod(split[3], NULL);
	    peer->last_mon_ping.tv_usec = 0;
	    peer->first_session_ping.tv_sec = (glong) g_strtod(split[4], NULL);
	    peer->first_session_ping.tv_usec = 0;
	    ts_add(node, peer); //TODO: validate ip and port.

	    g_free(line);
	    g_strfreev(split);
	}
    }

bye:    
    if ( ps_cache )
	g_io_channel_close(ps_cache);
    if ( ts_cache )
	g_io_channel_close(ts_cache);
    if ( ts_cache_timestamp )
	g_io_channel_close(ts_cache_timestamp);
    if ( ps_ts_name )
	g_strfreev(ps_ts_name);
}

static char *
avmon_sessions_file_name(AVMONNode *node)
{
    char *cache_dir_name = avmon_cache_dir_name(node);
    char *sessions_name = g_strconcat(cache_dir_name, "sessions.txt", NULL);
    
    g_free(cache_dir_name);
    
    return sessions_name;
}

#define SESSION_RECORD_SEPARATOR ":"
#define SESSION_RECORD_START "START"
#define SESSION_RECORD_END "END"

static void
record_session_start(AVMONNode *node)
{
    char *sessions_name = avmon_sessions_file_name(node);
    char *buff = NULL;
    GIOChannel *sessions = NULL;
    GError *gerror = NULL;
    gsize bytes_written;
    
    if ( !(sessions = g_io_channel_new_file(sessions_name, "a", &gerror)) )
	g_error("Could not open %s: %s", sessions_name, gerror->message); //aborts

    buff = g_strdup_printf("%s%s-%s%lu\n", SESSION_RECORD_START,
			   SESSION_RECORD_SEPARATOR,
			   SESSION_RECORD_SEPARATOR,
			   node->session_started.tv_sec);
    g_io_channel_write_chars(sessions, buff, -1, &bytes_written, &gerror);
    if ( gerror )
	g_error("Could not write to %s: %s", sessions_name, gerror->message); //aborts

    g_free(sessions_name);
    g_free(buff);
    g_io_channel_close(sessions);
}

//TODO: all session file management crap should be outside avmon.c
static void
verify_split_session_line(char **split) 
{
    if ( split[0] == NULL || split[1] == NULL || split[2] == NULL ||
	 split[3] != NULL ) {
	g_error("corrupt sessions file"); //aborts
    }
    if ( g_ascii_strncasecmp(split[0], SESSION_RECORD_START, strlen(SESSION_RECORD_START))
	 && g_ascii_strncasecmp(split[0], SESSION_RECORD_END, strlen(SESSION_RECORD_END)) )
	g_error("corrupt sessions file");
    //TODO: check more stuff
}

static void
read_previous_session_time(AVMONNode *node)
{
    GError *gerror = NULL;
    char *line1 = NULL, *line2 = NULL, *line3 = NULL, **split1 = NULL,
	**split2 = NULL, *blah = NULL;
    GIOStatus status;
    char *sessions_name = avmon_sessions_file_name(node);
    GIOChannel *sessions = g_io_channel_new_file(sessions_name, "r+", &gerror);
    GTimeVal ct;
    char *buff;
    gsize bytes_written;

    node->previous_session_end.tv_sec = 0;

    if ( !sessions ) {
	if ( !g_error_matches(gerror, G_FILE_ERROR, G_FILE_ERROR_NOENT) )
	    g_error("problem with sessions (%s) file: %s", sessions_name,
		    gerror->message); //aborts
	else
	    goto bye;
    }
/*
    for ( ; ; ) {
	status = g_io_channel_read_line(sessions, &line, NULL, NULL, &gerror);
	if ( gerror )
	    g_error("error reading sessions (%s): %s", sessions_name, 
		    gerror->message); //aborts
	if ( status == G_IO_STATUS_EOF ) {
	    split = g_strsplit(previous_line, SESSION_RECORD_SEPARATOR, -1);
	    if ( split[0] == NULL || split[1] == NULL || split[2] == NULL || 
		 split[3] != NULL )
		g_error("sessions file (%s) has wrong format", sessions_name); //aborts
	    if ( g_ascii_strncasecmp(split[0], SESSION_RECORD_END, 
				     strlen(SESSION_RECORD_END)) )
		goto bye;
	    node->previous_session_end.tv_sec = (glong) g_strtod(split[2], &blah);
	    if ( blah[0] != '\n' )
		g_error("sessions file (%s) is br0k3n", sessions_name); //aborts
	    break;
	}

	if ( previous_line )
	    g_free(previous_line);
	previous_line = line;
    }
*/
    for ( ; ; ) {
	status = g_io_channel_read_line(sessions, &line3, NULL, NULL, &gerror);
	if ( gerror )
	    g_error("error reading sessions (%s): %s", sessions_name,
		    gerror->message);
	if ( status == G_IO_STATUS_EOF ) {
	    if ( !line1 && !line2 ) //empty sessions file
		goto bye;

	    split1= g_strsplit(line1, SESSION_RECORD_SEPARATOR, -1);
	    verify_split_session_line(split1);

	    split2 = g_strsplit(line2, SESSION_RECORD_SEPARATOR, -1);
	    verify_split_session_line(split2);

	    if ( !g_ascii_strncasecmp(split1[0], SESSION_RECORD_START,
				      strlen(SESSION_RECORD_START)) &&
		 !g_ascii_strncasecmp(split2[0], SESSION_RECORD_END,
				      strlen(SESSION_RECORD_END)) ) {
		node->previous_session_end.tv_sec = (glong) g_strtod(split2[2], 
								     &blah);
		if ( blah[0] != '\n' )
		    g_error("sessions file (%s) is br0k3n", sessions_name); //aborts
		goto bye;
	    }

	    //END followed by END....

	    g_error("sessions file (%s) is br0k3n", sessions_name); //aborts

	    //TODO: I'm aborting here because currently "raw availability measurement"
	    //is assumed -- in fact, it is the only that can be used as of now. 
	    //One thing to do would be to erase raw measurements that do
	    //not fall inside valid recorded sessions, and then erase the dangling
	    //session end.
	    //
	    //TODO: As soon as other availability measurements are allowed, this
	    //should be revised. It might be that the session file won't even matter at all
	    //with a different user provided availability monitor.
	    
	    //..or START followed by START, or END followed by START
	}

	if ( line1 ) {
	    g_free(line1);
	    line1 = NULL;
	}
	if ( line2 ) {
	    g_free(line2);
	    line2 = NULL;
	}

	//finish reading (expected) START/END pair
	line1 = line3;
	status = g_io_channel_read_line(sessions, &line2, NULL, NULL, &gerror);
	if ( gerror )
	    g_error("error reading sessions (%s): %s", sessions_name,
		    gerror->message);
	if ( status == G_IO_STATUS_EOF ) {
	    split1 = g_strsplit(line1, SESSION_RECORD_SEPARATOR, -1);
	    verify_split_session_line(split1);

	    if ( g_ascii_strncasecmp(split1[0], SESSION_RECORD_START,
				     strlen(SESSION_RECORD_START)) ) {
		g_error("sessions file (%s) is br0k3n", sessions_name);
		//TODO: read previous TODO comment
	    }

	    //previous session didn't finish cleanly
	    switch ( conf_get_session_fix_method(node->conf) ) {
	    case CONF_SESSION_FIX_NONE:
		g_error("session file (%s) is missing an entry for the end of"
			"the previous session", sessions_name);
		//TODO: read previous TODO comment
		break;
	    case CONF_SESSION_FIX_CURRENT_TIME:
		g_get_current_time(&ct);
		sleep(1); //I'm being lazy here :-p
		util_eliminate_newline(split1[2]);
		buff = g_strdup_printf("%s%s%s%s%lu\n", SESSION_RECORD_END,
				       SESSION_RECORD_SEPARATOR, split1[2],
				       SESSION_RECORD_SEPARATOR, ct.tv_sec);
		g_io_channel_write_chars(sessions, buff, -1, &bytes_written,
					 &gerror);
		if ( gerror ) {
		    g_critical("Could not write to %s: %s", sessions_name,
			       gerror->message);
		    g_error_free(gerror);
		    gerror = NULL;
		}
		g_free(buff);
		g_warning("session END %s is an auto-fix", split1[2]);

		node->previous_session_end.tv_sec = ct.tv_sec;
		goto bye;
		
		break;
	    case CONF_SESSION_FIX_YOUNGUEST_RAW_AV:
		g_error("fixing a session using youngest raw availability is"
			"not yet implemented");
		//TODO: this is going to be a pain, the previous fix should
		//be good for now.
		break;
	    }
	}

	line3 = NULL;
    }

bye:
    g_free(sessions_name);
    if ( sessions )
	g_io_channel_close(sessions);
    if ( line1 )
	g_free(line1);
    else if ( line3 )
	g_free(line3);
    if ( line2 )
	g_free(line2);
    if ( split1 )
	g_strfreev(split1);
    if ( split2 )
	g_strfreev(split2);
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

    if ( !g_thread_supported () )
	g_thread_init (NULL);

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

#ifdef BACKGROUND_OVERHEAD_COUNTER
    node->msgboc = msg_background_overhead_counter_start(gerror);
    if ( !node->msgboc )
	goto exit_with_error;
#endif

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
#ifdef DEBUG
	    g_debug("I'm out");
#endif
	    goto exit_with_error;
	}
	node->join_status = JOIN_STATUS_IN;
#ifdef DEBUG
	g_debug("I'm in!");
#endif
    }

    if ( !prepare_cache_dir(node) )
	exit(1);
    read_previous_session_time(node);
    load_cached_sets(node);

    //
    pthread_create(&node->p_tid, NULL, pinged_peer_loop, (void *) node);

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

    record_session_start(node);

    return node;

exit_with_error:
    if ( node )
	avmon_node_free(node);
    if ( g_error_matches(*gerror, NET_ERROR, NET_ERROR_SIGPIPE) ) {
	g_error_free(*gerror);
	g_set_error(gerror, AVMON_ERROR, AVMON_ERROR_INTRODUCER_CLOSED,
		    "introducer closed the connection");
    }

    return NULL;
}

static void
save_ps_peer(gpointer _key, gpointer _peer, gpointer _ps_cache)
{
    AVMONPeer *peer = (AVMONPeer *) _peer;
    gsize bytes_written;
    GError *gerror = NULL;
    char *buff = g_strconcat(peer->ip, CACHE_SEPARATOR, peer->port, "\n", NULL);
    
    g_io_channel_write_chars((GIOChannel *) _ps_cache, buff, -1, &bytes_written,
			     &gerror);
    if ( gerror ) {
	//TODO: log?
	g_error_free(gerror);
    }
    g_free(buff);
}

static void
save_ts_peer(gpointer _key, gpointer _peer, gpointer _ts_cache)
{
    AVMONPeer *peer = (AVMONPeer *) _peer;
    gsize bytes_written;
    GError *gerror = NULL;
    char *buff = g_strdup_printf("%s%s%s%s%lu%s%lu%s%lu\n", 
				 peer->ip, CACHE_SEPARATOR, peer->port,
				 CACHE_SEPARATOR, peer->last_mon_ping_answered.tv_sec,
				 CACHE_SEPARATOR, peer->last_mon_ping.tv_sec,
				 CACHE_SEPARATOR, peer->first_session_ping.tv_sec);
				 
    g_io_channel_write_chars((GIOChannel *) _ts_cache, buff, -1, &bytes_written,
			     &gerror);
    if ( gerror ) {
	//TODO: log?
	g_error_free(gerror);
    }
    g_free(buff);
}

static gboolean
save_sets(AVMONNode *node)
{
    char **ps_ts_name = NULL;
    GIOChannel *ps_cache = NULL, *ts_cache = NULL;
    GError *gerror = NULL;
    gboolean ts_ok = FALSE;
    
    ps_ts_name = avmon_psts_cache_file_names(node);

    if ( !(ps_cache = g_io_channel_new_file(ps_ts_name[0], "w", &gerror)) ) {
	g_warning("couldn't open ps-cache to write: %s", gerror->message);
	g_error_free(gerror);
	gerror = NULL;
    } else {
	g_hash_table_foreach(node->ps, save_ps_peer, ps_cache);
    }

    if ( !(ts_cache = g_io_channel_new_file(ps_ts_name[1], "w", &gerror)) ) {
	g_warning("couldn't open ts-cache to write: %s", gerror->message);
	g_error_free(gerror);
	gerror = NULL;
    } else {
	g_hash_table_foreach(node->ts, save_ts_peer, ts_cache);
	ts_ok = TRUE;
    }
    
bye:
    if ( ps_ts_name )
	g_strfreev(ps_ts_name);
    if ( ps_cache )
	g_io_channel_close(ps_cache);
    if ( ts_cache )
	g_io_channel_close(ts_cache);

    return ts_ok;
}

static void
record_session_end(AVMONNode *node, gboolean ts_ok)
{
    char *sessions_name = avmon_sessions_file_name(node);
    char **psts_names = NULL;
    char *buff = NULL;
    GIOChannel *sessions = NULL, *ts_timestamp = NULL;
    GError *gerror = NULL;
    gsize bytes_written;
    GTimeVal gtv;
    g_get_current_time(&gtv);

    if ( ts_ok ) {
	psts_names = avmon_psts_cache_file_names(node);
	if ( !(ts_timestamp = g_io_channel_new_file(psts_names[2], "w", &gerror)) ) {
	    g_critical("couldn't write ts-cache timestamp: %s", gerror->message);
	    g_error_free(gerror);
	    gerror = NULL;
	} else {
	    buff = g_strdup_printf("%lu\n", gtv.tv_sec);
	    g_io_channel_write_chars(ts_timestamp, buff, -1, &bytes_written, &gerror);
	    if ( gerror ) {
		g_critical("could not write ts-cache timestamp: %s", gerror->message);
		g_error_free(gerror);
		gerror = NULL;
	    }
	    g_free(buff);
	    buff = NULL;
	    g_io_channel_close(ts_timestamp);
	}

	g_strfreev(psts_names);
    }
    
    if ( !(sessions = g_io_channel_new_file(sessions_name, "a", &gerror)) ) {
	g_critical("Could not open %s: %s", sessions_name, gerror->message);
	goto bye;
    }

    g_get_current_time(&gtv);
    buff = g_strdup_printf("%s%s%lu%s%lu\n", SESSION_RECORD_END,
			   SESSION_RECORD_SEPARATOR,
			   node->session_started.tv_sec,
			   SESSION_RECORD_SEPARATOR, gtv.tv_sec);
    g_io_channel_write_chars(sessions, buff, -1, &bytes_written, &gerror);
    if ( gerror )
	g_critical("Could not write to %s: %s", sessions_name, gerror->message);

bye:
    g_free(sessions_name);
    if ( buff )
	g_free(buff);
    if ( sessions )
	g_io_channel_close(sessions);
    if ( gerror )
	g_error_free(gerror);
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

    {
	PingedPeerMessage ppm;
	ppm.key = NULL;
	ppm.t = PP_EXIT;
	if ( write(node->pp_write_pipe, &ppm, 
		   sizeof(PingedPeerMessage)) == -1 ) {
	    util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_STOP,
				 "pp pipe");
	    return -1;
	}
	pthread_join(node->p_tid, NULL);
    }

    record_session_end(node, save_sets(node));

#ifdef BACKGROUND_OVERHEAD_COUNTER
    msg_background_overhead_counter_log();
    if ( msg_background_overhead_counter_quit(node->msgboc, gerror) )
	return -1;
#endif
    
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

#define RAW_AV_SESSIONS_EXTENSION ".sessions"

static inline char *
sessions_fname_from_raw_av_fname(const char *raw_av_fname)
{
    return g_strconcat(raw_av_fname, RAW_AV_SESSIONS_EXTENSION, NULL);
}

static void *
_avmon_get_raw_availability(void *_agrad)
{
    AVMONGetRawAvailabilityData *agrad = (AVMONGetRawAvailabilityData *) _agrad;
    GError *gerror = NULL;
    struct addrinfo *ai = NULL;
    char *result = g_strdup_printf("%s_%s_from_%s_%s.raw", agrad->target, 
				   agrad->target_port, agrad->monitor_ip,
				   agrad->monitor_port);
    char *result_session = sessions_fname_from_raw_av_fname(result);
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

    if ( msg_read_get_raw_availability_reply_data(socketfd, result, result_session,
						  agrad->timeout, &gerror) )
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
    char *sessions_file_name = NULL;
    GError *gerror = NULL;
    GPtrArray *arr = msg_read_target(socketfd, &gerror);
    AVMONPeer *target;

    if ( gerror || !arr->len )
	goto bye;

    if ( !(target = ts_lookup(node, g_ptr_array_index(arr, 0), 
			      g_ptr_array_index(arr, 1))) ) {
	msg_write_get_raw_availability_reply(socketfd, NULL, NULL, &gerror);
    } else {
	if ( target->default_output_name ) {
	    sessions_file_name = avmon_sessions_file_name(node);
	    fflush(target->default_output); //TODO: instead of flushing, use a checkpoint
	    msg_write_get_raw_availability_reply(socketfd, target->default_output_name,
						 sessions_file_name, &gerror);
	} else {
	    //TODO: send some warning instead of "UNKNOWN"
	    msg_write_get_raw_availability_reply(socketfd, NULL, NULL, &gerror);
	}
    }

bye:
    if ( sessions_file_name )
	g_free(sessions_file_name);
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

// ===
static void
_avmon_get_target_set(const char *ip, const char *port, void *_array)
{
    g_ptr_array_add((GPtrArray *) _array, peer_new(ip, port));
}

GPtrArray *
avmon_get_target_set(const char *monitor, const char *monitor_port, GError **gerror)
{
    g_assert(monitor != NULL);
    g_assert(monitor_port != NULL);

    GPtrArray *array = NULL, *ip_port_array;
    int socketfd;
    struct addrinfo *ai = net_char_to_addrinfo(monitor, monitor_port, gerror);
    if ( !ai )
	return NULL;
    
    if ( (socketfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
	 == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_TS, 
			     "couldn't create socket");
	socketfd = 0;
	goto bye;
    }
    
    if ( net_connect_nb(socketfd, ai->ai_addr, ai->ai_addrlen, 5 /*TODO*/, 0, gerror) ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_TS,
			     "couldn't connect");
	goto bye;
    }
    
    if ( msg_send_get_ts(socketfd, gerror) )
	goto bye;

    if ( msg_read_get_ts_reply(socketfd, gerror) )
	goto bye;

    if ( !(ip_port_array = msg_read_ts(socketfd, gerror)) )
	goto bye;
    
    array = g_ptr_array_new();
    process_ip_port_array(ip_port_array, TRUE, _avmon_get_target_set, array);

bye:
    if ( socketfd )
	close(socketfd);
    if ( ai )
	freeaddrinfo(ai);

    return array;
}

void
avmon_receive_get_ts(AVMONNode *node, int socketfd)
{
    GError *gerror = NULL;
    GPtrArray *ts_array = ts_to_array(node);

    msg_write_get_ts_reply(socketfd, ts_array, &gerror);
    if ( gerror )
	g_error_free(gerror);
}

//TODO: session IO should be outside avmon.c
#define BAD_LINE_ERROR 357
enum SessionIndicator {
    SESSION_START = 0,
    SESSION_END
};

enum SessionType {
    SESSION_UNDEFINED = 0,
    SESSION_MATCHED_START,
    SESSION_ONGOING,
    SESSION_UNMATCHED_START
};

typedef struct {
    GTimeVal *start;
    GTimeVal *end;
    enum SessionType type;
} Session;

typedef struct {
    GTimeVal t;
    GTimeVal tid;
    enum SessionIndicator indicator;
} SessionLine;

static void
session_free(Session *s)
{
    if ( s->start )
	g_free(s->start);
    if ( s->end )
	g_free(s->end);
    g_free(s);
}

static inline void
session_line_free(SessionLine *sl)
{
    g_free(sl);
}

//EOF == !SessionLine and !*gerror
static SessionLine *
read_sessions_line(GIOChannel *sessions, GError **gerror)
{
    SessionLine *sl = NULL;
    GIOStatus status;
    char *line = NULL, **split = NULL;
    
    if ( (status = g_io_channel_read_line(sessions, &line, NULL, NULL, gerror))
	 == G_IO_STATUS_EOF )
	return NULL;
    if ( *gerror )
	goto bye;
    
    split = g_strsplit(line, SESSION_RECORD_SEPARATOR, -1);
    if ( split[0] == NULL || split[1] == NULL || split[2] == NULL
	|| split[3] != NULL ) {
	g_set_error(gerror, AVMON_ERROR, BAD_LINE_ERROR, "not session file format");
	goto bye;
    }
    
    sl = g_new(SessionLine, 1);
    sl->t.tv_sec = (glong) g_ascii_strtod(split[2], NULL);
    sl->t.tv_usec = 0;
    if ( !g_ascii_strcasecmp(split[0], SESSION_RECORD_START) ) {
	sl->indicator = SESSION_START;
	sl->tid.tv_sec = sl->t.tv_sec;
	sl->tid.tv_usec = 0;
    } else if ( !g_ascii_strcasecmp(split[0], SESSION_RECORD_END) ) {
	sl->indicator = SESSION_END;
	sl->tid.tv_sec = (glong) g_ascii_strtod(split[1], NULL);
	sl->tid.tv_usec = 0;
    } else
	g_set_error(gerror, AVMON_ERROR, BAD_LINE_ERROR, "bad session indicator");
    
bye:
    if ( line )
	g_free(line);
    if ( split )
	g_strfreev(split);
    
    return sl;
}

/**
 * only use returned Session if SESSION_MATCHED_START or
 * SESSION_ONGOING
 */
static Session *
session_first(const char *sessions_fname, GError **gerror)
{
    Session *first = NULL;
    SessionLine *sl = NULL;
    GIOChannel *sessions = NULL;
    
    if ( !(sessions = g_io_channel_new_file(sessions_fname, "r", gerror)) )
	goto bye;

    first = g_new(Session, 1);
    first->type = SESSION_UNDEFINED;
    first->start = NULL;
    first->end = NULL;
    
    for ( ; ; ) {
	sl = read_sessions_line(sessions, gerror);
	if ( !sl && !*gerror ) {
	    if ( first->type == SESSION_UNMATCHED_START )
		first->type = SESSION_ONGOING;
	    goto bye; //EOF
	}
	if ( *gerror ) {
	    first->type = SESSION_UNDEFINED;
	    goto bye;
	}
	
	switch ( first->type ) {
	case SESSION_UNDEFINED:
	    if ( sl->indicator == SESSION_START ) {
		first->type = SESSION_UNMATCHED_START;
		first->start = g_new(GTimeVal, 1);
		first->start->tv_sec = sl->t.tv_sec;
		first->start->tv_usec = 0;
	    }
	    session_line_free(sl);
	    break;
	case SESSION_UNMATCHED_START:
	    if ( sl->indicator == SESSION_END &&
		 sl->tid.tv_sec == first->start->tv_sec ) {
		first->type = SESSION_MATCHED_START;
		first->end = g_new(GTimeVal, 1);
		first->end->tv_sec = sl->t.tv_sec;
		first->end->tv_usec = 0;
		
		goto bye;
	    }

	    if ( sl->indicator == SESSION_START ) {
		first->start->tv_sec = sl->t.tv_sec;
		first->start->tv_usec = 0;
	    } else {
		g_free(first->start);
		first->start = NULL;
		first->type = SESSION_UNDEFINED;
	    }

	    session_line_free(sl);
	    
	    break;
	}
    }
bye:
    if ( sl )
	session_line_free(sl);
    if ( sessions )
	g_io_channel_close(sessions);
    
    return first;
}

/**
 * Only returns well defined sessions, i.e., with START and END, or the ONGOING one
 * returns Session == NULL && !*gerror if there isn't next
 */
static Session *
session_next(const char *sessions_fname, Session *current, GError **gerror)
{
    Session *next = NULL;
    SessionLine *sl = NULL;
    GIOChannel *sessions = NULL;

    if ( !current ) {
	next = session_first(sessions_fname, gerror);
	if ( *gerror ) {
	    session_free(next);
	    next = NULL;
	    g_set_error(gerror, AVMON_ERROR, BAD_LINE_ERROR, "broken session file");
	}
	
	goto bye;
    }

    if ( current->type == SESSION_ONGOING )
	goto bye;

    if ( !(sessions = g_io_channel_new_file(sessions_fname, "r", gerror)) )
	goto bye;

    next = g_new(Session, 1);
    next->type = SESSION_UNDEFINED;
    next->start = NULL;
    next->end = NULL;

    for ( ; ; ) {
	sl = read_sessions_line(sessions, gerror);
	if ( !sl && !*gerror ) {
	    if ( next->type == SESSION_UNMATCHED_START )
		next->type = SESSION_ONGOING;
	    goto bye;
	}
	if ( *gerror )
	    goto bye;

	if ( sl->t.tv_sec <= current->start->tv_sec ) {
	    session_line_free(sl);

	    if ( next->type != SESSION_UNDEFINED ) {
		//br0k3n session file, or misconfigured host, or??
		next->type = SESSION_UNDEFINED;
		if ( next->start ) {
		    g_free(next->start);
		    next->start = NULL;
		}
	    }

	    continue;
	}

	switch ( next->type ) {
	case SESSION_UNDEFINED:
	    if ( sl->indicator == SESSION_START ) {
		next->type = SESSION_UNMATCHED_START;
		next->start = g_new(GTimeVal, 1);
		next->start->tv_sec = sl->t.tv_sec;
		next->start->tv_usec = 0;
	    }
	    session_line_free(sl);
	    break;
	case SESSION_UNMATCHED_START:
	    if ( sl->indicator == SESSION_END &&
		 sl->tid.tv_sec == next->start->tv_sec ) {
		next->type = SESSION_MATCHED_START;
		next->end = g_new(GTimeVal, 1);
		next->end->tv_sec = sl->t.tv_sec;
		next->end->tv_usec = 0;
		
		goto bye;
	    }

	    if ( sl->indicator == SESSION_START ) {
		next->start->tv_sec = sl->t.tv_sec;
		next->start->tv_usec = 0;
	    } else {
		g_free(next->start);
		next->start = NULL;
		next->type = SESSION_UNDEFINED;
		
	    }

	    session_line_free(sl);
	    
	    break;
	}
    }
    
bye:
    if ( next )
	if ( next->type != SESSION_ONGOING
	     && next->type != SESSION_MATCHED_START ) {
	    session_free(next);
	    next = NULL;
	}
    if ( sl )
	session_line_free(sl);
    if ( sessions )
	g_io_channel_close(sessions);
    
    return next;
}

/*
static Session *
session_for_event(const char *sessions_fname, const GTimeVal *event_time,
		  GError **gerror)
{
    Session *s = NULL;
    SessionLine *sl = NULL, *previous = NULL;
    GIOChannel *sessions = NULL;
    
    if ( !(sessions = g_io_channel_new_file(sessions_fname, "r", gerror)) )
	goto bye;
    
    s = g_new(Session, 1);
    s->start = NULL;
    s->end = NULL;
    s->type = SESSION_UNDEFINED;
    
    for ( ; ; ) {
	sl = read_sessions_line(sessions, gerror);
	
	if ( !sl && !*gerror ) {
	    if ( s->start )
		s->type = SESSION_ONGOING;
	    break; //EOF
	}
	if ( *gerror )
	    goto bye;
	
	if ( sl->t.tv_sec <= event_time->tv_sec ) {
	    switch ( sl->indicator ) {
	    case SESSION_START:
		if ( !s->start )
		    s->start = g_new(GTimeVal, 1);

		s->start->tv_sec = sl->t.tv_sec;
		s->start->tv_usec = 0;
		
		session_line_free(sl); sl = NULL;
		
		break;
	    case SESSION_END:
		if ( !s->start ) {
		    g_free(s->start);
		    s->start = NULL;
		} else if ( sl->t.tv_sec == event_time->tv_sec ) {
		    s->end = g_new(GTimeVal, 1);
		    s->end->tv_sec = sl->t.tv_sec;
		    s->end->tv_usec = 0;

		    s->type = SESSION_MATCHED_START;
		    
		    goto bye;
		}
		break;
	    }
	} else {
	    switch ( sl->indicator ) {
	    case SESSION_START:
		if ( !s->start ) {
		    //this session file has no corresponding session for the event,
		    //session file must be broken
		    goto bye;
		} else {
		    //dirty shutdown found
		    s->type = SESSION_UNMATCHED_START;
		    goto bye;
		}
		break;
	    case SESSION_END:
		if ( !s->start ) {
		    //no corresponding session for the event,
		    //session file must be broken
		    goto bye;
		} else {
		    s->end = g_new(GTimeVal, 1);
		    s->end->tv_sec = sl->t.tv_sec;
		    s->end->tv_usec = 0;

		    s->type = SESSION_MATCHED_START;
		    
		    goto bye;
		}
		break;
	    }
	}
    }
bye:
    if ( *gerror )
	if ( s ) {
	    session_free(s);
	    s = NULL;
	}
    if ( sl )
	session_line_free(sl);
    if ( sessions )
	g_io_channel_close(sessions);
    
    return s;
}
*/

//TODO: "raw availability" IO should be outside avmon.c
typedef struct {
    GTimeVal t;
    glong period;
} RawAvLine;

//EOF == !RawAvLine and !*gerror
static RawAvLine *
read_raw_av_line(GIOChannel *av_file, GError **gerror)
{
    RawAvLine *ral = NULL;
    GIOStatus status;
    char *line = NULL, **split = NULL;
    
    if ( (status = g_io_channel_read_line(av_file, &line, NULL, NULL, gerror))
	 == G_IO_STATUS_EOF )
	return NULL;
    if ( *gerror )
	goto bye;
    
    split = g_strsplit(line, AV_OUTPUT_SEPARATOR, -1);
    if ( split[0] == NULL || split[1] == NULL || split[2] != NULL ) {
	g_set_error(gerror, AVMON_ERROR, BAD_LINE_ERROR, "wrong file format");
	goto bye;
    }
    
    ral = g_new(RawAvLine, 1);
    ral->t.tv_sec = (glong) g_ascii_strtod(split[0], NULL);
    ral->t.tv_usec = 0;
    ral->period = (glong) g_ascii_strtod(split[1], NULL);
    
bye:
    if ( line )
	g_free(line);
    if ( split )
	g_strfreev(split);
    
    return ral;
}

static double
av_raw_for_session(const char *raw_fname, const Session *s, 
		   gboolean seen_before, GError **gerror)
{
    RawAvLine *ral = NULL;
    GIOChannel *raw = NULL;
    double av = -1.0, i;
    glong max_pongs, last, period;

    if ( !(raw = g_io_channel_new_file(raw_fname, "r", gerror)) )
	goto bye;
    
    //find first within session
    for ( ; ; ) {
	ral = read_raw_av_line(raw, gerror);
	if ( !ral && !*gerror ) {
	    if ( seen_before )
		av = 0.0;
	    goto bye;
	}
	if ( *gerror )
	    goto bye;
	if ( ral->t.tv_sec >= s->start->tv_sec ) {
	    if ( s->type == SESSION_MATCHED_START ) {
		if ( ral->t.tv_sec > s->end->tv_sec ) {
		    if ( seen_before )
			av = 0.0;
		    goto bye;
		}
	    }
	    //ONGOING or ral->t.tv_sec <= s->end->tv_sec :
	    period = ral->period;
	    last = ral->t.tv_sec;
	    break;
	}
	g_free(ral);
    }

    //IMPORTANT: ASSUMMING THAT PING PERIOD DOES NOT CHANGE WITHIN A SESSION
    if ( s->type == SESSION_MATCHED_START ) {
	if ( seen_before )
	    max_pongs = (s->end->tv_sec - s->start->tv_sec) / period;
	else {
	    max_pongs = (s->end->tv_sec - last) / period;
	    max_pongs++;
	}
	for ( i = 1.0; ; ) {
	    ral = read_raw_av_line(raw, gerror);
	    if ( !ral && !*gerror )
		break;
	    if ( *gerror )
		goto bye;
	    if ( ral->t.tv_sec > s->end->tv_sec ) {
		g_free(ral);
		break;
	    }
	    i += 1.0;
	    g_free(ral);
	}
    } else { //ONGOING
	glong first = last;
	for ( i = 1.0; ; ) {
	    ral = read_raw_av_line(raw, gerror);
	    if ( !ral && !*gerror )
		break;
	    if ( *gerror )
		goto bye;
	    i += 1.0;
	    last = ral->t.tv_sec;
	    g_free(ral);
	}
	//TODO: better way to compute ongoing sessions
	//TODO: get the raw file to include last ping time?
	if ( seen_before )
	    max_pongs = (last - s->start->tv_sec) / period;
	else {
	    //take care of a new node that first appeared during
	    //an ongoing session
	    max_pongs = (last - first) / period;
	    max_pongs++;
	}
    }

    av = i / (double) max_pongs;

bye:
    if ( raw )
	g_io_channel_close(raw);

    return av;
}

double
avmon_av_from_full_raw_availability(const char *raw_fname, GError **gerror)
{
    g_assert(raw_fname != NULL);
    
    double av = 0.0, tmp_av;
    Session *s = NULL, *s_old = NULL;
    gboolean seen_before = FALSE;
    int i;
    char *mon_sessions_fname = sessions_fname_from_raw_av_fname(raw_fname);

    for ( i = 0; ; ) {
	s_old = s;
	s = session_next(mon_sessions_fname, s_old, gerror);
	if ( s_old ) {
	    session_free(s_old);
	    s_old = NULL;
	}
	if ( *gerror ) {
	    av = -1.0;
	    goto bye;
	}
	if ( !s )
	    break;

	tmp_av = av_raw_for_session(raw_fname, s, seen_before, gerror);
	if ( *gerror ) {
	    av = -1.0;
	    goto bye;
	}

	if ( seen_before ) {
	    av += tmp_av;
	    i++;
	} else if ( tmp_av > 0 ) {
	    av = tmp_av;
	    i++;
	    seen_before = TRUE;

	    //tmp_av == -1.0 if not seen before and no trace of the target in a session
	}
    }

    if ( i )
	av = av / ((double) i);

bye:
    if ( s )
	session_free(s);
    
    return av;
}

typedef void (*PIPDAFunc) (const char *ip, const char *port, const char *data,
			   void *pipda_data);

static void
process_ip_port_data_array(GPtrArray *array, gboolean destroy, PIPDAFunc pipda_func,
			   void *pipda_data)
{
    int i;
    char *ip, *port, *data;
    
    for ( i = 0; i < array->len; i+= 3 ) {
	ip = g_ptr_array_index(array, i);
	port = g_ptr_array_index(array, i + 1);
	data = g_ptr_array_index(array, i + 2);
	
	pipda_func(ip, port, data, pipda_data);
	
	if ( destroy ) {
	    g_free(ip);
	    g_free(port);
	    g_free(data);
	}
    }

    if ( destroy )
	g_ptr_array_free(array, TRUE);
}

static void
_avmon_get_last_heard_of_target_set(const char *ip, const char *port, const char *data,
				    void *array)
{
    AVMONPeer *peer = peer_new(ip, port);
    peer->last_heard_of = (glong) g_ascii_strtod(data, NULL);
    g_ptr_array_add((GPtrArray *) array, peer);
}


GPtrArray *
avmon_get_last_heard_of_target_set(const char *monitor, const char *monitor_port,
				   GError **gerror)
{
    g_assert(monitor != NULL);
    g_assert(monitor_port != NULL);
    
    GPtrArray *array = NULL, *ip_port_data_array;
    int socketfd;
    struct addrinfo *ai = net_char_to_addrinfo(monitor, monitor_port, gerror);
    if ( !ai )
	return NULL;
    
    if ( (socketfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))
	 == -1 ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_LAST_HEARD_OF,
			     "couldn't create a socket");
	socketfd = 0;
	goto bye;
    }

    if ( net_connect_nb(socketfd, ai->ai_addr, ai->ai_addrlen, 5 /*TODO*/, 0, gerror) ) {
	util_set_error_errno(gerror, AVMON_ERROR, AVMON_ERROR_GET_LAST_HEARD_OF,
			     "couldn't connect to monitor");
	goto bye;
    }

    if ( msg_send_get_last_heard_of_ts(socketfd, gerror) )
	goto bye;
    
    if ( msg_read_get_last_heard_of_ts_reply(socketfd, gerror) )
	goto bye;

    if ( !(ip_port_data_array = msg_read_last_heard_of_ts(socketfd, gerror)) )
	goto bye;
    
    array = g_ptr_array_new();
    process_ip_port_data_array(ip_port_data_array, TRUE, 
			       _avmon_get_last_heard_of_target_set, array);

bye:
    if ( socketfd )
	close(socketfd);
    if ( ai )
	freeaddrinfo(ai);
    
    return array;
}

void
avmon_receive_get_last_heard_of_ts(AVMONNode *node, int socketfd)
{
    GError *gerror = NULL;
    GPtrArray *ts_array = ts_to_array(node);
    GPtrArray *data_array = g_ptr_array_new();
    int i;
    AVMONPeer *peer;

    for ( i = 0; i < ts_array->len; i++ ) {
	peer = g_ptr_array_index(ts_array, i);
	g_ptr_array_add(data_array,
			g_strdup_printf("%lu", avmon_peer_mon_last_heard_of(peer)));
    }
    
    msg_write_get_last_heard_of_ts_reply(socketfd, ts_array, data_array, &gerror);
    if ( gerror )
	g_error_free(gerror);

    for ( i = 0; i < ts_array->len; i++ )
	g_free(g_ptr_array_index(data_array, i));
    g_ptr_array_free(data_array, TRUE);
}
