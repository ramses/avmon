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
 * \file conf.c
 * \author Ramses Morales
 * \version
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"

#define CONF_GROUP_INTRODUCER "introducer"
#define CONF_name             "name"
#define CONF_port             "port"
#define CONF_timeout          "timeout"

#define CONF_GROUP_LISTENER   "listener"
#define CONF_host_ip          "host_ip"
#define CONF_tcp_udp_port     "tcp_udp_port"

#define CONF_GROUP_PROTOCOL   "protocol"
#define CONF_period           "period"
#define CONF_enable_forgetful_pinging "enable_forgetful_pinging"

#define CONF_GROUP_MONITORING "monitoring"
//CONF_PERIOD
#define CONF_default_av_output_prefix  "default_av_output_prefix"

#define CONF_GROUP_SESSION               "session"
#define CONF_fix_missing_end_method      "fix_missing_end_method"
#define CONF_fix_method_younguest_raw_av "younguest_raw_av"
#define CONF_fix_method_current_time     "current_time"
#define CONF_fix_method_none             "none"

#define CONF_MAX_PORT         65535

GQuark
conf_error_quark(void)
{
    static GQuark quark = 0;
    
    if ( quark == 0 )
	quark = g_quark_from_static_string("conf-error-quark");
    
    return quark;
}

struct _Conf {
    char *introducer_name;
    int introducer_port;
    int introducer_timeout;

    int listener_tcp_udp_port;
    char *host_ip;

    int protocol_period;
    gboolean enable_forgetful_pinging;

    int monitoring_period;
    char *default_av_output_prefix;

    enum ConfSessionFixMethod csfm;
};

void
conf_free(Conf *conf)
{
    g_assert( conf != NULL );

    g_free(conf->introducer_name);
    g_free(conf->host_ip);
    g_free(conf->default_av_output_prefix);

    g_free(conf);
}

Conf *
conf_load(const char *fname, GError **gerror)
{
    GKeyFile *gkf = NULL;
    Conf *conf = g_new(Conf, 1);

    gkf = g_key_file_new();
    
    if ( !g_key_file_load_from_file(gkf, fname, G_KEY_FILE_NONE, gerror) )
        goto exit_with_error;

    conf = g_new(Conf, 1);
    conf->introducer_name = NULL;
    conf->default_av_output_prefix = NULL;
    conf->host_ip = NULL;
    
    // INTRODUCER CONF
    conf->introducer_name =
	g_key_file_get_string(gkf, CONF_GROUP_INTRODUCER, CONF_name, gerror);
    if ( *gerror )
	goto exit_with_error;
    
    conf->introducer_port = 
	g_key_file_get_integer(gkf, CONF_GROUP_INTRODUCER, CONF_port, gerror);
    if ( *gerror )
        goto exit_with_error;
    if ( conf->introducer_port > CONF_MAX_PORT ) {
	g_set_error(gerror, CONF_ERROR, CONF_ERROR_VALUE, "bad port value: %d",
		    conf->introducer_port);
	goto exit_with_error;
    }

    conf->introducer_timeout =
	g_key_file_get_integer(gkf, CONF_GROUP_INTRODUCER, CONF_timeout, gerror);
    if ( *gerror )
	goto exit_with_error;

    // LISTENER CONF
    conf->listener_tcp_udp_port =
	g_key_file_get_integer(gkf, CONF_GROUP_LISTENER, CONF_tcp_udp_port, gerror);
    if ( *gerror )
	goto exit_with_error;
    if ( conf->listener_tcp_udp_port > CONF_MAX_PORT ) {
	g_set_error(gerror, CONF_ERROR, CONF_ERROR_VALUE, "bad port value: %d",
		    conf->listener_tcp_udp_port);
	goto exit_with_error;
    }

    if ( g_key_file_has_key(gkf, CONF_GROUP_LISTENER, CONF_host_ip, gerror) ) {
	if ( *gerror )
	    goto exit_with_error;
	
	conf->host_ip =
	    g_key_file_get_string(gkf, CONF_GROUP_LISTENER, CONF_host_ip, gerror);
	if ( *gerror )
	    goto exit_with_error;

	{
	    struct in_addr blah;
	    if ( !inet_aton(conf->host_ip, &blah) ) {
		g_set_error(gerror, CONF_ERROR, CONF_ERROR_VALUE, "bad host_ip: %s",
			    conf->host_ip);
		goto exit_with_error;
	    }
	}
    }

    // JOIN CONF
    /*
    conf->join_weight =
	g_key_file_get_integer(gkf, CONF_GROUP_JOIN, CONF_weight, gerror);
    if ( *gerror )
	goto exit_with_error;
    */

    // PROTOCOL CONF
    conf->protocol_period = 
	g_key_file_get_integer(gkf, CONF_GROUP_PROTOCOL, CONF_period, gerror);
    if ( *gerror )
	goto exit_with_error;

    conf->enable_forgetful_pinging =
	g_key_file_get_boolean(gkf, CONF_GROUP_PROTOCOL,
			       CONF_enable_forgetful_pinging, gerror);
    if ( *gerror )
	goto exit_with_error;

    // MONITORING CONF
    conf->monitoring_period =
	g_key_file_get_integer(gkf, CONF_GROUP_MONITORING, CONF_period, gerror);
    if ( *gerror )
	goto exit_with_error;

    conf->default_av_output_prefix = 
	g_key_file_get_string(gkf, CONF_GROUP_MONITORING,
			      CONF_default_av_output_prefix, gerror);
    if ( *gerror )
	goto exit_with_error;

    //SESSION CONF
    if ( g_key_file_has_group(gkf, CONF_GROUP_SESSION) ) {
	gchar *method = g_key_file_get_string(gkf, CONF_GROUP_SESSION,
					      CONF_fix_missing_end_method, gerror);
	if ( !method )
	    conf->csfm = CONF_SESSION_FIX_NONE;
	else {
	    if ( !g_ascii_strcasecmp(method, CONF_fix_method_none) )
		conf->csfm = CONF_SESSION_FIX_NONE;
	    else if ( !g_ascii_strcasecmp(method, CONF_fix_method_younguest_raw_av) )
		conf->csfm = CONF_SESSION_FIX_YOUNGUEST_RAW_AV;
	    else if ( !g_ascii_strcasecmp(method, CONF_fix_method_current_time) )
		conf->csfm = CONF_SESSION_FIX_CURRENT_TIME;
	    else
		g_set_error(gerror, CONF_ERROR, CONF_ERROR_VALUE,
			    "bad session fix method %s\n", method);
	    g_free(method);
	}
    } else {
	conf->csfm = CONF_SESSION_FIX_NONE;
    }
        
    //
    g_key_file_free(gkf);
    
    return conf;

exit_with_error:
    if ( gkf )
	g_key_file_free(gkf);
    
    if ( conf->introducer_name )
	g_free(conf->introducer_name);
    if ( conf->default_av_output_prefix )
	g_free(conf->default_av_output_prefix);
    if ( conf->host_ip )
	g_free(conf->host_ip);
    
    g_free(conf);
    
    return NULL;
}

int
conf_get_listener_tcp_udp_port(Conf *conf)
{
    return conf->listener_tcp_udp_port;
}

char *
conf_get_introducer_name(Conf *conf)
{
    return g_strdup(conf->introducer_name);
}

int
conf_get_introducer_port(Conf *conf)
{
    return conf->introducer_port;
}

int
conf_get_introducer_timeout(Conf *conf)
{
    return conf->introducer_timeout;
}

int
conf_get_protocol_period(Conf *conf)
{
    return conf->protocol_period;
}

int
conf_get_monitoring_period(Conf *conf)
{
    return conf->monitoring_period;
}

char *
conf_get_default_av_output_prefix(Conf *conf)
{
    return g_strdup(conf->default_av_output_prefix);
}

char *
conf_get_host_ip(Conf *conf)
{
    if ( !conf->host_ip )
	return NULL;
    
    return g_strdup(conf->host_ip);
}

gboolean
conf_enable_forgetful_pinging(Conf *conf)
{
    return conf->enable_forgetful_pinging;
}

enum ConfSessionFixMethod
conf_get_session_fix_method(Conf *conf)
{
    return conf->csfm;
}
