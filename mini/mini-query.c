/*
 *  AVMON mini-query
 *  Copyright 2007, 2008, 2009 Ramses Morales.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *  Neither the names of Distributed Protocols Research Group, University of
 *  Illinois at Urbana-Champaign, nor the names of its contributors may be used
 *  to endorse or promote products derived from this Software without specific
 *  prior written permission.
 */

/**
 * \file mini-query.c
 * \author Ramses Morales
 * \version
 */

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "avmon.h"
#include "net.h"

static gboolean query_ping_set = FALSE;
static gboolean query_target_set = FALSE;
static gboolean query_raw_av = FALSE;

static char *target_host = NULL;
static char *target_port = NULL;

static void
av_from_raw_availabilities(GPtrArray *raw_availabilities, GError **gerror)
{
    int i;
    
    for ( i = 0; i < raw_availabilities->len; i++ ) {
	avmon_av_from_full_raw_availability(g_ptr_array_index(raw_availabilities, i),
					    gerror);
	if ( *gerror ) {
	    fprintf(stderr, "%s\n", (*gerror)->message);
	    break;
	}
    }
}

int
main(int argc, char **argv)
{
    int i;
    AVMONPeer *peer = NULL;
    char **target = NULL;
    GError *gerror = NULL;
    GPtrArray *set = NULL, *raw_availabilities = NULL;
    GOptionContext *context;
    GOptionEntry entries[] = {
	{"ping-set", 'p', 0, G_OPTION_ARG_NONE, &query_ping_set,
	 "Query ping set", NULL},
	{"target-set", 't', 0, G_OPTION_ARG_NONE, &query_target_set,
	 "Query target set", NULL},
	{"raw-av", 'r', 0, G_OPTION_ARG_NONE, &query_raw_av,
	 "Query raw availability", NULL},
	{ NULL }
    };

    context = g_option_context_new("TARGET_HOST:PORT - Tool to query nodes in an AVMON overlay.");
    g_option_context_set_summary(context, "Copyright (C) 2007, 2008 Ramses Morales"
				 "\nhttp://avmon.sf.net");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_parse(context, &argc, &argv, &gerror);
    if ( gerror ) {
	fprintf(stderr, "%s\n\n%s\n", gerror->message, 
		g_option_context_get_help(context, TRUE, NULL));
	exit(1);
    }
    if ( argc != 2 ) {
	fprintf(stderr, "%s\n", g_option_context_get_help(context, TRUE, NULL));
	exit(1);
    }

    target = g_strsplit(argv[1], ":", 2);
    target_host = target[0];
    target_port = target[1];
    if ( !target_port ) {
	fprintf(stderr, "%s\n", g_option_context_get_help(context, TRUE, NULL));
	exit(1);
    }
    g_option_context_free(context);

    if ( query_ping_set || query_raw_av ) {
	printf("Asking %s for its ping set... \n", argv[1]);
	if ( !(set = avmon_get_ping_set(target_host, target_port, &gerror)) ) {
	    fprintf(stderr, "Could not query ping set: %s\n", gerror->message);
	    exit(1);
	}
    }

    if ( query_ping_set ) {
	printf("%s's ping set:\n", argv[1]);
	for ( i = 0; i < set->len; i++ ) {
	    peer = g_ptr_array_index(set, i);
	    printf("%s:%s\n", avmon_peer_get_ip(peer), avmon_peer_get_port(peer));
	}
    }

    if ( query_raw_av ) {
	if ( !set->len ) {
	    printf("Can't query availability. %s's ping set is empty\n", argv[1]);
	} else {
	    if ( !(raw_availabilities = 
		   avmon_get_raw_availability(set, 10 /* TODO */,
					      target_host, target_port,
					      &gerror)) ) {
		fprintf(stderr, "Could not query raw availability: %s\n",
			gerror->message);
		exit(1);
	    }
	    printf("%s's raw availability stored at:\n", argv[1]);
	    for ( i = 0; i < raw_availabilities->len; i++ ) {
		if ( !g_ptr_array_index(raw_availabilities, i) )
		    printf("No Answer\n");
		else
		    printf("%s\n", g_ptr_array_index(raw_availabilities, i));
	    }
	    av_from_raw_availabilities(raw_availabilities, &gerror);
	}
    }

    if ( query_target_set ) {
	printf("Asking %s for its target set... \n", argv[1]);
	if ( !(set = avmon_get_target_set(target_host, target_port, &gerror)) ) {
	    fprintf(stderr, "Could not query target set: %s\n", gerror->message);
	    exit(1);
	}
	
	printf("%s's target set:\n", argv[1]);
	for ( i = 0; i < set->len; i++ ) {
	    peer = g_ptr_array_index(set, i);
	    printf("%s:%s\n", avmon_peer_get_ip(peer), avmon_peer_get_port(peer));
	}
    }

    return 0;
}
