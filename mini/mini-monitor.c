/*
 *  AVMON mini-monitor
 *  Copyright 2007, 2008 Ramses Morales
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
 */

/**
 * \file mini-monitor.c
 * \author Ramses Morales
 * \version $Id: mini-monitor.c,v 1.3 2008/05/31 00:23:38 ramses Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <glib.h>

#include <avmon/avmon.h>

#define CONF_GROUP_MINI_MONITOR "mini monitor"
#define CONF_log                "log"
#define CONF_pipe_name          "pipe_name"
#define CONF_K                  "K"
#define CONF_N                  "N"

#define FIFO_COMMAND_BEGINS '|'
#define FIFO_COMMAND_ENDS   '$'

const char *FIFO_COMMAND_START = "start";
const char *FIFO_COMMAND_STOP = "stop";
const char *FIFO_COMMAND_QUIT = "quit";

static AVMONNode *node;
static int K, N;

static char *conf = NULL;
static char *pipe_name = NULL;
static char *log_name = NULL;
static FILE *log = NULL;
static int n_pipe, ignore_me;

static GHashTable *exec_table = NULL;
typedef void (*Func) (void);

static void
log_func(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message,
	 gpointer user_data)
{
    GString *string = g_string_new("");
    struct timeval tv;
    char timestamp[128];

    gettimeofday(&tv, NULL);
    ctime_r(&tv.tv_sec, timestamp);
    timestamp[strlen(timestamp) - 1] = '\0';

    g_string_append_printf(string, "[%s] ", timestamp);
    
    if ( log_domain )
	g_string_append_printf(string, "%s: ", log_domain);

    switch ( log_level ) {
    case G_LOG_LEVEL_ERROR:
	g_string_append_printf(string, "error: ");
	break;
    case G_LOG_LEVEL_CRITICAL:
	g_string_append_printf(string, "critical: ");
	break;
    case G_LOG_LEVEL_WARNING:
	g_string_append_printf(string, "warning: ");
	break;
    case G_LOG_LEVEL_MESSAGE:
	g_string_append_printf(string, "message: ");
	break;
    case G_LOG_LEVEL_INFO:
	g_string_append_printf(string, "info: ");
	break;
    case G_LOG_LEVEL_DEBUG:
	g_string_append_printf(string, "debug: ");
	break;
    }

    g_string_append_printf(string, "%s\n", message);

    fprintf(log, "%s", string->str);
    g_string_free(string, TRUE);
    
    if ( log_level == G_LOG_LEVEL_ERROR )
	fclose(log);
}

static void
do_start(void)
{
    GError *gerror = NULL;
    
    if ( node ) {
#ifdef DEBUG
	g_debug("node already running?");
#endif	
	return;
    }

    node = avmon_start(conf, K, N, &gerror);
    if ( !node ) {
	fprintf(stderr, "Couldn't start AVMON\n");
	if ( gerror )
	    fprintf(stderr, "%s\n", gerror->message);
	else
	    fprintf(stderr, "Unknown reason\n");
	fflush(log);
	if ( g_error_matches(gerror, AVMON_ERROR, AVMON_ERROR_INTRODUCER_CLOSED) )
	    g_error_free(gerror);
	else
	    exit(1);
    }
}

static void
do_stop(void)
{
    GError *gerror = NULL;
    
    if ( !node )
	return;

    avmon_stop(node, &gerror);
    node = NULL;

    if ( gerror ) {
	fprintf(stderr, "Error stoping AVMON: %s\n", gerror->message);
	exit(1);
    }
}

static void
do_quit(void)
{
    if ( node ) 
	do_stop();

    close(n_pipe);
    close(ignore_me);

    exit(0);
}

static gboolean
parse_conf(const gchar *option_name, const gchar *value, gpointer null_data,
	   GError **gerror)
{
    if ( access(value, R_OK) ) {
	g_set_error(gerror, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, 
		    "Problem with configuration file (%s): %s", value,
		    strerror(errno));
	return FALSE;
    }
    conf = g_strdup(value);
    
    return TRUE;
}

static void
configuration(void)
{
    GError *gerror = NULL;
    GKeyFile *gkf = g_key_file_new();
    
    if ( !g_key_file_load_from_file(gkf, conf, G_KEY_FILE_NONE, &gerror) ) {
	fprintf(stderr, "Could not load configuration file %s: %s\n", conf,
		gerror->message);
	exit(1);
    }

    if ( g_key_file_has_key(gkf, CONF_GROUP_MINI_MONITOR, CONF_log, &gerror ) ) {
	log_name = g_key_file_get_string(gkf, CONF_GROUP_MINI_MONITOR, CONF_log, 
					 &gerror);
	if ( gerror ) {
	    fprintf(stderr, "%s\n", gerror->message);
	    exit(1);
	}
	if ( strlen(log_name) == 0 ) {
	    g_free(log_name);
	    log_name = NULL;
	}
    } else {
	log_name = NULL;
    }

    pipe_name = g_key_file_get_string(gkf, CONF_GROUP_MINI_MONITOR, CONF_pipe_name,
				      &gerror);
    if ( gerror ) {
	fprintf(stderr, "%s\n", gerror->message);
	exit(1);
    }

    K = g_key_file_get_integer(gkf, CONF_GROUP_MINI_MONITOR, CONF_K, &gerror);
    if ( gerror ) {
	fprintf(stderr, "%s\n", gerror->message);
	exit(1);
    }
    
    N = g_key_file_get_integer(gkf, CONF_GROUP_MINI_MONITOR, CONF_N, &gerror);
    if ( gerror ) {
	fprintf(stderr, "%s\n", gerror->message);
	exit(1);
    }
    
    g_key_file_free(gkf);
}

static void
loop(void)
{
    GError *gerror = NULL;
    char buff[8];
    GString *string = g_string_new("");
    int count, state = 0;
    Func func = NULL;

    for ( ; ; ) {
	if ( (count = read(n_pipe, buff, 1)) == -1 )
	    g_error("Problem reading fifo %s\n", strerror(errno));
	if ( !count )
	    g_error("Closed fifo?\n");

	buff[count] = '\0';
	switch ( state ) {
	case 0: //waiting for a new command
	    if ( buff[0] == FIFO_COMMAND_BEGINS ) {
		g_string_truncate(string, 0);
		state = 1;
	    }
	    break;
	case 1: //reading the command
	    if ( buff[0] == FIFO_COMMAND_ENDS ) {
		func = g_hash_table_lookup(exec_table, string->str);
		if ( func )
		    func();
		else
		    g_debug("unknown command: %s", string->str);
		state = 0;
	    } else if ( g_ascii_isprint(buff[0]) ) {
		g_string_append_c(string, buff[0]);
	    } else {
		state = 0;
	    }
	    break;
	}
    }
}

int
main(int argc, char **argv)
{
    GError *gerror = NULL;
    GOptionContext *context;
    GOptionEntry entries[] = {
	{"conf", 'c', 0, G_OPTION_ARG_CALLBACK, parse_conf, "Configuration filename",
	 NULL},
	{ NULL }
    };

    node = NULL;

    context = g_option_context_new("-- simple avmon app");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_parse(context, &argc, &argv, &gerror);
    if ( gerror ) {
	fprintf(stderr, "%s\n", gerror->message);
	exit(1);
    }
    g_option_context_free(context);
    if ( !conf ) {
	fprintf(stderr, "Please specify configuration filename\n");
	exit(1);
    }

    configuration();

    // log stuff --->
    if ( log_name ) {
	if ( !(log = fopen(log_name, "a")) ) {
	    fprintf(stderr, "Couln't open %s: %s\n", log_name,
		    strerror(errno));
	    exit(1);
	}
	g_log_set_default_handler(log_func, NULL);
    }
    // <--- log stuff

    // execution table --->
    exec_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    g_hash_table_insert(exec_table, FIFO_COMMAND_START, do_start);
    g_hash_table_insert(exec_table, FIFO_COMMAND_STOP, do_stop);
    g_hash_table_insert(exec_table, FIFO_COMMAND_QUIT, do_quit);
    // <--- execution table

    if ( mkfifo(pipe_name, S_IRUSR | S_IWUSR) && (errno != EEXIST) ) {
	fprintf(stderr, "Problem with fifo %s: %s", pipe_name, 
		strerror(errno));
	exit(1);
    }

    n_pipe = open(pipe_name, O_RDONLY);
    ignore_me = open(pipe_name, O_WRONLY);
    if ( n_pipe == -1 ) {
	fprintf(stderr, "Couldn't read pipe: %s\n", strerror(errno));
	exit(1);
    }
    g_free(pipe_name);

    loop();
    
    return 0;
}
