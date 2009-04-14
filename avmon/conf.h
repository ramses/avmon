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
 * \file conf.h
 * \author Ramses Morales
 * \version
 */

#ifndef __AVMON_CONF_H__
#define __AVMON_CONF_H__

#include <avmon/common.h>

AVMON_BEGIN_DECLS

#define CONF_ERROR       conf_error_quark()
#define CONF_ERROR_VALUE 1

enum ConfSessionFixMethod {
    CONF_SESSION_FIX_NONE = 0,
    CONF_SESSION_FIX_CURRENT_TIME,
    CONF_SESSION_FIX_YOUNGUEST_RAW_AV
};

typedef struct _Conf Conf;

Conf *conf_load(const char *fname, GError **gerror);
void conf_free(Conf *conf);
int conf_get_listener_tcp_udp_port(Conf *conf);
char *conf_get_introducer_name(Conf *conf); //remember to free returned string
int conf_get_introducer_port(Conf *conf);
int conf_get_protocol_period(Conf *conf);
int conf_get_monitoring_period(Conf *conf);
char *conf_get_default_av_output_prefix(Conf *conf);
int conf_get_introducer_timeout(Conf *conf);
/**
 * value of host_ip key
 * 
 * @param[in] conf
 * @return value of host_ip, or NULL if it was not defined. Don't forget to free
 * after use.
 */
char *conf_get_host_ip(Conf *conf);
gboolean conf_enable_forgetful_pinging(Conf *conf);
ConfSessionFixMethod conf_get_session_fix_method(Conf *conf);

AVMON_END_DECLS

#endif /* __AVMON_CONF_H__ */

