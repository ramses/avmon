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
 * \file listener.h
 * \author Ramses Morales
 * \version $Id: listener.h,v 1.2 2008/06/04 16:41:07 ramses Exp $
 */
 
#ifndef __AVMON_LISTENER_H__
#define __AVMON_LISTENER_H__

#include <avmon/common.h>
#include <avmon/avmon.h>
#include <avmon/conf.h>

AVMON_BEGIN_DECLS

#define AVMON_LISTENER_ERROR           avmon_listener_error_quark()
#define AVMON_LISTENER_ERROR_START     1
#define AVMON_LISTENER_ERROR_START_TCP 2
#define AVMON_LISTENER_ERROR_START_UDP 3
#define AVMON_LISTENER_ERROR_STOP_UDP  4
#define AVMON_LISTENER_ERROR_STOP_TCP  5

typedef struct _AVMONListener AVMONListener;

AVMONListener *avmon_listener_start(AVMONNode *node, Conf *conf, GError **gerror);
int avmon_listener_stop(AVMONListener *al, GError **gerror);

AVMON_END_DECLS

#endif /* __AVMON_LISTENER_H__ */
