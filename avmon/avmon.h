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
 * \file avmon.h
 * \author Ramses Morales
 * \version
 */
 
#ifndef __AVMON_H__
#define __AVMON_H__

#include <avmon/common.h>

AVMON_BEGIN_DECLS

#define AVMON_ERROR        avmon_error_quark()
#define AVMON_ERROR_JOIN   1
#define AVMON_ERROR_START  2
#define AVMON_ERROR_NODE   3
#define AVMON_ERROR_GET_PS 4
#define AVMON_ERROR_STOP   5
#define AVMON_ERROR_INTRODUCER_CLOSED 6
#define AVMON_ERROR_GET_TS 7
#define AVMON_ERROR_GET_LAST_HEARD_OF 8

#define AVMON_INTRODUCER_NONE "none"

typedef struct _AVMONNode AVMONNode;
typedef struct _AVMONPeer AVMONPeer;

typedef void (*AVMONFunc) (AVMONNode *node, const char *target_ip, 
			   const char *target_port);
typedef void (*AVMONReplyFunc) (AVMONNode *node, AVMONPeer *peer);
typedef void (*AVMONAvOutputFunc) (AVMONNode *node, AVMONPeer *peer);

/**
 * Use to create an AVMON node, and join the monitoring overlay.
 *
 * \param[in] conf_file Name of file holding AVMON's configuration parameters.
 * \param[in] K System-wide constant.
 * \param[in] N System-wide constant.
 * \param[out] gerror If something goes wrong gerror will be non-NULL.
 * \return NULL if error, pointer to AVMONNode if OK.
 */
AVMONNode *avmon_start(const char *conf_file, int K, int N, GError **gerror);

/**
 * Use to make an AVMON node stop and leave the overlay.
 *
 * @param[in,out] node The node we want to stop. The function will free the
 * memory used by node, and node will be set to NULL.
 * @param[out] gerror If something goes wrong, gerror will be non-NULL.
 * @return 0 if OK.
 */
int avmon_stop(AVMONNode *node, GError **gerror);

/**
 * IP address of an AVMONPeer
 *
 * @param[in] peer
 * @return peer's ip. Don't forget to free after use.
 */
char *avmon_peer_get_ip(const AVMONPeer *peer);

/**
 * Port address of an AVMONPeer
 *
 * @param[in] peer
 * @return peer's port. Don't forget to free after use.
 */
char *avmon_peer_get_port(const AVMONPeer *peer);

/**
 * Only use this after calling avmon_get_last_heard_of_target_set()
 */
glong avmon_peer_last_heard_of(const AVMONPeer *peer);

/**
 * returns the number of seconds the monitor last heard of the given peer
 *
 * @param[in] peer
 * @return seconds
 */
glong avmon_peer_mon_last_heard_of(const AVMONPeer *peer);

/**
 * Ask an AVMON node for its Ping Set.
 *
 * \param[in] target Host name or ip of avmon node.
 * \param[in] target_port AVMON port of avmon node.
 * \param[out] gerror If something goes wrong, *gerror will be non-NULL.
 * \return Returns GPtrArray populated with AVMONPeer. Can be empty. 
 * NULL only if error. Free array and elements after use.
 */
GPtrArray *avmon_get_ping_set(const char *target, const char *target_port,
			      GError **gerror);

/**
 * Ask an AVMON node for its Target Set.
 *
 * \param[in] monitor Host name or ip of avmon node.
 * \param[in] monitor_port AVMON port of avmon node.
 * \param[out] gerror If something goes wrong, *gerror will be non-NULL.
 * \return Returns GPtrArray populated with AVMONPeer. Can be empty. 
 * NULL only if error. Free array and elements after use.
 */
GPtrArray *avmon_get_target_set(const char *monitor, const char *monitor_port,
				GError **gerror);

/**
 * Use this function to request a number of monitors to provide the raw
 * availability for a specific AVMON node.
 *
 * \param monitors[in] The list of monitors to query.
 * \param timeout[in] The number of seconds to wait for a monitor to answer. Must be
 * larger than 0.
 * \param target[in] The hostname or ip-address of the AVMON node.
 * \param target_port[in] The port number of the AVMON node.
 * \param gerror[out] If the function fails, *gerror will be non-NULL.
 * \return The resulting GPtrArray will be populated with the file-names where
 * the raw measurements are stored. The index numbers in this array will correspond
 * to the index numbers in the \code monitors \endcode array. Failed requests
 * are represented by a NULL entry. If the function fails, it returns NULL.
 */
GPtrArray *avmon_get_raw_availability(const GPtrArray *monitors, int timeout,
				      const char *target, 
				      const char *target_port, GError **gerror);

/**
 * Computes availability of process B measured by process A during its sessions.
 *
 * \param raw_fname[in] Raw availability of B as measured by A.
 * \param gerror[out] If the function fails, *gerror will be non-NULL.
 * \return a value in [0.0, 1.0] or -1.0 if *gerror != NULL.
 */
double avmon_av_from_full_raw_availability(const char *raw_fname, GError **gerror);

/**
 *
 * \param[in] monitor Host name or ip of avmon node.
 * \param[in] monitor_port avmon port of avmon node.
 * \param[out] gerror If something goes wrong, *gerror will be non-NULL.
 * \return Returns GPtrArray populated with AVMONPeer. Can be empty. NULL only
 * if error. Call avmon_peer_last_heard_of on each AVMONPeer. Free array and elements
 * after use.
 */
GPtrArray *avmon_get_last_heard_of_target_set(const char *monitor, const char *monitor_port,
					      GError **gerror);

AVMON_END_DECLS

#endif /* __AVMON_H__ */
