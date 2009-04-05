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
 * \file messages.h
 * \author Ramses Morales
 * \version
 */

#ifndef __AVMON_MESSAGES_H__
#define __AVMON_MESSAGES_H__

#include <avmon/common.h>
#include <avmon/net.h>
#include <inttypes.h>

AVMON_BEGIN_DECLS

#define MSG_ERROR                                msg_error_quark()
#define MSG_ERROR_IDS                            1
#define MSG_ERROR_NOT_JOIN_REPLY                 2
#define MSG_ERROR_BAD_FORWARD                    3
#define MSG_ERROR_NOT_FETCH_REPLY                4
#define MSG_ERROR_NOT_HEAD                       5
#define MSG_ERROR_NOT_GET_PS_REPLY               6
#define MSG_ERROR_NOT_GET_RAW_AVAILABILITY_REPLY 7
#define MSG_ERROR_GET_RAW_AVAILABILITY_REPLY     8
#define MSG_ERROR_IP                             9
#define MSG_ERROR_INVALID_PACKET_TYPE            10
#define MSG_ERROR_NOT_GET_TS_REPLY               11

enum MsgDatagramTypes {
    MSG_PING           = 0X01,
    MSG_PONG           = 0X02,
    MSG_CV_PING        = 0X03,
    MSG_CV_PONG        = 0X04,
    MSG_NOTIFY         = 0X05,
    MSG_FORWARD        = 0X06,
    MSG_NOT_A_DATAGRAM = 0X07
};

enum MsgPacketType {
    MSG_JOIN                 = 0X01,
    MSG_CV_FETCH             = 0X02,
    MSG_GET_PS               = 0X03,
    MSG_GET_RAW_AVAILABILITY = 0X04,
    MSG_GET_TS               = 0X05
};

enum MsgPacketReplyType {
    MSG_JOIN_REPLY                 = 0X06,
    MSG_FETCH_REPLY                = 0X07,
    MSG_GET_PS_REPLY               = 0X08,
    MSG_GET_RAW_AVAILABILITY_REPLY = 0X09,
    MSG_GET_TS_REPLY               = 0X0A,
    MSG_NOT_A_PACKET               = 0X0B
};

extern const char *MSG_HEAD;

#define MSG_HEAD_SIZE     8
#define MSG_JOIN_SIZE     (8+4)
#define MSG_CV_PING_SIZE  (8+3)
#define MSG_CV_PONG_SIZE  (8+3)
#define MSG_PING_SIZE     (8+3)
#define MSG_PONG_SIZE     (8+3)
#define MSG_CV_FETCH_SIZE (8+1)
#define MSG_GET_PS_SIZE   (8+1)
#define MSG_GET_TS_SIZE   (8+1)

#define MSG_GET_RAW_AVAILABILITY_REPLY_HEAD_SIZE (1 + 1)
    
#define MSG_DELIMITER_C   '|'
#define MSG_DELIMITER_S   "|"

typedef struct {
    uint8_t weight;
    uint16_t port;
    char ip[NET_IP_CHAR_SIZE + 1];
} MsgForwardData;

int msg_read_type(int socketfd, uint8_t *buff, GError **gerror);
int msg_datagram_type(const uint8_t *buffer);
int msg_read_head(int socketfd, GError **gerror);
int msg_read_join_reply(int socketfd, GError **gerror);
int msg_read_join_payload(int socketfd, uint16_t *peer_port, uint8_t *weight,
			  GError **gerror);
int msg_send_cv_fetch(int socketfd, GError **gerror);
int msg_send_join(int socketfd, uint8_t weight, uint16_t my_port, GError **gerror);
void msg_send_notify(const char *i_ip, const char *i_port, const char *j_ip,
		     const char *j_port);
void msg_send_cv_ping(const char *peer_ip, const char *peer_port, uint16_t my_port);
void msg_send_cv_pong(struct sockaddr_in *peer_addr, uint16_t peer_port,
		      uint16_t my_port, GError **gerror);
int msg_send_monitoring_ping(const char *ip, const char *port, uint16_t my_port,
			     GError **gerror);
void msg_send_monitoring_pong(struct sockaddr_in *peer_addr, uint16_t peer_port,
			      uint16_t my_port, GError **gerror);
GPtrArray *msg_ids_from_notify_buff(const uint8_t *buff, GError **gerror);
uint16_t msg_port_from_ping_buff(const uint8_t *buff, GError **gerror);
uint16_t msg_port_from_pong_buff(const uint8_t *buff, GError **gerror);
GPtrArray *msg_read_cv(int socketfd, GError **gerror);
gboolean msg_is_valid_datagram(const uint8_t *buffer, int bytes);
int msg_write_join_reply(int socketfd, const GPtrArray *cv_array, GError **gerror);
void msg_send_forward(const char *forward_ip, const char *forward_port,
		      uint16_t joiner_port, const char *joiner_ip, uint8_t weight);
MsgForwardData *msg_data_from_forward_buff(const uint8_t *buff, GError **gerror);
void msg_forward_data_free(MsgForwardData *mfd);
int msg_write_fetch_reply(int socketfd, const GPtrArray *cv_array, GError **gerror);
int msg_read_fetch_reply(int socketfd, GError **gerror);
int msg_send_get_ps(int socketfd, GError **gerror);
int msg_read_get_ps_reply(int socketfd, GError **gerror);
GPtrArray *msg_read_ps(int socketfd, GError **gerror);
int msg_write_get_ps_reply(int socketfd, const GPtrArray *ps_array, GError **gerror);
int msg_send_get_raw_availability(int socketfd, const char *target_ip, const char *target_port, GError **gerror);
int msg_read_get_raw_availability_reply(int socketfd, GError **gerror);
int msg_read_get_raw_availability_reply_data(int socketfd, const char *filename,
					     const char *filename_session,
					     int timeout, GError **gerror);
GPtrArray *msg_read_target(int socketfd, GError **gerror);
int msg_write_get_raw_availability_reply(int socketfd, const char *filename, 
					 const char *sessions_filename, GError **gerror);
int msg_send_get_ts(int socketfd, GError **gerror);
int msg_read_get_ts_reply(int socketfd, GError **gerror);
GPtrArray *msg_read_ts(int socketfd, GError **gerror);
int msg_write_get_ts_reply(int socketfd, const GPtrArray *ts_array, GError **gerror);

AVMON_END_DECLS

#endif /* __AVMON_MESSAGES_H__ */
