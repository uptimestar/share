/**
 * @package jIPtables
 * @copyright Copyright (C) 2011 jIPtables. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <meltingshell@gmail.com>"
 *
 *         This file is part of jIPtables.
 *         jIPtables is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         jIPtables is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 *
 *         You should have received a copy of the GNU General Public License
 *         along with jIPtables. If not, see
 *         <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_dccp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_sctp.h>
#include <net_sf_jIPtables_connection_NetFilterConnTask.h>

JNIEnv * env;
jobject obj;
jmethodID buildMethod;
jmethodID terminateMethod;
jmethodID newNotificationMethod;
jmethodID updateNotificationMethod;
jmethodID destroyedNotificationMethod;
struct nfct_handle *h;

const char * const proto2str[IPPROTO_MAX] = {
		[IPPROTO_TCP] = "tcp",
		[IPPROTO_UDP] = "udp",
		[IPPROTO_UDPLITE] = "udplite",
		[IPPROTO_ICMP ] = "icmp",
		[IPPROTO_ICMPV6 ] = "icmpv6",
		[IPPROTO_SCTP ] = "sctp",
		[IPPROTO_GRE] = "gre",
		[IPPROTO_DCCP] = "dccp", };

const char * const states[TCP_CONNTRACK_MAX] = {
		[TCP_CONNTRACK_NONE ] = "NONE",
		[TCP_CONNTRACK_SYN_SENT ] = "SYN_SENT",
		[TCP_CONNTRACK_SYN_RECV ] = "SYN_RECV",
		[TCP_CONNTRACK_ESTABLISHED ] = "ESTABLISHED",
		[TCP_CONNTRACK_FIN_WAIT ] = "FIN_WAIT",
		[TCP_CONNTRACK_CLOSE_WAIT ] = "CLOSE_WAIT",
		[TCP_CONNTRACK_LAST_ACK ] = "LAST_ACK",
		[TCP_CONNTRACK_TIME_WAIT ] = "TIME_WAIT",
		[TCP_CONNTRACK_CLOSE ] = "CLOSE" };

const char * const sctp_states[SCTP_CONNTRACK_MAX] = {
		[SCTP_CONNTRACK_NONE ] = "NONE",
		[SCTP_CONNTRACK_CLOSED] = "CLOSED",
		[SCTP_CONNTRACK_COOKIE_WAIT] = "COOKIE_WAIT",
		[SCTP_CONNTRACK_COOKIE_ECHOED] = "COOKIE_ECHOED",
		[SCTP_CONNTRACK_ESTABLISHED] = "ESTABLISHED",
		[SCTP_CONNTRACK_SHUTDOWN_SENT] = "SHUTDOWN_SENT",
		[SCTP_CONNTRACK_SHUTDOWN_RECD] = "SHUTDOWN_RECD",
		[SCTP_CONNTRACK_SHUTDOWN_ACK_SENT] = "SHUTDOWN_ACK_SENT", };

const char * const dccp_states[DCCP_CONNTRACK_MAX] = {
		[DCCP_CONNTRACK_NONE ] = "NONE",
		[DCCP_CONNTRACK_REQUEST] = "REQUEST",
		[DCCP_CONNTRACK_RESPOND] = "RESPOND",
		[DCCP_CONNTRACK_PARTOPEN ] = "PARTOPEN",
		[DCCP_CONNTRACK_OPEN] = "OPEN",
		[DCCP_CONNTRACK_CLOSEREQ] = "CLOSEREQ",
		[DCCP_CONNTRACK_CLOSING ] = "CLOSING",
		[DCCP_CONNTRACK_TIMEWAIT] = "TIMEWAIT",
		[DCCP_CONNTRACK_IGNORE] = "IGNORE",
		[DCCP_CONNTRACK_INVALID ] = "INVALID", };

static void setField(jobject connection, const char * field, const char * value) {
	jclass connectionCls = (*env)->GetObjectClass(env, connection);
	jmethodID
			setMethod =
					(*env)->GetMethodID(env, connectionCls, "setField", "(Ljava/lang/String;Ljava/lang/String;)V");
	(*env)->CallVoidMethod(env, connection, setMethod, (*env)->NewStringUTF(env, field), (*env)->NewStringUTF(env, value));
}

jobject newConnection(char* connectionID) {
	return (*env)->CallObjectMethod(env, obj, buildMethod, (*env)->NewStringUTF(env, connectionID));
}

static int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {

	char tmp[128];

	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_ID));
	jobject conn = newConnection(tmp);

	u_int8_t l3ProtoNum = nfct_get_attr_u8(ct, ATTR_L3PROTO);
	u_int8_t l4ProtoNum = nfct_get_attr_u8(ct, ATTR_L4PROTO);

	sprintf(tmp, "%u", l3ProtoNum);
	setField(conn, "l3protoNum", tmp);

	sprintf(tmp, "%u", l4ProtoNum);
	setField(conn, "l4protoNum", tmp);
	setField(conn, "l4proto", proto2str[l4ProtoNum]);

	switch (l3ProtoNum) {
	case AF_INET:
		if (inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_IPV4_SRC), tmp, sizeof(tmp)))
			setField(conn, "src", tmp);

		if (inet_ntop(AF_INET, nfct_get_attr(ct, ATTR_IPV4_DST), tmp, sizeof(tmp)))
			setField(conn, "dst", tmp);
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_IPV6_SRC), tmp, sizeof(tmp)))
			setField(conn, "src", tmp);

		if (inet_ntop(AF_INET6, nfct_get_attr(ct, ATTR_IPV6_DST), tmp, sizeof(tmp)))
			setField(conn, "dst", tmp);
		break;

	}

	sprintf(tmp, "%u", nfct_get_attr_u16(ct, ATTR_PORT_SRC));
	setField(conn, "sport", tmp);

	sprintf(tmp, "%u", nfct_get_attr_u16(ct, ATTR_PORT_DST));
	setField(conn, "dport", tmp);

	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_BYTES));
	setField(conn, "origBytes", tmp);
	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_PACKETS));
	setField(conn, "origPackets", tmp);

	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_REPL_COUNTER_BYTES));
	setField(conn, "replyBytes", tmp);
	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_REPL_COUNTER_PACKETS));
	setField(conn, "replyPackets", tmp);

	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_MARK));
	setField(conn, "mark", tmp);

	sprintf(tmp, "%u", nfct_get_attr_u32(ct, ATTR_TIMEOUT));
	setField(conn, "timeout", tmp);

	switch (l4ProtoNum) {
	case IPPROTO_TCP:
		setField(conn, "state", states[nfct_get_attr_u8(ct, ATTR_TCP_STATE)]);
		break;
	case IPPROTO_SCTP:
		setField(conn, "state", sctp_states[nfct_get_attr_u8(ct, ATTR_SCTP_STATE)]);
		break;
	case IPPROTO_DCCP:
		setField(conn, "state", dccp_states[nfct_get_attr_u8(ct, ATTR_DCCP_STATE)]);
		break;
	}

	switch (type) {
	case NFCT_T_NEW:
		(*env)->CallVoidMethod(env, obj, newNotificationMethod, conn);
		break;
	case NFCT_T_UPDATE:
		(*env)->CallVoidMethod(env, obj, updateNotificationMethod, conn);
		break;
	case NFCT_T_DESTROY:
		(*env)->CallVoidMethod(env, obj, destroyedNotificationMethod, conn);
		break;
	}

	if ((*env)->CallBooleanMethod(env, obj, terminateMethod)) {
		return NFCT_CB_STOP;
	} else {
		return NFCT_CB_CONTINUE;
	}
}

JNIEXPORT void JNICALL Java_net_sf_jIPtables_connection_NetFilterConnTask_init (JNIEnv * javaEnv, jobject javaObj) {
	env = javaEnv;
	obj = javaObj;

	jclass cls = (*env)->GetObjectClass(env, obj);
	buildMethod = (*env)->GetMethodID(env, cls, "getConnection", "(Ljava/lang/String;)Lnet/sf/jIPtables/connection/Connection;");
	terminateMethod = (*env)->GetMethodID(env, cls, "isTerminated", "()Z");

	newNotificationMethod = (*env)->GetMethodID(env, cls, "notifyNewConnection", "(Ljava/lang/Object;)V");
	updateNotificationMethod = (*env)->GetMethodID(env, cls, "notifyUpdatedConnection", "(Ljava/lang/Object;)V");
	destroyedNotificationMethod = (*env)->GetMethodID(env, cls, "notifyDestroyedConnection", "(Ljava/lang/Object;)V");

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);

	if (!h) {
		perror("nfct_open");
	}

	u_int8_t family = AF_INET;

	nfct_callback_register(h, NFCT_T_ALL, cb, NULL);
	nfct_query(h, NFCT_Q_DUMP, &family);
	nfct_catch(h);
	nfct_close(h);
}

JNIEXPORT void JNICALL Java_net_sf_jIPtables_connection_NetFilterConnTask_deinit (JNIEnv * javaEnv, jobject javaObj) {
	u_int8_t family = AF_INET;
	nfct_query(h, NFCT_Q_DUMP, &family);
}
