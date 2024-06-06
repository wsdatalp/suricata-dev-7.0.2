/**
 * \file
 *
 * \author wdd
 */

#ifndef __UTIL_LOG_KAFKA_H__
#define __UTIL_LOG_KAFKA_H__

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>

#include "conf.h"            /* ConfNode   */
#include "util-hashmap.h"

typedef struct  {
    const char *brokers;
    const char *topic_name_flow;
    const char *topic_name_alarm;
}KafkaSetup;

typedef struct {
    rd_kafka_t *rk;
    rd_kafka_topic_t *rkt_flow;
    rd_kafka_topic_t *rkt_alarm;
    const char *is_send_flow;
    const char *is_send_alarm;
    //告警流量的上文全流量
    HashMap *previous_flow_hash_map;
    //告警流量的上文全流量
    HashMap *alert_flow_ids;
}SCLogKafkaContext;

int LogFileWriteKafka(void *lf_ctx, const char *string, size_t string_len);
int SCConfLogOpenKafka(ConfNode *kafka_node, void *lf_ctx);
int haveAlertByFlowId(int64_t flow_id);
#endif

#endif
