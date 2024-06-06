#include "suricata-common.h"
#include "util-log-kafka.h"
#include "util-logopenfile.h"

#include <string.h>
#include "util-debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "util-byte.h"
#ifdef HAVE_LIBRDKAFKA

#define DEFAULT_EXPIRATION_TIME              3
#define DEFAULT_KAFKA_QUEUE_MAX_MESSAGES           "10000000"
#define DEFAULT_KAFKA_QUEUE_MAX_BYTES              "104857"
// 定义全局变量
uint32_t memory_expiration_time =3;
uint32_t memory_free_sleep_time =0;
// 告警流量ids
static HashMap* hashMapAlertFlowIds;
pthread_mutex_t mutex[10000];
/** \brief close kafka log
 *  \param log_ctx Log file context
 */
int total=0;
int fail_num = 0;
int josn_error=0;
int excluding_flow=0;
int excluding_alert=0;
int send_alert_num = 0;
int flow_num=0;
//结束标记
int end_flag=0;
static void SCLogFileCloseKafka(LogFileCtx *log_ctx)
{
    SCLogKafkaContext *kafka_ctx = log_ctx->kafka;
    SCLogInfo("data statistics---> total：%i-----josn_error：%i--excluding_alert：%i--send_alert_num：%i--flow_num：%i", total,josn_error,excluding_alert,send_alert_num,flow_num);
    if (NULL == kafka_ctx) {
        return;
    }

    if (kafka_ctx->rk) {
        /* Poll to handle delivery reports */
        rd_kafka_poll(kafka_ctx->rk, 0);

        /* Wait for messages to be delivered */
        while (rd_kafka_outq_len(kafka_ctx->rk) > 0)
            rd_kafka_poll(kafka_ctx->rk, 100);
    }

    if (kafka_ctx->rkt_flow) {
        /* Destroy topic */
        rd_kafka_topic_destroy(kafka_ctx->rkt_flow);
    }
    if(kafka_ctx->rkt_alarm){
    	rd_kafka_topic_destroy(kafka_ctx->rkt_alarm);
    }


    if (kafka_ctx->rk) {
        /* Destroy the handle */
        rd_kafka_destroy(kafka_ctx->rk);
    }
    free(kafka_ctx);
    end_flag=1;

    return;
}


// 线程函数，监控哈希表并删除过期节点
void* MonitorHashMapKey(void* arg) {
    HashMap* hashMap = (HashMap*)arg;
    Node** nodePtr = hashMap->table;

    while (1) {
        // 遍历哈希表
        for (int i = 0; i < hashMap->size; i++) {
            int lock =  pthread_mutex_trylock(&mutex[i]);
            if (lock != 0){
                continue;
            }
            Node* node = nodePtr[i];
             Node* heedNode = node;
            Node* oldNode = NULL;
            while (node != NULL) {
                if (node->expire_time > time(NULL)) {
                    oldNode = node;
                    // 节点未过期，继续遍历下一个节点
                    node = node->next;
                    continue;
                }
                //头结点过期
                if (oldNode==NULL){
                    nodePtr[i] = node->next;
                    heedNode = nodePtr[i];
                }else{
                    oldNode->next=node->next;
                }
                Node* tempNode = node->next;
                // 节点已过期，删除节点并释放内存
                free(node->key); // 释放键内存
                free(node);       // 释放节点内存
                if(heedNode != NULL){
                     heedNode->count = heedNode->count-1;
                }

                // 删除当前节点后，继续遍历下一个节点
                node = tempNode;
            }
            pthread_mutex_unlock(&mutex[i]);
        }
        sleep(memory_free_sleep_time);
    }
    return NULL;
}

/**
 * \brief LogFileWriteKafka() writes log data to kafka output.
 * \param lf_ctx Log file context allocated by caller
 * \param string buffer with data to write
 * \param string_len data length
 * \retval 0 on sucess;
 * \retval -1 on failure;
 */

int LogFileWriteKafka(void *lf_ctx, const char *string, size_t string_len)
{
    total++;
//    if(strstr(string, "\"failed\"")){
//        fail_num++;
//        return -1;
//    }
    cJSON *flow_root = cJSON_Parse(string);
    if (flow_root == NULL)
    {
        josn_error++;
        return -1;
    }
//    //如果不包含flow节点，直接返回
//    cJSON *flow_item = cJSON_GetObjectItem(flow_root, "flow");
//    if (flow_item == NULL){
//        excluding_flow++;
//        return -1;
//    }
    int group_id = -1;
    //是否为请求头和响应头的数据,1是，0不是
    int is_head_data=0;
    //如果不包含alert节点，直接返回
    cJSON *alert_item = cJSON_GetObjectItem(flow_root, "alert");
    if (alert_item == NULL){
        //校验是否通过，1通过，0不通过
        int flag_check_success=0;
        cJSON *event_type_value = cJSON_GetObjectItem(flow_root, "event_type");
        if (event_type_value != NULL && cJSON_IsString(event_type_value)){
            char* event_type = cJSON_GetStringValue(event_type_value);
            //告警的上下文流量
            if (event_type != NULL && strcmp(event_type, "alertContext") == 0){
                group_id = 1;
                flag_check_success=1;
            }
        }
        if (flag_check_success ==0){
            cJSON *http_item = cJSON_GetObjectItem(flow_root, "http");
            if (http_item != NULL){
                //如果包含 请求头或响应头
                cJSON *request_headers = cJSON_GetObjectItem(http_item, "request_headers");
                cJSON *response_headers = cJSON_GetObjectItem(http_item, "response_headers");
                if (response_headers!= NULL || response_headers !=NULL){
                    is_head_data=1;
                    flag_check_success=1;
                }
            }
        }
        if (flag_check_success == 0){
            cJSON_Delete(flow_root);
            return -1;
        }
    }else{
        if (cJSON_IsObject(alert_item)) {
            cJSON *group_id_value = cJSON_GetObjectItem(alert_item, "groupId");
            if (cJSON_IsNumber(group_id_value)) {
                group_id = group_id_value->valueint;
            }
        }
    }
    LogFileCtx *log_ctx = lf_ctx;
    SCLogKafkaContext *kafka_ctx = log_ctx->kafka;

    //流量id
    cJSON *flow_id_value = cJSON_GetObjectItem(flow_root, "flow_id");
    char *flow_id;
    if (flow_id_value != NULL && cJSON_IsNumber(flow_id_value)) {
        flow_id = cJSON_Print(flow_id_value);
    }else{
        cJSON_Delete(flow_root);
        josn_error++;
        return -1;
    }

    cJSON_Delete(flow_root);

    if(group_id == 1){
        //全流量信息，发送到流量对应的topic中
        flow_num++;
        if (rd_kafka_produce(kafka_ctx->rkt_flow, RD_KAFKA_PARTITION_UA,
                                 RD_KAFKA_MSG_F_COPY,
                    /* Payload and length */
                                 (void *)string, string_len,
                    /* Optional key and its length */
                                 NULL, 0,
                    /* Message opaque, provided in
                     * delivery report callback as
                     * msg_opaque. */
                                 NULL) == -1)
        {
            /* Poll to handle delivery reports */
            rd_kafka_poll(kafka_ctx->rk, 0);
            //重试一次
            if (rd_kafka_produce(kafka_ctx->rkt_flow, RD_KAFKA_PARTITION_UA,
                                 RD_KAFKA_MSG_F_COPY,
                    /* Payload and length */
                                 (void *)string, string_len,
                    /* Optional key and its length */
                                 NULL, 0,
                    /* Message opaque, provided in
                     * delivery report callback as
                     * msg_opaque. */
                                 NULL) == -1)
            {
                SCLogError("kafka_error -- Failed to produce to topic %s "
                        "msg:%s %s\n",
                        log_ctx->kafka_setup.topic_name_flow, string,
                        rd_kafka_err2str(
                                rd_kafka_errno2err(errno)));
                /* Poll to handle delivery reports */
                rd_kafka_poll(kafka_ctx->rk, 0);
            }
        }
        rd_kafka_poll(kafka_ctx->rk, 0);
    }else{
        send_alert_num++;
        //匹配到规则的告警数据
        if (rd_kafka_produce(kafka_ctx->rkt_alarm, RD_KAFKA_PARTITION_UA,
                         RD_KAFKA_MSG_F_COPY,
            /* Payload and length */
                         (void *)string, string_len,
            /* Optional key and its length */
                         NULL, 0,
            /* Message opaque, provided in
 *              * delivery report callback as
 *                           * msg_opaque. */
                         NULL) == -1)
        {
//            SCLogError("kafka_error -- Failed to produce to topic %s "
//                       "partition %i: %s\n",
//                       log_ctx->kafka_setup.topic_name_alarm, 0,
//                       rd_kafka_err2str(
//                               rd_kafka_errno2err(errno)));
            /* Poll to handle delivery reports */
            rd_kafka_poll(kafka_ctx->rk, 0);
            //重试一次
            if (rd_kafka_produce(kafka_ctx->rkt_alarm, RD_KAFKA_PARTITION_UA,
                         RD_KAFKA_MSG_F_COPY,
            /* Payload and length */
                         (void *)string, string_len,
            /* Optional key and its length */
                         NULL, 0,
            /* Message opaque, provided in
 *              * delivery report callback as
 *                           * msg_opaque. */
                         NULL) == -1)
            {
                /* Poll to handle delivery reports */
                rd_kafka_poll(kafka_ctx->rk, 0);
                SCLogError("kafka_error -- Failed to produce to topic %s "
                           "msg:%s %s\n",
                           log_ctx->kafka_setup.topic_name_alarm, string,
                           rd_kafka_err2str(
                                   rd_kafka_errno2err(errno)));
            }
        }
        rd_kafka_poll(kafka_ctx->rk, 0);
        // 获取当前时间
        time_t current_time;
        time(&current_time);
        // 定义要添加的秒数
        int seconds_to_add = (int)memory_expiration_time;
        // 计算新的过期时间
        time_t expire_time = current_time + seconds_to_add;
        //非请求头数据
        if (is_head_data == 0){
            int index = hashCode(flow_id) % 10000;
            pthread_mutex_lock(&mutex[index]);
            //将告警的流量flow_id暂存到内存
            putKey(hashMapAlertFlowIds, flow_id, expire_time);
            pthread_mutex_unlock(&mutex[index]);
        }
    }
    if(flow_id != NULL){
        free(flow_id);
    }

    return -1;
}

/**
 * \brief Message delivery report callback.
 * Called once for each message.
 */
static void msg_delivered (rd_kafka_t *rk,
                           void *payload, size_t len,
                           int error_code,
                           void *opaque, void *msg_opaque)
{
    rk = rk;
    payload = payload;
    len = len;
    opaque = opaque;
    msg_opaque = msg_opaque;
    if (error_code)
        SCLogError("kafka_error  -- Message delivery failed: %s\n",
                   rd_kafka_err2str(error_code));
}

/** \brief configure and initializes kafka output logging
 *  \param kafka_node ConfNode structure for the output section in question
 *  \param lf_ctx Log file context allocated by caller
 *  \retval 0 on success
 */
int SCConfLogOpenKafka(ConfNode *kafka_node, void *lf_ctx)
{
    LogFileCtx *log_ctx = lf_ctx;
    SCLogKafkaContext *kafka_ctx = NULL;

    if (NULL == kafka_node) {
        return -1;
    }

    log_ctx->kafka_setup.brokers = ConfNodeLookupChildValue(kafka_node, "brokers");
    log_ctx->kafka_setup.topic_name_flow = ConfNodeLookupChildValue(kafka_node, "topic-flow");
    log_ctx->kafka_setup.topic_name_alarm = ConfNodeLookupChildValue(kafka_node, "topic-alarm");

    /*create kafka ctx*/
    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *topic_conf;
    rd_kafka_topic_conf_t *topic_conf_alarm;
    char tmp[16];
    char errstr[512];
    kafka_ctx = (SCLogKafkaContext*) SCCalloc(1, sizeof(SCLogKafkaContext));
    if (kafka_ctx == NULL) {
        SCLogError( "kafka_error Unable to allocate kafka context");
        exit(EXIT_FAILURE);
    }
    /*是否需要发送数据到流量的topic*/
    kafka_ctx->is_send_flow = ConfNodeLookupChildValue(kafka_node, "is-send-flow");
     /*是否需要发送数据到流量告警的topic*/
    kafka_ctx->is_send_alarm = ConfNodeLookupChildValue(kafka_node, "is-send-alarm");
    //内存中数据过期时间
    char *expire_time = ConfNodeLookupChildValue(kafka_node, "memory-expiration-time");
    //释放内存线程的休眠时间,单位秒，可以为0
    char *sleep_time = ConfNodeLookupChildValue(kafka_node, "memory-free-sleep-time");
    //过期时间
    if (expire_time != NULL){
        StringParseUint32(&memory_expiration_time, 10, 0,expire_time);
    }
    if (sleep_time != NULL){
        StringParseUint32(&memory_free_sleep_time, 10, 0,sleep_time);
    }

    //kafka队列最大消息数量
    char *queue_max_messages = ConfNodeLookupChildValue(kafka_node, "queue-max-messages");
    char *queue_max_bytes = ConfNodeLookupChildValue(kafka_node, "queue-max-bytes");
    if (queue_max_messages == NULL){
        queue_max_messages = DEFAULT_KAFKA_QUEUE_MAX_MESSAGES;
    }
    if (queue_max_bytes == NULL){
        queue_max_bytes = DEFAULT_KAFKA_QUEUE_MAX_BYTES;
    }
    conf = rd_kafka_conf_new();
    /*设置压缩类型为lz4  */
    rd_kafka_conf_set(conf, "compression.codec", "lz4", errstr, sizeof(errstr));
//    rd_kafka_conf_set(conf, "batch.num.messages", "100", errstr, sizeof(errstr));
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf,
                                              "internal.termination.signal",
                                              tmp,
                                              errstr,
                                              sizeof(errstr))) {
        SCLogError("kafka_error Unable to allocate kafka context");
    }
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf,
                                              "broker.version.fallback",
                                              "0.8.2",
                                              errstr,
                                              sizeof(errstr))) {
        SCLogError("kafka_error %s", errstr);
    }
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf,
                                              "queue.buffering.max.messages",
                                              queue_max_messages,
                                              errstr,
                                              sizeof(errstr))) {
        SCLogError("kafka_error %s", errstr);
    }
    if (RD_KAFKA_CONF_OK != rd_kafka_conf_set(conf,
                                              "queue.buffering.max.kbytes",
                                              queue_max_bytes,
                                              errstr,
                                              sizeof(errstr))) {
        SCLogError("kafka_error %s", errstr);
    }

    rd_kafka_conf_set_dr_cb(conf, msg_delivered);
    if (!(kafka_ctx->rk = rd_kafka_new(RD_KAFKA_PRODUCER,
                                       conf,
                                       errstr,
                                       sizeof(errstr)))) {
        SCLogError("kafka_error -- Failed to create new producer: %s", errstr);
        exit(EXIT_FAILURE);
    }
    // 适配kafka集群
    char *broker;
    broker = strtok(log_ctx->kafka_setup.brokers, ",");
    while(broker != NULL){
         if (0 == rd_kafka_brokers_add(kafka_ctx->rk, broker)) {
                SCLogError("kafka_error -- No valid brokers specified");
                exit(EXIT_FAILURE);
         }
         broker = strtok(NULL, ",");
    }

    topic_conf = rd_kafka_topic_conf_new();
    kafka_ctx->rkt_flow = rd_kafka_topic_new(kafka_ctx->rk,
                                        log_ctx->kafka_setup.topic_name_flow,
                                        topic_conf);
    if (NULL == kafka_ctx->rkt_flow) {
        SCLogError("kafka_error -- Failed to create kafka topic %s",
                   log_ctx->kafka_setup.topic_name_flow);
        exit(EXIT_FAILURE);
    }
    topic_conf_alarm = rd_kafka_topic_conf_new();
    kafka_ctx->rkt_alarm = rd_kafka_topic_new(kafka_ctx->rk,
					log_ctx->kafka_setup.topic_name_alarm,
                                        topic_conf_alarm);
   if(NULL == kafka_ctx->rkt_alarm){
   	SCLogError("kafka_error -- Failed to create kafka topic %s",
                   log_ctx->kafka_setup.topic_name_alarm);
        exit(EXIT_FAILURE);
   }
    log_ctx->kafka = kafka_ctx;
    log_ctx->Close = SCLogFileCloseKafka;

    hashMapAlertFlowIds = createHashMap(10000);
    //创建1个线程来监控内存中
    pthread_t threadId2;
    // 创建线程并传入哈希表作为参数
    int errCode2 = pthread_create(&threadId2, NULL, MonitorHashMapKey, hashMapAlertFlowIds);
    if (errCode2 != 0) {
        SCLogError("kafka_error -- creating monitorHashMapKey by alertFlowIds thread fail ");
        exit(EXIT_FAILURE);
    }
    // 分离线程，使其在后台运行
    pthread_detach(threadId2);
    return 0;
}
/**
 * 根据flow_id判断是否有告警
 */
int haveAlertByFlowId(int64_t f_id){
    int result = FALSE;
    char* flow_id= (char*)malloc(sizeof(char) * 20);
    sprintf(flow_id, "%ld", f_id);
    int index = hashCode(flow_id) % 10000;
    pthread_mutex_lock(&mutex[index]);
    //如果存在告警的flow_id
    if(hashMapAlertFlowIds !=NULL && existenceKey(hashMapAlertFlowIds,flow_id) == 1){
        result = TRUE;
    }
    pthread_mutex_unlock(&mutex[index]);
    if (flow_id != NULL){
       free(flow_id);
    }
    return result;
}
#endif