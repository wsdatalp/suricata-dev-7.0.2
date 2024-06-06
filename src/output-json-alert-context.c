/* Copyright (C) 2013-2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Logs alerts in JSON format.
 *
 */
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
#include "pthread.h"
#include "string.h"
#include "suricata-common.h"
#include "packet.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "decode.h"

#include "stream.h"
#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-logopenfile.h"
#include "util-misc.h"
#include "util-time.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "detect-metadata.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "app-layer-frames.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "log-pcap.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-dnp3.h"
#include "output-json-dns.h"
#include "output-json-http.h"
#include "output-json-tls.h"
#include "output-json-ssh.h"
#include "rust.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-flow.h"
#include "output-json-sip.h"
#include "output-json-rfb.h"
#include "output-json-mqtt.h"
#include "output-json-ike.h"
#include "output-json-modbus.h"
#include "output-json-frame.h"
#include "output-json-quic.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-validate.h"
#include "util-hashmap.h"
#include "action-globals.h"
#include "util-device.h"
#include "flow-storage.h"
#include "util-log-kafka.h"

#define BASE64_BUFFER_SIZE_C(x) ((4 * (((x) + 2) / 3)) + 1)
extern uint32_t memory_expiration_time;
extern uint32_t memory_free_sleep_time;
pthread_mutex_t mut[10000];
pthread_mutex_t flowMapTMutex;
int haveAlertByFlowId(int64_t flow_id);
static void* ContextMonitorHashMap(void* arg);
struct context_pkt {
    uint32_t pkt_len;
    char *pkt_chars;
    Packet *packet;
    int isFromMemory;
};
typedef struct AlertContextJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} AlertContextJsonOutputCtx;

typedef struct JsonAlertContextLogThread_ {
    MemBuffer *payload_buffer;
    AlertContextJsonOutputCtx* json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonAlertContextLogThread;
static struct context_pkt *get_context_pkt(const Packet *p);
void set_context_pkt(const Packet *p, struct context_pkt *context_pkt_data);




// 队列包含的信息
typedef struct queue_pkt_ {
    struct context_pkt qu[20];      //用来存储全部的队列中的元素
    int head;     //队列头
    int tail;     //队尾
    int qlength;  //队列长度
    int maxsize;  //用来记录队列的最大容量

} QUEUE_PKT;



typedef struct {
    char* key;
    void* value;
    time_t expire_time;
    struct CNode* next;
} CNode;

typedef  int (*FreeValue)(void* value);
typedef struct {
    CNode** table;
    int size;
    FreeValue freeValue;
} CHashMap;



QUEUE_PKT *CreateQueue() {
    QUEUE_PKT *q = (QUEUE_PKT *) malloc(sizeof(QUEUE_PKT));

    if (q == NULL) {
        printf("Memory alloc failure\n");
        exit(-1);
    }


    q->head = 0;
    q->tail = 0;
    q->qlength = 0;
    q->maxsize = 20;


    return q;
}


int Empty(QUEUE_PKT *q) {
    return q->qlength == 0 ? TRUE : FALSE;
}

int Full(QUEUE_PKT *q) {

    return q->qlength == q->maxsize ? TRUE : FALSE;
}

void freeQuValue(struct context_pkt * pkt){

    if (pkt == NULL){
        return;
    }
    if (pkt->pkt_chars != NULL) {
        free(pkt->pkt_chars);
        pkt->pkt_chars=NULL;
    }
    if (pkt->packet!=NULL){
        if (pkt->packet->flow != NULL){
            free(pkt->packet->flow);
            pkt->packet->flow=NULL;
        }
        if (pkt->packet->ip4h != NULL){
            free(pkt->packet->ip4h);
            pkt->packet->ip4h=NULL;
        }
        if (pkt->packet->ip6h != NULL){
            free(pkt->packet->ip6h);
            pkt->packet->ip6h=NULL;
        }
        if (pkt->packet->icmpv4h != NULL){
            free(pkt->packet->icmpv4h);
            pkt->packet->icmpv4h=NULL;
        }
        if (pkt->packet->icmpv6h != NULL){
            free(pkt->packet->icmpv6h);
            pkt->packet->icmpv6h=NULL;
        }
        if (pkt->packet->livedev != NULL){
            free(pkt->packet->livedev);
            pkt->packet->livedev=NULL;
        }
        free(pkt->packet);
    }
    pkt->packet=NULL;
    pkt->pkt_len = 0;
}

//入队
struct context_pkt *Enqueue(QUEUE_PKT *q) {

    if (Full(q)) {
        struct context_pkt *data = &q->qu[q->head];
        q->head = (q->head + 1) % q->maxsize;
        freeQuValue(data);
        return data;
    } else {
        struct context_pkt *data = &q->qu[q->qlength];
        q->qlength++;
        return data;
    }


}


struct context_pkt *Dequeue(QUEUE_PKT *q) {


    if (Empty(q)) {
        return NULL;
    } else {
        struct context_pkt *data = &q->qu[q->head];
        q->head = (q->head + 1) % q->maxsize;
        q->qlength--;

        return data;
    }

}
// 释放队列
int freeQU(void* value){
    if(value != NULL){
        QUEUE_PKT *queuePkt = (QUEUE_PKT *) value;
        //出队
        struct context_pkt * pkt = Dequeue(queuePkt);
        while (pkt !=NULL){
            //释放队列中的值
            freeQuValue(pkt);
            pkt = Dequeue(queuePkt);

        }
        free(queuePkt);
    }
}


// 创建哈希表
CHashMap* CreateCHashMap(int size,FreeValue freeValue) {
    CHashMap* map = (CHashMap*)malloc(sizeof(CHashMap));
    map->size = size;
    map->table = (CNode**)calloc(size, sizeof(CNode*));
    map->freeValue = freeValue;
    return map;
}

static  int ChashCode(char* key) {
    int hash = 0;
    for (int i = 0; key[i] != '\0'; i++) {
        hash = (hash * 31 + key[i]) % 997;
    }
    return hash;
}

static char *CopyKey(char *key){
    int len = strlen(key);
    char* new_key = (char*)malloc(sizeof(char )*(len+1));
    strcpy(new_key,key);
    return new_key;
}

static void FreeOneNode(CHashMap *hashMap) {
    CNode **nodePtr = hashMap->table;


    while (1){
        // 遍历哈希表
        for (int i = 0; i < hashMap->size; i++) {
            int lock =  pthread_mutex_trylock(&mut[i]);
            if (lock != 0){
                continue;
            }
            CNode *node = nodePtr[i];
            CNode *pNode = NULL;
            while (node != NULL) {
                //如果过期时间大于当前时间则继续遍历
                if (node->expire_time > time(NULL)) {
                    pNode = node;
                    node = node->next;
                    continue;
                }

                if(pNode == NULL){
                    nodePtr[i] = node->next;
                }else{
                    pNode->next = node->next;
                }
                CNode *nextNode =   node->next;
                free(node->key);
                hashMap->freeValue(node->value);
                free(node);
                node = nextNode;
            }
            pthread_mutex_unlock(&mut[i]);
        }
        sleep(memory_free_sleep_time);
    }

}

void Cput(CHashMap* map, char* key, void* value, time_t expire_time) {

    int index = ChashCode(key) % map->size;

    for (CNode* node = map->table[index]; node != NULL; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            void *valueNode = node->value;
            map->freeValue(valueNode);
            node->value = value;
            if (expire_time > node->expire_time) {
                node->expire_time = expire_time;
            }
            return;
        }
    }

    CNode* new_node = (CNode*)malloc(sizeof(CNode));
    new_node->value = value;
    new_node->key = CopyKey(key);
    new_node->value = value;
    new_node->expire_time = expire_time;
    new_node->next = (struct Node *) map->table[index];
    map->table[index] = new_node;

}

void* CgetAndRM(CHashMap* map, char* key) {
    int index = ChashCode(key) % map->size;

    CNode* node = map->table[index];
    CNode* pNode = NULL;

    while (node !=NULL){
        if (strcmp(node->key, key) == 0) {
            if(pNode == NULL){
                map->table[index] = (CNode *) node->next;
            } else{
                pNode->next = node->next;
            }
            free(node->key);
            void *findValue =   node->value;
            free(node);
            return findValue;
        } else{
            pNode = node;
            node = node->next;
        }
    }
    return NULL;
}


void* Cget(CHashMap* map, char* key) {
    int index = ChashCode(key) % map->size;

    CNode* node = map->table[index];
    while (node !=NULL){
        if (strcmp(node->key, key) == 0) {
            return  node->value;
        } else{
            node = node->next;
        }
    }
    return NULL;
}


static void EveAddContextFlow(Flow *f, JsonBuilder *js,int isFromMemory)
{
    //数据是否来自内存，1是0否
    FlowBypassInfo *fc = NULL;
    if (isFromMemory == 1){
        fc = (FlowBypassInfo *)((void *)f + sizeof(Flow));
    } else{
        fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    }

    if (fc) {
        jb_set_uint(js, "upPkts", f->todstpktcnt + fc->todstpktcnt);
        jb_set_uint(js, "downPkts", f->tosrcpktcnt + fc->tosrcpktcnt);
        jb_set_uint(js, "upBytes", f->todstbytecnt + fc->todstbytecnt);
        jb_set_uint(js, "downBytes", f->tosrcbytecnt + fc->tosrcbytecnt);

        jb_open_object(js, "bypassed");
        jb_set_uint(js, "upPkts", fc->todstpktcnt);
        jb_set_uint(js, "downPkts", fc->tosrcpktcnt);
        jb_set_uint(js, "upBytes", fc->todstbytecnt);
        jb_set_uint(js, "downBytes", fc->tosrcbytecnt);
        jb_close(js);
    } else {
        jb_set_uint(js, "upPkts", f->todstpktcnt);
        jb_set_uint(js, "downPkts", f->tosrcpktcnt);
        jb_set_uint(js, "upBytes", f->todstbytecnt);
        jb_set_uint(js, "downBytes", f->tosrcbytecnt);
    }

    char timebuf1[64];
    CreateIsoTimeString(f->startts, timebuf1, sizeof(timebuf1));
    jb_set_string(js, "start", timebuf1);
}
JsonBuilder *CreateContextEveHeader(struct context_pkt *contextPkt,
                                    enum OutputJsonLogDirection dir,
                                    const char *event_type,
                                    JsonAddrInfo *addr)
{
    const Packet *p = contextPkt->packet;
    char timebuf[64];
    const Flow *f = (const Flow *)p->flow;

    JsonBuilder *js = jb_new_object();
    if (unlikely(js == NULL)) {
        return NULL;
    }
    jb_set_uint(js, "packetLen", contextPkt->pkt_len);
    unsigned long p_len = BASE64_BUFFER_SIZE_C(contextPkt->pkt_len);
    uint8_t p_encoded_packet[p_len];
    if (Base64Encode((unsigned char*) contextPkt->pkt_chars, contextPkt->pkt_len, p_encoded_packet, &p_len) == SC_BASE64_OK) {
        jb_set_string(js, "packetBase64", (char *)p_encoded_packet);
    }

    //设置logTime
    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf));
    struct timeval time1;
    gettimeofday(&time1,NULL);
    long long startTime = (long long)time1.tv_sec*1000 + (long long )time1.tv_usec / 1000;

    jb_set_uint(js, "logTime", startTime);


    //设置logId
    const char *c = "89ab";
    int n;
    char logId[37];
    char *logId_p = logId;
    for( n = 0; n < 16; ++n ){
        int b = rand()%255;
        switch( n ){
            case 6:
                sprintf(logId_p,"4%x",b%15 );
                break;
            case 8:
                sprintf(logId_p,"%c%x",c[rand()%strlen( c )],b%15 );
                break;
            default:
                sprintf(logId_p,"%02x",b );
                break;
        }
        logId_p += 2;
        switch( n )
        {
            case 3:
            case 5:
            case 7:
            case 9:
                *logId_p++ = '-';
                break;
        }
    }
    *logId_p = 0;

    jb_set_string(js, "logId", logId);

    CreateEveFlowId(js, f);


    /* input interface */
    if (p->livedev) {
        jb_set_string(js, "in_iface", p->livedev->dev);
    }

    /* pcap_cnt */
    if (p->pcap_cnt != 0) {
        jb_set_uint(js, "pcap_cnt", p->pcap_cnt);
    }

    if (event_type) {
        jb_set_string(js, "event_type", event_type);
    }

    /* 5-tuple */
    JsonAddrInfo addr_info = json_addr_info_zero;
    if (addr == NULL) {
        JsonAddrInfoInit(p, dir, &addr_info);
        addr = &addr_info;
    }
    jb_set_string(js, "srcIp", addr->src_ip);
    jb_set_uint(js, "srcPort", addr->sp);
    jb_set_string(js, "destIp", addr->dst_ip);
    jb_set_uint(js, "destPort", addr->dp);
    jb_set_string(js, "transferProtocol", addr->proto);

    /* icmp */
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (p->icmpv4h) {
                jb_set_uint(js, "icmp_type", p->icmpv4h->type);
                jb_set_uint(js, "icmp_code", p->icmpv4h->code);
            }
            break;
        case IPPROTO_ICMPV6:
            if (p->icmpv6h) {
                jb_set_uint(js, "icmp_type", p->icmpv6h->type);
                jb_set_uint(js, "icmp_code", p->icmpv6h->code);
            }
            break;
    }

    jb_set_string(js, "pkt_src", PktSrcToString(p->pkt_src));

    return js;
}
/**
 * 封装json数据
 * @param contextPkt
 * @param ctx
 * @return
 */
static int AlertContextJson(struct context_pkt *contextPkt,const OutputJsonThreadCtx *ctx)
{
    Packet *p = contextPkt->packet;

    //初始化地址信息（5原组）
    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);
    //创建JsonBuilder，封装5元组等信息
    JsonBuilder *jb =
            CreateContextEveHeader(contextPkt, LOG_DIR_PACKET, "alertContext", &addr);
    if (unlikely(jb == NULL))
        return TM_ECODE_OK;
    if (p->flow != NULL) {

        EveAddAppProto(p->flow, jb);

        if (p->flowflags & FLOW_PKT_TOSERVER) {
            jb_set_string(jb, "direction", "to_server");
        } else {
            jb_set_string(jb, "direction", "to_client");
        }
        jb_open_object(jb, "flow");
        EveAddContextFlow(p->flow, jb,contextPkt->isFromMemory);
        if (p->flowflags & FLOW_PKT_TOCLIENT) {
            jb_set_string(jb, "src_ip", addr.dst_ip);
            jb_set_string(jb, "dest_ip", addr.src_ip);
            if (addr.sp > 0) {
                jb_set_uint(jb, "src_port", addr.dp);
                jb_set_uint(jb, "dest_port", addr.sp);
            }
        } else {
            jb_set_string(jb, "src_ip", addr.src_ip);
            jb_set_string(jb, "dest_ip", addr.dst_ip);
            if (addr.sp > 0) {
                jb_set_uint(jb, "src_port", addr.sp);
                jb_set_uint(jb, "dest_port", addr.dp);
            }
        }
        jb_close(jb);
    }
    //将json信息输出【目前使用的方式是：输出到kafka】
    OutputJsonBuilderBuffer(jb, ctx);
    jb_free(jb);
    return TM_ECODE_OK;
}

static CHashMap *flow_hash_map;

int JsonContextAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (p->flow_hash == NULL || p->flow == NULL) {
        return 0;
    }
    //计算获取一个flow_id
    int64_t f_id = FlowGetId(p->flow);
    //判断已产生的告警流量是否包含当前的flow_id
    int havaAlert = haveAlertByFlowId(f_id);
    char *flow_id = (char *) malloc(sizeof(char) * 20);
    sprintf(flow_id, "%ld", f_id);

    //加锁，避免使用和释放冲突
    int index = ChashCode(flow_id) % 10000;
    pthread_mutex_lock(&mut[index]);
    //如果已产生的告警流量的flowIdList包含当前flow_id
    if (havaAlert == TRUE) {
        //从内存中取出，当前flow_id对应的流量信息进行输出

        //从map中取出队列
        QUEUE_PKT *queue =(QUEUE_PKT *)CgetAndRM(flow_hash_map, flow_id);
        //遍历队列，将队列中存放的packet全部出队，并输出
        if (queue != NULL) {
            struct context_pkt *context_pkt_data = Dequeue(queue);
            while (context_pkt_data != NULL) {

                JsonAlertContextLogThread *jsonAlertContextLogThread = thread_data;
                //封装json输出
                AlertContextJson(context_pkt_data,jsonAlertContextLogThread->ctx);
                //释放队列中的value值
                freeQuValue(context_pkt_data);
                context_pkt_data = Dequeue(queue);
            }
            free(queue);
        }
        //对于当前这条流量信息，直接输出
        struct context_pkt *context_pkt_data = get_context_pkt(p);
        JsonAlertContextLogThread *jsonAlertContextLogThread = thread_data;
        //封装json输出
        AlertContextJson(context_pkt_data,jsonAlertContextLogThread->ctx);

        free(context_pkt_data->pkt_chars);
        free(context_pkt_data);


    } else {
        //如果已产生的告警流量的flowIdList不包含当前flow_id，则将其暂存到内存中

        // 获取当前时间
        time_t current_time;
        time(&current_time);
        // 定义要添加的秒数
        int seconds_to_add = (int)memory_expiration_time;
        // 计算新的过期时间
        time_t expire_time = current_time + seconds_to_add;

        //如果当前flow_id已经有一个队列，直接入队即可，如果没有，先创建一个队列，放到map中
        QUEUE_PKT *queue =(QUEUE_PKT *) Cget(flow_hash_map, flow_id);
        if (queue == NULL) {
            queue = CreateQueue();
            Cput(flow_hash_map, flow_id, queue, expire_time);
        }
        //将当前流量信息入队
        struct context_pkt *context_pkt_data = Enqueue(queue);
        set_context_pkt(p, context_pkt_data);

    }
    free(flow_id);

    pthread_mutex_unlock(&mut[index]);
    return 0;
}
/**
 * 将原始的packet进行copy
 * @param srcPacket
 * @return
 */
Packet* PacketCopy(const Packet* srcPacket){
    if (srcPacket ==NULL){
        return NULL;
    }
    Packet* destPacket = (Packet*)malloc(sizeof(Packet));
    destPacket->flowflags =srcPacket->flowflags;
    destPacket->sp =srcPacket->sp;
    destPacket->dp = srcPacket->dp;
    destPacket->proto=srcPacket->proto;
    destPacket->pcap_cnt=srcPacket->pcap_cnt;
    destPacket->ip4h=srcPacket->ip4h;


    if (srcPacket->livedev != NULL){
        LiveDevice* liveDevice = (LiveDevice*)malloc(sizeof(LiveDevice));
        liveDevice->dev=srcPacket->livedev->dev;
        liveDevice->mtu=srcPacket->livedev->mtu;
        liveDevice->id=srcPacket->livedev->id;
        destPacket->livedev =liveDevice;
    } else{
        destPacket->livedev=NULL;
    }

    if (srcPacket->ip6h != NULL){
        IPV6Hdr* ipv6Hdr = (IPV6Hdr*)malloc(sizeof(IPV6Hdr));
        ipv6Hdr->ip6_hdrun=srcPacket->ip6h->ip6_hdrun;
        ipv6Hdr->ip6_hdrun2=srcPacket->ip6h->ip6_hdrun2;
        destPacket->ip6h=ipv6Hdr;
    }else{
        destPacket->ip6h =NULL;
    }

    if (srcPacket->ip4h != NULL){
        IPV4Hdr* ipv4Hdr = (IPV4Hdr*)malloc(sizeof(IPV4Hdr));
        ipv4Hdr->ip4_hdrun1=srcPacket->ip4h->ip4_hdrun1;
        ipv4Hdr->ip_csum=srcPacket->ip4h->ip_csum;
        ipv4Hdr->ip_id=srcPacket->ip4h->ip_id;
        ipv4Hdr->ip_len=srcPacket->ip4h->ip_len;
        ipv4Hdr->ip_off=srcPacket->ip4h->ip_off;
        ipv4Hdr->ip_proto=srcPacket->ip4h->ip_proto;
        ipv4Hdr->ip_tos=srcPacket->ip4h->ip_tos;
        ipv4Hdr->ip_ttl=srcPacket->ip4h->ip_ttl;
        ipv4Hdr->ip_verhl=srcPacket->ip4h->ip_verhl;
        destPacket->ip4h=ipv4Hdr;
    } else{
        destPacket->ip4h=NULL;
    }
    if (srcPacket->icmpv4h != NULL){
        ICMPV4Hdr* icmpv4h = (ICMPV4Hdr*)malloc(sizeof(ICMPV4Hdr));
        icmpv4h->code=srcPacket->icmpv4h->code;
        icmpv4h->type=srcPacket->icmpv4h->type;
        icmpv4h->checksum=srcPacket->icmpv4h->checksum;
        destPacket->icmpv4h=icmpv4h;
    } else{
        destPacket->icmpv4h=NULL;
    }
    if (srcPacket->icmpv6h != NULL){
        ICMPV6Hdr* icmpv6h = (ICMPV6Hdr*)malloc(sizeof(ICMPV6Hdr));
        icmpv6h->type =srcPacket->icmpv6h->type;
        icmpv6h->code =srcPacket->icmpv6h->code;
        icmpv6h->csum =srcPacket->icmpv6h->csum;
        icmpv6h->icmpv6b =srcPacket->icmpv6h->icmpv6b;
        destPacket->icmpv6h=icmpv6h;
    } else{
        destPacket->icmpv6h=NULL;
    }

    destPacket->src = srcPacket->src;
    destPacket->dst=srcPacket->dst;
    destPacket->ip4vars=srcPacket->ip4vars;


    if (srcPacket->flow != NULL){
        Flow* flow = (Flow*)(malloc(sizeof(Flow)+sizeof(FlowBypassInfo)));
        FlowBypassInfo *fc = FlowGetStorageById(srcPacket->flow, GetFlowBypassInfoID());
        flow->src=srcPacket->flow->src;
        flow->dst=srcPacket->flow->dst;
        flow->sp=srcPacket->flow->sp;
        flow->dp=srcPacket->flow->dp;
        flow->proto=srcPacket->flow->proto;
        flow->recursion_level=srcPacket->flow->recursion_level;
        flow->vlan_idx=srcPacket->flow->vlan_idx;
        flow->ffr=srcPacket->flow->ffr;
        flow->timeout_at=srcPacket->flow->timeout_at;
        flow->alproto=srcPacket->flow->alproto;
        flow->alproto_expect=srcPacket->flow->alproto_expect;
        flow->alproto_orig=srcPacket->flow->alproto_orig;
        flow->alproto_tc=srcPacket->flow->alproto_tc;
        flow->alproto_ts=srcPacket->flow->alproto_ts;
        flow->startts=srcPacket->flow->startts;
        flow->flow_hash=srcPacket->flow->flow_hash;
        flow->todstpktcnt=srcPacket->flow->todstpktcnt;
        flow->tosrcpktcnt=srcPacket->flow->tosrcpktcnt;
        flow->todstbytecnt=srcPacket->flow->todstbytecnt;
        flow->tosrcbytecnt=srcPacket->flow->tosrcbytecnt;
        if (fc != NULL){
            FlowBypassInfo *pBypassInfo = (FlowBypassInfo *)((void *)flow + sizeof(Flow));
            pBypassInfo->todstpktcnt=fc->todstpktcnt;
            pBypassInfo->tosrcpktcnt=fc->tosrcpktcnt;
            pBypassInfo->todstbytecnt=fc->todstbytecnt;
            pBypassInfo->tosrcbytecnt=fc->tosrcbytecnt;
        } else{
            FlowBypassInfo *pBypassInfo = (FlowBypassInfo *)((void *)flow + sizeof(Flow));
            pBypassInfo->todstpktcnt=0;
            pBypassInfo->tosrcpktcnt=0;
            pBypassInfo->todstbytecnt=0;
            pBypassInfo->tosrcbytecnt=0;
        }
        destPacket->flow=flow;
    } else{
        destPacket->flow=NULL;
    }

    return destPacket;
}
void set_context_pkt(const Packet *p, struct context_pkt *context_pkt_data) {
    uint32_t p_max_len = p->pktlen;
    if (p_max_len == NULL) {
        return;
    }
    char *pkt_data = (char *) GET_PKT_DATA(p);
    char *pkt_chars = (char *) malloc(sizeof(char) * p_max_len);
    for (int i = 0; i < p_max_len; ++i) {
        pkt_chars[i] = pkt_data[i];
    }

    context_pkt_data->pkt_len = p_max_len;
    context_pkt_data->pkt_chars = pkt_chars;
    Packet *packet = PacketCopy(p);
    context_pkt_data->packet=packet;
    //数据是否来自内存，1是0否
    context_pkt_data->isFromMemory=1;
    return;
}
/**
 *
 * @param p packet包
 * @return
 */
static struct context_pkt *get_context_pkt(const Packet *p){
    uint32_t p_max_len = p->pktlen;
    if (p_max_len == NULL){
        return NULL;
    }
    char *pkt_data =   (char*) GET_PKT_DATA(p);
    char *pkt_chars = (char*)malloc(sizeof(char) * p_max_len);
    for (int i = 0; i < p_max_len; ++i) {
        pkt_chars[i] = pkt_data[i];
    }
    struct context_pkt *context_pkt_data = (struct context_pkt *) malloc(sizeof(struct context_pkt));
    context_pkt_data->pkt_len = p_max_len;
    context_pkt_data->pkt_chars  = pkt_chars;

    context_pkt_data->packet=p;
    //数据是否来自内存，1是0否
    context_pkt_data->isFromMemory=0;
    return  context_pkt_data;
}




int JsonAContextCondition(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (flow_hash_map == NULL) {
        pthread_mutex_lock(&flowMapTMutex);
        if (flow_hash_map == NULL){
            flow_hash_map = CreateCHashMap(10000,freeQU);

            pthread_t threadId;
            //创建一个独立的线程，进行内存释放
            int errCode = pthread_create(&threadId, NULL, FreeOneNode, flow_hash_map);
            if (errCode != 0) {
                SCLogError("kafka_error -- creating ContextMonitorHashMap thread fail ");
                exit(EXIT_FAILURE);
            }
            // 分离线程，使其在后台运行
            pthread_detach(threadId);
        }
        pthread_mutex_unlock(&flowMapTMutex);
    }

    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        return TRUE;
    }
    return FALSE;
}
