//
// Created by Administrator on 29/11/2023.
//

#ifndef SURICATA_DEV_DEV_UTIL_HASHMAP_H
#define SURICATA_DEV_DEV_UTIL_HASHMAP_H


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>


typedef struct {
    char* value;
    struct ValueNode* next;
} ValueNode;

// 哈希表节点结构体
typedef struct {
    char* key;
    ValueNode* value;
    // 过期时间
    time_t expire_time;
    //此条数据是否已被使用
    char* is_used;
    struct Node* next;
    int count;
} Node;


// 哈希表结构体
typedef struct {
    Node** table;
    int size;
} HashMap;
int hashCode(char* key);
HashMap* createHashMap(int size);
void put(HashMap* map, char* key, void* value, time_t expire_time);
void putKey(HashMap* map, char* key, time_t expire_time);
/**
 * 判断是否存在key
 * @param key
 * @return 存在返回 1  不存在返回0
 */
int existenceKey(HashMap* map, char* key);

void* get(HashMap* map, char* key);



#endif //SURICATA_DEV_DEV_UTIL_HASHMAP_H

