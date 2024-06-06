//
// Created by Administrator on 29/11/2023.
//
#include "suricata-common.h"
#include "util-debug.h"
#include "util-hashmap.h"

// 计算哈希值
int hashCode(char* key) {
    int hash = 0;
    for (int i = 0; key[i] != '\0'; i++) {
        hash = (hash * 31 + key[i]) % 997;
    }
    return hash;
}

// 创建哈希表
HashMap* createHashMap(int size) {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    map->size = size;
    map->table = (Node**)calloc(size, sizeof(Node*));
    for (int i = 0; i < size; ++i) {
        map->table[i] = NULL;
    }
    return map;
}


// 插入节点
void put(HashMap* map, char* key, void* value, time_t expire_time) {
    int index = hashCode(key) % map->size;
    // 如果节点已存在，则把新的value和旧的value组成一个list
    for (Node* node = map->table[index]; node != NULL; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            //插入value
            ValueNode* valueNode =  (ValueNode*)node->value;
            ValueNode* newValueNode = (ValueNode*)malloc(sizeof(ValueNode));
            newValueNode->next = valueNode;
            newValueNode->value = value;
            node->value = newValueNode;
            // 设置过期时间。如果新节点的过期时间比旧节点的过期时间更晚，则更新过期时间。
            if (expire_time > node->expire_time) {
                node->expire_time = expire_time;
            }
            return;
        }
    }

    // 如果节点不存在，则创建新的节点
    ValueNode* valueNode = (ValueNode*)malloc(sizeof(ValueNode));
    valueNode->next = NULL;
    valueNode->value = value;
    Node* new_node = (Node*)malloc(sizeof(Node));
    new_node->key = key;
    new_node->value = valueNode;
    new_node->expire_time = expire_time;
    new_node->is_used = "no";
    new_node->next = NULL;
    // 把新节点插入到链表头部
    new_node->next = map->table[index];
    map->table[index] = new_node;
}

static char *CopyStr(char *key){
    int len = strlen(key);
    char* new_key = (char*)malloc(sizeof(char )*(len+1));
    strcpy(new_key,key);
    return new_key;
}

// 插入节点
void putKey(HashMap* map, char* key, time_t expire_time) {
    int index = hashCode(key) % map->size;
    // 如果节点已存在，则把新的value和旧的value组成一个list
    for (Node* node = map->table[index]; node != NULL; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            // 设置过期时间。如果新节点的过期时间比旧节点的过期时间更晚，则更新过期时间。
            if (expire_time > node->expire_time) {
                node->expire_time = expire_time;
            }
            return;
        }
    }
    int count = 0;
    if (map->table[index] != NULL){
        count = map->table[index]->count + 1;
    }
    if(count > 200){
        Node* endNode = map->table[index] ;
        for (Node* node = map->table[index]; node != NULL; node = node->next) {
            endNode = node;
        }
        char *newkey = CopyStr(key);
        free(  endNode->key);
        endNode->key = newkey;
    } else{
        // 如果节点不存在，则创建新的节点
        Node* new_node = (Node*)malloc(sizeof(Node));
        new_node->key = CopyStr(key);
        new_node->expire_time = expire_time;
        new_node->next = NULL;
        // 把新节点插入到链表头部
        new_node->next = map->table[index];
        new_node->count = count;
        map->table[index] = new_node;
    }


}

int existenceKey(HashMap* map, char* key){
    int index = hashCode(key) % map->size;
    // 如果节点已存在，则把新的value和旧的value组成一个list
    for (Node* node = map->table[index]; node != NULL; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            //存在
            return 1;
        }
    }
    //不存在
    return 0;
}
// 获取节点
void* get(HashMap* map, char* key) {
    int index = hashCode(key) % map->size;

    // 在链表中查找key
    for (Node* node = map->table[index]; node != NULL; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            // 如果已被使用，则删除该node
            if (strcmp(node->is_used, "yes") == 0) {
                Node* prev = NULL;
                Node* n = node;
                while (n !=NULL){
                    if (strcmp(n->is_used, "yes") == 0) {
                        if (prev == NULL) {
                            map->table[index] = n ->next;
                        } else{
                            prev->next = n->next;
                        }
                        Node* next = n->next;
                        // 释放value
                        ValueNode* valueNode = (ValueNode*)n->value;
                        while(valueNode != NULL){
                            ValueNode* valueNodeNext = valueNode->next;
                            free(valueNode->value);
                            free(valueNode);
                            valueNode = valueNodeNext;
                        }
                        free(n);
                        n = next;
                        continue;
                    } else{
                        prev = n;
                        n = n->next;
                    }
                }
                return NULL;
            }
            node->is_used = "yes";
            return node->value;
        }
    }
    return NULL;
}
