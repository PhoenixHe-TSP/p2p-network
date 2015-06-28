//
// Created by htc on 15-6-28.
//

#ifndef NETWORK_FLOW_H
#define NETWORK_FLOW_H

#include "chunk.h"
#include "bt_io.h"

enum flow_task_type {
  FLOW_SEND = 0,
  FLOW_RECV = 1
};

struct flow_task {
  int type;
  char data[BT_CHUNK_SIZE];
  int peer_id;
  void* extra_data;
  void (*done)(struct flow_task* task);
  void (*fail)(struct flow_task* task);

  int sockfd;
};

void new_download_task(char* hash, struct flow_task*);

void new_upload_task(struct flow_task*);

void new_packet(int peer_id, struct packet_header *header, char* data);

#endif //NETWORK_FLOW_H
