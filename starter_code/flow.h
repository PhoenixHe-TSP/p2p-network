//
// Created by htc on 15-6-28.
//

#ifndef NETWORK_FLOW_H
#define NETWORK_FLOW_H

#include "chunk.h"
#include "bt_io.h"
#include "priority_queue.h"

enum flow_task_type {
  FLOW_SEND = 0,
  FLOW_RECV = 1
};

struct flow_packet {
  int seq;
  int pos;
  int data_len;
  struct flow_packet *next;
};

struct flow_task {
  int type;
  int peer_id;
  void* extra_data;
  void (*done)(struct flow_task* task);
  void (*fail)(struct flow_task* task);

  int ack;
  int pos;
  int timeout_id;
  int timeout_cnt;

  int window_size;

  // send window
  int dup_ack;
  int send_window_size;
  struct flow_packet *send_window, *send_window_tail;
  // recv window
  pri_queue recv_window;

  char data[BT_CHUNK_SIZE];
};

void flow_init();

void new_download_task(char* hash, struct flow_task*);

void new_upload_task(struct flow_task*);

void new_packet(int peer_id, struct packet_header *header, char* data);

#endif //NETWORK_FLOW_H
