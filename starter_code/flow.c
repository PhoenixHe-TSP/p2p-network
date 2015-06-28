//
// Created by htc on 15-6-28.
//

#include <stddef.h>
#include <unistd.h>
#include "flow.h"
#include "uthash.h"
#include "debug.h"

struct task_map {
  int peer_id;
  struct flow_task *task;
  UT_hash_handle hh;
} *tasks = NULL;

void handle_ack(struct packet_header *header, struct flow_task *task) {

}

void handle_data(struct packet_header *header, struct flow_task *task, void *data) {

}

void handle_denied(struct packet_header *header, struct flow_task *task) {
  struct task_map *tm;
  HASH_FIND_INT(tasks, &task->peer_id, tm);
  HASH_DEL(tasks, tm);
  free(tm);
  if (task->type == FLOW_RECV) {
    close(task->sockfd);
  }
  if (task->fail) {
    task->fail(task);
  }
}

void new_download_task(char *hash, struct flow_task *task) {
  if ((task->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("Cannot open socket for sending");
    if (task->fail) {
      task->fail(task);
    }
    return;
  }
  task->type = FLOW_RECV;

  struct task_map *tm = malloc(sizeof(struct task_map));
  tm->peer_id = task->peer_id;
  tm->task = task;
  HASH_ADD_INT(tasks, peer_id, tm);

  // TODO
}

void new_upload_task(struct flow_task* task) {
  task->type = FLOW_SEND;

  struct task_map *tm = malloc(sizeof(struct task_map));
  tm->peer_id = task->peer_id;
  tm->task = task;
  HASH_ADD_INT(tasks, peer_id, tm);

  // TODO
}

void new_packet(int peer_id, struct packet_header *header, char* data) {
  struct task_map *tm;
  HASH_FIND_INT(tasks, &peer_id, tm);
  if (tm == NULL) {
    DPRINTF(DEBUG_SOCKETS, "Unknown peer_id %d\n", peer_id);
    return;
  }
  struct flow_task *task = tm->task;

  switch (header->type) {
    case PACKET_ACK:
      handle_ack(header, task);
      break;

    case PACKET_DATA:
      handle_data(header, task, data);
      break;

    case PACKET_DENIED:
      handle_denied(header, task);
      break;

    default:
      break;
  }
}
