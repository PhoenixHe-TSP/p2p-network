//
// Created by htc on 15-6-28.
//

#include <stddef.h>
#include <unistd.h>
#include "flow.h"
#include "uthash.h"
#include "timeout.h"
#include "debug.h"
#include "peer.h"
#include "utlist.h"

static struct task_recv_list {
  struct flow_task *task;
  struct task_recv_list *next, *prev;
};

static struct task_map {
  int peer_id;

  struct flow_task *cur_send_task;
  struct flow_task *cur_recv_task;
  struct task_recv_list *pending_recv_tasks;

  UT_hash_handle hh;
} *peer_tasks = NULL;

struct data_cache {
  size_t len;
  void* data[];
};

void next_recv_task(int id);

void flow_init() {
  struct bt_peer_s *peer = peer_config.peers;
  for (; peer; peer = peer->next) {
    if (peer->id == peer_config.identity) {
      continue;
    }

    struct task_map *tm = malloc(sizeof (struct task_map));
    memset(tm, 0, sizeof(struct task_map));
    tm->peer_id = peer->id;
    HASH_ADD_INT(peer_tasks, peer_id, tm);
  }
}

void handle_ack(struct packet_header *header, struct flow_task *task) {
  if (task->type == FLOW_RECV) {
    return;
  }

  if (header->ack != task->ack + 1) {
    DPRINTF(DEBUG_SOCKETS, "Unaccepted ACK packet\n");
    return;
  }

  ++task->ack;
  if (task->pos == BT_CHUNK_SIZE) {
    DPRINTF(DEBUG_SOCKETS, "SEND DONE\n");
    struct task_map *tm;
    HASH_FIND_INT(peer_tasks, &task->peer_id, tm);
    tm->cur_send_task = NULL;

    if (task->done) {
      task->done(task);
    }
    return;
  }

  int data_len = 1000;
  if (task->pos + data_len > BT_CHUNK_SIZE) {
    data_len = BT_CHUNK_SIZE - task->pos;
  }
  char data[data_len];
  memcpy(data, task->data + task->pos, (size_t) data_len);
  task->pos += data_len;

  send_packet(task->peer_id, PACKET_DATA, task->ack + 1, -1, data, data_len);
}

void handle_data(struct packet_header *header, struct flow_task *task, void *data) {
  size_t data_len = header->total_len - header->header_len;

  if (header->seq == task->ack + 1) {
    task->ack = header->seq;
    memcpy(task->data + task->pos, data, data_len);
    task->pos += data_len;

    while (!priq_size(task->window)) {
      int64_t seq;

      priq_top(task->window, &seq);
      if (seq <= task->ack) {
        priq_pop(task->window, NULL);
        continue;
      }

      if (seq != task->ack + 1) {
        break;
      }

      ++task->ack;
      struct data_cache *cache = priq_pop(task->window, NULL);
      memcpy(task->data + task->pos, cache->data, cache->len);
      task->pos += data_len;
      free(cache);
    }

  } else {
    struct data_cache *cache = malloc(sizeof(size_t) + data_len);
    cache->len = data_len;
    memcpy(cache->data, data, data_len);
    priq_push(task->window, cache, header->seq);
  }

  send_packet(task->peer_id, PACKET_ACK, -1, task->ack, NULL, 0);

  if (task->pos == BT_CHUNK_SIZE) {
    DPRINTF(DEBUG_SOCKETS, "RECV DONE\n");
    priq_free(task->window);

    if (task->done) {
      task->done(task);
    }

    next_recv_task(task->peer_id);
  }
}

void next_recv_task(int peer_id) {
  struct task_map *tm;
  HASH_FIND_INT(peer_tasks, &peer_id, tm);
  tm->cur_recv_task = NULL;
  if (tm->pending_recv_tasks == NULL) {
    return;
  }

  struct task_recv_list *node = tm->pending_recv_tasks;
  struct flow_task *task = node->task;
  DL_DELETE(tm->pending_recv_tasks, node);
  free(node);

  tm->cur_recv_task = task;
  send_packet(task->peer_id, PACKET_GET, 1, -1, task->data, SHA1_HASH_SIZE);
}

void handle_denied(struct packet_header *header, struct flow_task *task) {
  DPRINTF(DEBUG_SOCKETS, "task failed\n");
  struct task_map *tm;
  HASH_FIND_INT(peer_tasks, &task->peer_id, tm);
  tm->cur_recv_task = NULL;

  priq_free(task->window);
  if (task->fail) {
    task->fail(task);
  }
}

void new_download_task(char *hash, struct flow_task *task) {
  task->type = FLOW_RECV;
  task->window = priq_new(8);
  task->ack = 0;
  task->pos = 0;
  task->timeout_id = -1;
  memcpy(task->data, hash, SHA1_HASH_SIZE);

  struct task_map *tm;
  HASH_FIND_INT(peer_tasks, &task->peer_id, tm);

  struct task_recv_list *node = malloc(sizeof(struct task_recv_list));
  node->task = task;
  DL_APPEND(tm->pending_recv_tasks, node);

  if (tm->cur_recv_task == NULL) {
    next_recv_task(task->peer_id);
  }
}

void new_upload_task(struct flow_task* task) {
  task->type = FLOW_SEND;
  task->ack = 0;
  task->pos = 0;
  task->timeout_id = -1;

  struct task_map *tm;
  HASH_FIND_INT(peer_tasks, &task->peer_id, tm);

  if (tm->cur_send_task) {
    send_packet(task->peer_id, PACKET_DENIED, -1, -1, NULL, 0);
    if (task->fail) {
      task->fail(task);
    }
    return;
  }

  tm->cur_send_task = task;
  send_packet(task->peer_id, PACKET_DATA, 1, -1, NULL, 0);
}

void new_packet(int peer_id, struct packet_header *header, char* data) {
  struct task_map *tm;
  HASH_FIND_INT(peer_tasks, &peer_id, tm);

  switch (header->type) {
    case PACKET_ACK:
      if (!tm->cur_send_task) {
        DPRINTF(DEBUG_SOCKETS, "Unexcepted ACK packet\n");
        break;
      }
      handle_ack(header, tm->cur_send_task);
      break;

    case PACKET_DATA:
      if (!tm->cur_recv_task) {
        DPRINTF(DEBUG_SOCKETS, "Unexcepted DATA packet\n");
        break;
      }
      handle_data(header, tm->cur_recv_task, data);
      break;

    case PACKET_DENIED:
      if (!tm->cur_recv_task) {
        DPRINTF(DEBUG_SOCKETS, "Unexcepted DENIED packet\n");
        break;
      }
      handle_denied(header, tm->cur_recv_task);
      break;

    default:
      break;
  }
}

