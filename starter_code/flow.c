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

static struct task_map {
  int id;
  struct flow_task *task;
  UT_hash_handle hh;
} *send_tasks = NULL, *recv_tasks = NULL;

struct data_cache {
  size_t len;
  void* data[];
};

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
    HASH_FIND_INT(send_tasks, &task->peer_id, tm);
    HASH_DEL(send_tasks, tm);
    free(tm);

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

  send_packet(task->peer_id, peer_sockfd, PACKET_DATA, task->ack + 1, -1, data, data_len);
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

  send_packet(task->peer_id, task->sockfd, PACKET_ACK, -1, task->ack, NULL, 0);

  if (task->pos == BT_CHUNK_SIZE) {
    DPRINTF(DEBUG_SOCKETS, "RECV DONE\n");

    struct task_map *tm;
    HASH_FIND_INT(recv_tasks, &task->sockfd, tm);
    HASH_DEL(recv_tasks, tm);
    free(tm);
    priq_free(task->window);
    close(task->sockfd);

    if (task->done) {
      task->done(task);
    }
  }
}

void handle_denied(struct packet_header *header, struct flow_task *task) {
  DPRINTF(DEBUG_SOCKETS, "task failed\n");
  struct task_map *tm;
  HASH_FIND_INT(recv_tasks, &task->sockfd, tm);
  HASH_DEL(recv_tasks, tm);
  free(tm);
  if (task->type == FLOW_RECV) {
    priq_free(task->window);
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
  task->window = priq_new(8);
  task->ack = 0;
  task->pos = 0;
  task->timeout_id = -1;

  struct task_map *tm = malloc(sizeof(struct task_map));
  tm->id = task->sockfd;
  tm->task = task;
  HASH_ADD_INT(recv_tasks, id, tm);

  send_packet(task->peer_id, task->sockfd, PACKET_GET, 1, -1, hash, SHA1_HASH_SIZE);
}

void new_upload_task(struct flow_task* task) {
  task->type = FLOW_SEND;
  task->ack = 1;
  task->pos = 0;
  task->timeout_id = -1;

  struct task_map *tm = malloc(sizeof(struct task_map));
  tm->id = task->peer_id;
  tm->task = task;
  HASH_ADD_INT(send_tasks, id, tm);

  send_packet(task->peer_id, peer_sockfd, PACKET_DATA, 1, -1, NULL, 0);
}

void new_packet(int peer_id, int fd, struct packet_header *header, char* data) {
  struct task_map *tm;

  if (fd == peer_sockfd) {
    HASH_FIND_INT(send_tasks, &peer_id, tm);
    if (tm == NULL) {
      DPRINTF(DEBUG_SOCKETS, "Unknown peer id %d, discarding packet\n", peer_id);
      return;
    }
  } else {
    HASH_FIND_INT(recv_tasks, &fd, tm);
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

void flow_set_fd(fd_set* fs, int* maxfd) {
  struct task_map *tm, *tmp;
  HASH_ITER(hh, recv_tasks, tm, tmp) {
    struct flow_task *task = tm->task;

    FD_SET(task->sockfd, fs);
    if (task->sockfd > *maxfd) {
      *maxfd = task->sockfd;
    }
  }
}

void flow_process_udp(fd_set* fs) {
  struct task_map *tm, *tmp;
  HASH_ITER(hh, recv_tasks, tm, tmp) {
    struct flow_task *task = tm->task;

    if (FD_ISSET(task->sockfd, fs)) {
      process_inbound_udp(task->sockfd);
    }
  }
}
