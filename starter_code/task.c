//
// Created by htc on 15-6-25.
//

#include "task.h"
#include "bt_io.h"
#include "peer.h"
#include "chunk.h"
#include "data.h"
#include "debug.h"
#include "timeout.h"

struct task_chunk {
  struct task_file* file_task;
  int status;
  int peer_id;
  int chunk_n;
  char hash[SHA1_HASH_SIZE];
};

struct task_file {
  int fd;
  int status;
  int n_chunks;
  int n_waiting_rsp;
  int n_downloading;
  struct task_chunk* chunk_tasks;
};

struct task_send {
  int status;
  int peer_id;
  char data[BT_CHUNK_SIZE];
};

struct task_peer_who_has_info {
  int peer_id;
  int timout_msec;
  int status;
  int n_try;
  struct task_file* task_file;
};

void task_peer_who_has_timeout(struct task_peer_who_has_info *info) {
  if (info->status) {
    free(info);
    return;
  }

  struct task_file *task_file = info->task_file;
  if (++info->n_try > 3) {
    fprintf(stderr, "peer %d not responding\n", info->peer_id);
    free(info);
    if ((--task_file->n_waiting_rsp) == 0 && task_file->n_downloading == 0) {
      printf("GET failed: cannot download any piece of file.\n");
      free(task_file);
    }
    return;
  }

  char data[sizeof(int) + SHA1_HASH_SIZE * task_file->n_chunks];
  char* p = data;
  *((int*) p) = task_file->n_chunks;
  p += 4;
  for (int i = 0; i < task_file->n_chunks; ++i) {
    memcpy(p, task_file->chunk_tasks[i].hash, SHA1_HASH_SIZE);
    p += SHA1_HASH_SIZE;
  }

  send_packet(info->peer_id, PACKET_WHOHAS, -1, -1, data, sizeof(data));

  timeout_register((uint64_t) info->timout_msec, (void (*)(void *)) task_peer_who_has_timeout, info);
  info->timout_msec += info->timout_msec;
}

void init_file_broadcast(struct task_file *task_file) {

  bt_peer_t *peer = peer_config.peers;
  while (peer) {
    if (peer->id != peer_config.identity) {
      ++task_file->n_waiting_rsp;
      struct task_peer_who_has_info *info = malloc(sizeof(struct task_peer_who_has_info));
      info->peer_id = peer->id;
      info->status = 0;
      info->task_file = task_file;
      info->timout_msec = 1000;
      info->n_try = 0;
      task_peer_who_has_timeout(info);
    }
    peer = peer->next;
  }
}

void new_file_task(char* chunkfile, char* outputfile) {
  FILE* chunk_file = fopen(chunkfile, "r");
  if (chunk_file == NULL) {
    perror("Cannot open chunk file");
    return;
  }

  struct task_file *task_file = malloc(sizeof(struct task_file));
  task_file->n_waiting_rsp = 0;
  task_file->fd = open(outputfile, O_CREAT | O_WRONLY);
  if (task_file->fd == -1) {
    perror("Cannot open output file");
    free(task_file);
    return;
  }

  int n = 0, i, index;
  char hash[SHA1_HASH_SIZE * 2 + 1];
  while (fscanf(chunk_file, "%d %s\n", &index, hash) != -1) {
    ++n;
  }
  task_file->n_chunks = n;
  task_file->chunk_tasks = malloc(n * sizeof(struct task_chunk));
  rewind(chunk_file);
  for (i = 0; i < n; ++i) {
    fscanf(chunk_file, "%d %s\n", &index, hash);
    struct task_chunk *chunk = task_file->chunk_tasks + i;
    chunk->chunk_n = i;
    chunk->status = 0;
    hex2binary(hash, strlen(hash), (uint8_t *) chunk->hash);
  }

  init_file_broadcast(task_file);
}

void response_i_have(int peer_id, char *body) {
  int n = *((int*)body);
  char data[n * SHA1_HASH_SIZE + sizeof(int)];

  int ret = data_request_chunks(n, body + sizeof(int), data + sizeof(int));
  if (ret == 0) {
    return;
  }
  *((int*)data) = ret;

  DPRINTF(DEBUG_PROCESSES, "Response to peer %d : IHAVE %d blocks\n", peer_id, ret);
  send_packet(peer_id, PACKET_IHAVE, -1, -1, data, sizeof(data));
}

void handle_i_have(int peer_id, char *body) {
}



