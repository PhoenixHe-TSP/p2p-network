//
// Created by htc on 15-6-25.
//

#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include "task.h"
#include "bt_io.h"
#include "peer.h"
#include "chunk.h"
#include "data.h"
#include "debug.h"
#include "timeout.h"
#include "uthash.h"
#include "utarray.h"
#include "flow.h"

enum task_chunk_status {
  STATUS_WAITING = 0,
  STATUS_DOWNLOADING = 1,
  STATUS_DONE = 2,
  STATUS_FAILED = -1
};

struct task_chunk {
  struct task_file* file_task;
  int status;
  int chunk_n;
  char hash[SHA1_HASH_SIZE];
  UT_array peers;
  struct flow_task flow;
  UT_hash_handle hh;
};

struct task_chunks {
  char hash[SHA1_HASH_SIZE];
  struct task_chunk *tasks;
  UT_hash_handle hh;
} *task_chunks_all = NULL;

struct task_file {
  int fd;
  int status;
  int n_chunks;
  int n_waiting_rsp;
  int n_downloading;
  int n_done;
  struct task_chunk* chunk_tasks;
};

struct task_peer_who_has_info {
  int peer_id;
  int timout_msec;
  int status;
  int n_try;
  struct task_file* task_file;
};

struct peer_status {
  int peer_id;
  UT_array pending_requests;
  UT_hash_handle hh;
} *peers_all = NULL;

void task_init() {
  bt_peer_t *peer = peer_config.peers;
  while (peer) {
    struct peer_status *ps = malloc(sizeof(struct peer_status));
    ps->peer_id = peer->id;
    utarray_init(&ps->pending_requests, &ut_ptr_icd);
    HASH_ADD_INT(peers_all, peer_id, ps);

    peer = peer->next;
  }
}

void free_task_file(struct task_file* task) {
  for (int i = 0; i < task->n_chunks; ++i) {
    struct task_chunk *chunk_task = task->chunk_tasks + i;
    utarray_done(&chunk_task->peers);

    struct task_chunks *task_chunks;
    HASH_FIND(hh, task_chunks_all, &chunk_task->hash, SHA1_HASH_SIZE, task_chunks);
    HASH_DEL(task_chunks->tasks, chunk_task);
    if (task_chunks->tasks == NULL) {
      HASH_DEL(task_chunks_all, task_chunks);
    }
  }
  close(task->fd);
  free(task);
}

void free_task_peer_who_has_info(struct task_peer_who_has_info *info) {
  struct peer_status *ps;
  HASH_FIND_INT(peers_all, &info->peer_id, ps);
  int len = utarray_len(&ps->pending_requests);
  for (int i = 0; i < len; ++i) {
    struct task_peer_who_has_info **x = (struct task_peer_who_has_info **) utarray_eltptr(&ps->pending_requests, i);
    if (*x == info) {
      *x = NULL;
      break;
    }
  }

  free(info);
}

void task_peer_who_has_timeout(struct task_peer_who_has_info *info) {
  if (info->status) {
    free_task_peer_who_has_info(info);
    return;
  }

  struct task_file *task_file = info->task_file;
  if (++info->n_try > 3) {
    fprintf(stderr, "peer %d not responding\n", info->peer_id);
    free_task_peer_who_has_info(info);
    if ((--task_file->n_waiting_rsp) == 0 && task_file->n_downloading == 0) {
      printf("GET failed: cannot download any piece of file.\n");
      free_task_file(task_file);
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
      info->status = STATUS_WAITING;
      info->task_file = task_file;
      info->timout_msec = 1000;
      info->n_try = 0;

      struct peer_status *ps;
      HASH_FIND_INT(peers_all, &info->peer_id, ps);
      utarray_push_back(&ps->pending_requests, &info);

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
  task_file->n_downloading = 0;
  task_file->n_done = 0;
  task_file->fd = open(outputfile, O_CREAT | O_WRONLY, 0666);
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
    chunk->file_task = task_file;
    chunk->chunk_n = i;
    chunk->status = STATUS_WAITING;
    hex2binary(hash, strlen(hash), (uint8_t *) chunk->hash);
    utarray_init(&chunk->peers, &ut_int_icd);

    struct task_chunks *task_chunks_p;
    HASH_FIND(hh, task_chunks_all, chunk->hash, SHA1_HASH_SIZE, task_chunks_p);
    if (task_chunks_p == NULL) {
      task_chunks_p = malloc(sizeof(struct task_chunks));
      task_chunks_p->tasks = NULL;
      memcpy(task_chunks_p->hash, chunk->hash, SHA1_HASH_SIZE);
      HASH_ADD(hh, task_chunks_all, hash, SHA1_HASH_SIZE, task_chunks_p);
    }
    HASH_ADD(hh, task_chunks_p->tasks, file_task, sizeof(void*), chunk);
  }

  init_file_broadcast(task_file);
}

void response_i_have(int peer_id, char *body) {
  int n = *((uint8_t*)body);
  char data[n * SHA1_HASH_SIZE + sizeof(int)];

  int ret = data_request_chunks(n, body + sizeof(int), data + sizeof(int));
  *((uint8_t*)data) = (uint8_t) ret;

  if (ret == 0) {
    return;
  }

  DPRINTF(DEBUG_PROCESSES, "Response to peer %d : IHAVE %d blocks\n", peer_id, ret);
  send_packet(peer_id, PACKET_IHAVE, -1, -1, data, sizeof(data));
}

void handle_download_done(struct flow_task* flow) {
  struct task_chunk *chunk = flow->extra_data;
  struct task_file *file = chunk->file_task;
  chunk->status = STATUS_DONE;
  // TODO: check hash value

  if (lseek(file->fd, chunk->chunk_n * BT_CHUNK_SIZE, SEEK_SET) == -1) {
    perror("Cannot seek position in file for writing");
  } else {
    int size = write(file->fd, flow->data, BT_CHUNK_SIZE);
    if (size != BT_CHUNK_SIZE) {
      fprintf(stderr, "Cannot write to file, the file content maybe incomplete\n");
    }
  }

  data_save_chunk(chunk->hash, flow->data);

  --file->n_downloading;
  ++file->n_done;
  if (file->n_done == file->n_chunks) {
    printf("Finish downloading\n");
    free_task_file(file);
  }
}

void handle_download_fail(struct flow_task* flow) {
  struct task_chunk *chunk = flow->extra_data;
  struct task_file *file = chunk->file_task;
  if (!utarray_len(&chunk->peers)) {
    fprintf(stderr, "Cannot download part of file\n");
    chunk->status = STATUS_FAILED;
    file->status = STATUS_FAILED;
    return;
  }

  flow->peer_id = *(int*) utarray_back(&chunk->peers);
  utarray_pop_back(&chunk->peers);
  new_download_task(chunk->hash, flow);
}

void handle_i_have(int peer_id, char *body) {
  struct peer_status *ps;
  HASH_FIND_INT(peers_all, &peer_id, ps);
  int len = utarray_len(&ps->pending_requests);
  for (int i = 0; i < len; ++i) {
    struct task_peer_who_has_info **x = (struct task_peer_who_has_info **) utarray_eltptr(&ps->pending_requests, i);
    if (*x == NULL) {
      continue;
    }
    if ((*x)->status == STATUS_WAITING) {
      (*x)->status = STATUS_DONE;
      --(*x)->task_file->n_waiting_rsp;
    }
  }
  utarray_clear(&ps->pending_requests);

  int n = *((uint8_t*) body);
  body += sizeof(uint32_t);
  for (int i = 0; i < n; ++i) {
    char* hash = body + i * SHA1_HASH_SIZE;

    struct task_chunks *task_chunks_p;
    HASH_FIND(hh, task_chunks_all, hash, SHA1_HASH_SIZE, task_chunks_p);
    if (task_chunks_p == NULL) {
      continue;
    }
    struct task_chunk *chunk, *tmp;
    HASH_ITER(hh, task_chunks_p->tasks, chunk, tmp) {

      if (chunk->status == STATUS_WAITING || chunk->status == STATUS_FAILED) {
        ++chunk->file_task->n_downloading;
        struct flow_task *flow = malloc(sizeof(struct flow_task));
        flow->peer_id = peer_id;
        flow->extra_data = chunk;
        flow->done = handle_download_done;
        flow->fail = handle_download_fail;
        new_download_task(hash, flow);

      } else if (chunk->status == STATUS_DOWNLOADING) {
        utarray_push_back(&chunk->peers, &peer_id);
      }
    }
  }
}

void handle_get_done(struct flow_task* flow) {
  free(flow);
}

void handle_get(int peer_id, char *hash) {
  struct flow_task *flow = malloc(sizeof(struct flow_task));
  flow->peer_id = peer_id;
  flow->done = handle_get_done;
  flow->fail = handle_get_done;
  if (data_load_chunk(hash, flow->data)) {
    free(flow);
    send_packet(peer_id, PACKET_DENIED, -1, -1, hash, 0);
    return;
  }
  new_upload_task(flow);
}

