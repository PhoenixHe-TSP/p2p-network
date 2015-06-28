//
// Created by htc on 15-6-25.
//

#ifndef NETWORK_TASK_H
#define NETWORK_TASK_H

#include <sys/socket.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "sha.h"
#include "chunk.h"

struct task_file;

struct task_chunk {
  struct task_file* file_task;
  int status;
  int peer_id;
  int chunk_n;
  char hash[SHA1_HASH_SIZE + 1];
};

struct task_file {
  int fd;
  int status;
  int n_chunks;
  struct task_chunk* chunk_tasks;
};

struct task_send {
  int status;
  int peer_id;
  char data[BT_CHUNK_SIZE];
};


void init_file_broadcast(struct task_file *pFile);


void new_file_task(char* chunkfile, char* outputfile);


#endif //NETWORK_TASK_H


