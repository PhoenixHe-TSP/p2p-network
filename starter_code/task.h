//
// Created by htc on 15-6-25.
//

#ifndef NETWORK_TASK_H
#define NETWORK_TASK_H

#include "sha.h"
#include "chunk.h"

struct task_file;

struct task_chunk {
  struct task_file* file_task;
  int status;
  int fd;
  int chunk_n;
  char hash[SHA1_HASH_SIZE];
};

struct task_file {
  int fd;
  int status;
  int n_chunks;
  struct task_chunk* chunk_tasks;
};

struct task_send {
  int status;
  char data[BT_CHUNK_SIZE];
};


void new_file_task();


#endif //NETWORK_TASK_H


