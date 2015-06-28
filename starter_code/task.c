//
// Created by htc on 15-6-25.
//

#include "task.h"


void new_file_task(char* chunkfile, char* outputfile) {
  FILE* chunk_file = fopen(chunkfile, "r");
  if (chunk_file == NULL) {
    perror("Cannot open chunk file");
    return;
  }

  struct task_file *task_file = malloc(sizeof(struct task_file));

  task_file->fd = open(outputfile, O_CREAT | O_WRONLY);
  if (task_file->fd == -1) {
    perror("Cannot open output file");
    free(task_file);
    return;
  }

  int n = 0, i, index;
  char hash[SHA1_HASH_SIZE + 1];
  while (fscanf(chunk_file, "%d %s\n", &index, hash)) {
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
    memcpy(chunk->hash, hash, SHA1_HASH_SIZE);
  }

  init_file_broadcast(task_file);
}

void init_file_broadcast(struct task_file *task_file) {
}
