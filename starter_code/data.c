//
// Created by htc on 15-6-25.
//

#include <stdio.h>
#include "data.h"
#include "sha.h"
#include "uthash.h"
#include "debug.h"
#include "chunk.h"

struct chunk_data {
  char hash[SHA1_HASH_SIZE];
  int global_id;
  UT_hash_handle hh;
} *chunks = NULL;

char master_file_name[256];

void data_init() {
  FILE* fd = fopen(peer_config.chunk_file, "r");
  char buf[256], line[256];
  fgets(line, 256, fd);
  sscanf(line, "%s %s", buf, master_file_name);
  DPRINTF(DEBUG_INIT, "set master file: %s\n", master_file_name);
  int chunk_n;

  fgets(line, 256, fd);
  while (fgets(line, 256, fd)) {
    if (sscanf(line, "%d %s", &chunk_n, buf) != 2) {
      continue;
    };

    struct chunk_data* chunk = malloc(sizeof(struct chunk_data));
    chunk->global_id = chunk_n;
    hex2binary(buf, strlen(buf), (uint8_t *) chunk->hash);
    DPRINTF(DEBUG_INIT, "add chunk: %d %s\n", chunk_n, buf);
    HASH_ADD(hh, chunks, hash, SHA1_HASH_SIZE,chunk);
  }
}

int data_request_chunks(int chunk_n, char* required, char* out) {
  int ret = 0;
  for (int i = 0; i < chunk_n; ++i) {
    struct chunk_data *chunk = NULL;
    HASH_FIND(hh, chunks, required + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE, chunk);
    if (chunk != NULL) {
      memcpy(out + (ret++) * SHA1_HASH_SIZE, required + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE);
    }
  }
  return ret;
}
