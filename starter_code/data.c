//
// Created by htc on 15-6-25.
//

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "data.h"
#include "sha.h"
#include "uthash.h"
#include "debug.h"
#include "chunk.h"

struct chunk_data {
  char hash[SHA1_HASH_SIZE];
  int owned;
  int global_id;
  UT_hash_handle hh;
} *chunks = NULL;

static char master_file_name[256];

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

    struct chunk_data *chunk = malloc(sizeof(struct chunk_data));
    chunk->owned = 0;
    chunk->global_id = chunk_n;
    hex2binary(buf, strlen(buf), (uint8_t *) chunk->hash);
    DPRINTF(DEBUG_INIT, "add chunk: %d %s\n", chunk_n, buf);
    HASH_ADD(hh, chunks, hash, SHA1_HASH_SIZE,chunk);
  }

  fclose(fd);
  fd = fopen(peer_config.has_chunk_file, "r");
  while (fgets(line, 256, fd)) {
    if (sscanf(line, "%d %s", &chunk_n, buf) != 2) {
      continue;
    };

    char hash[SHA1_HASH_SIZE];
    hex2binary(buf, strlen(buf), (uint8_t *) hash);
    struct chunk_data *chunk;
    HASH_FIND(hh, chunks, hash, SHA1_HASH_SIZE, chunk);
    if (chunk == NULL) {
      fprintf(stderr, "Block %s is found in haschunks file but doesn't exist in masterchunks file\n", buf);
      continue;
    }

    chunk->owned = 1;
  }
  fclose(fd);
}

int data_request_chunks(int chunk_n, char* required, char* out) {
  int ret = 0;
  for (int i = 0; i < chunk_n; ++i) {
    struct chunk_data *chunk = NULL;
    HASH_FIND(hh, chunks, required + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE, chunk);
    if (chunk != NULL && chunk->owned) {
      memcpy(out + (ret++) * SHA1_HASH_SIZE, required + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE);
    }
  }
  return ret;
}


int data_load_chunk(char* hash, char* dest) {
  struct chunk_data *chunk;
  HASH_FIND(hh, chunks, hash, SHA1_HASH_SIZE, chunk);
  if (chunk == NULL || !chunk->owned) {
    return -1;
  }

  int fd = open(master_file_name, O_RDONLY);
  if (fd < 0) {
    perror("Cannot open master file for reading");
    return -1;
  }

  if (lseek(fd, chunk->global_id * BT_CHUNK_SIZE, SEEK_SET) == -1) {
    perror("Cannot seek in master file");
    close(fd);
    return -1;
  }

  if (read(fd, dest, BT_CHUNK_SIZE) != BT_CHUNK_SIZE) {
    fprintf(stderr, "Read failed\n");
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

int data_save_chunk(char* hash, char* data) {
  struct chunk_data *chunk;
  HASH_FIND(hh, chunks, hash, SHA1_HASH_SIZE, chunk);
  if (chunk == NULL) {
    fprintf(stderr, "Chunk not found while saving\n");
    return -1;
  }

  chunk->owned = 1;
  return 0;
}
