//
// Created by htc on 15-6-28.
//

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include "bt_io.h"
#include "peer.h"
#include "uthash.h"
#include "debug.h"
#include "spiffy.h"

#define PACKET_MAGIC 15441
#define PACKET_VERSION 1

struct io_peer {
  int id;
  struct sockaddr_in addr;
  UT_hash_handle hh_id;
  UT_hash_handle hh_addr;
} *peers_id = NULL, *peers_addr = NULL;

static int max_id = 0;

void bt_io_init() {
  struct bt_peer_s* p = peer_config.peers;
  while (p) {
    struct io_peer* peer = malloc(sizeof(struct io_peer));
    peer->id = p->id;
    memcpy(&peer->addr, &p->addr, sizeof(struct sockaddr_in));
    if (peer->id > max_id) {
      max_id = peer->id;
    }

    HASH_ADD(hh_id, peers_id, id, sizeof(int), peer);
    HASH_ADD(hh_addr, peers_addr, addr, sizeof(struct sockaddr_in), peer);

    p = p->next;
  }
}

void packet_ntoh(struct packet_header*header) {
  header->magic = ntohs(header->magic);
  header->header_len = ntohs(header->header_len);
  header->total_len = ntohs(header->total_len);
  header->ack = ntohl(header->ack);
  header->seq = ntohl(header->seq);
}

void packet_hton(struct packet_header* header) {
  header->magic = htons(header->magic);
  header->header_len = htons(header->header_len);
  header->total_len = htons(header->total_len);
  header->ack = htonl(header->ack);
  header->seq = htonl(header->seq);
}

int parse_packet(struct sockaddr_in* addr, char* raw, struct packet_header* header, char* body) {
  struct io_peer *peer = NULL;
  HASH_FIND(hh_addr, peers_addr, addr, sizeof(struct sockaddr_in), peer);
  if (peer == NULL) {
    peer = malloc(sizeof(struct io_peer));
    peer->id = ++max_id;
    memcpy(&peer->addr, addr, sizeof(struct sockaddr_in));

    HASH_ADD(hh_id, peers_id, id, sizeof(int), peer);
    HASH_ADD(hh_addr, peers_addr, addr, sizeof(struct sockaddr_in), peer);

    DPRINTF(DEBUG_SOCKETS, "New peer from %s:%d <- %d\n",
           inet_ntoa(addr->sin_addr),
           ntohs(addr->sin_port), peer->id);
  }

  int peer_id = peer->id;

  memcpy(header, raw, sizeof(struct packet_header));
  packet_ntoh(header);
  if (header->magic != PACKET_MAGIC || header->version != PACKET_VERSION) {
    fprintf(stderr, "Cannot parse unknown packet with MAGIC %d and version %d\n", header->magic, header->version);
    return -1;
  }

  size_t body_len = header->total_len - header->header_len;
  memcpy(body, raw + header->header_len, body_len);

  DPRINTF(DEBUG_SOCKETS, "receive packet from peer:%d type:%d seq:%d ack:%d body_len:%d\n",
          peer_id, header->type, header->seq, header->ack, body_len);

  return peer_id;
}

int send_packet(int peer_id, int sockfd, int type, int seq, int ack, char* body, int body_len) {
  DPRINTF(DEBUG_SOCKETS, "send packet to peer:%d type:%d seq:%d ack:%d body_len:%d\n",
          peer_id, type, seq, ack, body_len);

  struct io_peer *peer = NULL;
  HASH_FIND(hh_id, peers_id, &peer_id, sizeof(int), peer);
  if (peer == NULL) {
    fprintf(stderr, "Unknown peer id %d\n", peer_id);
    return -1;
  }

  char data[sizeof(struct packet_header) + body_len];
  struct packet_header *header = (struct packet_header *) data;
  header->magic = PACKET_MAGIC;
  header->version = PACKET_VERSION;
  header->header_len = sizeof(struct packet_header);
  header->total_len = (uint16_t) (header->header_len + body_len);
  header->type = (unsigned int) type;
  header->seq = (unsigned int) seq;
  header->ack = (unsigned int) ack;
  packet_hton(header);

  if (body && body_len) {
    memcpy(data + sizeof(struct packet_header), body, (size_t) body_len);
  }

  int ret = spiffy_sendto(sockfd, data, sizeof(data), MSG_NOSIGNAL, (const struct sockaddr *) &peer->addr, sizeof(struct sockaddr_in));
  if (ret == -1) {
    DEBUG_PERROR("Cannot send packet\n");
  }

  return ret;
}

int free_peer_id(int peer_id) {
  struct io_peer *peer;
  HASH_FIND(hh_id, peers_id, &peer_id, sizeof(int), peer);
  if (peer == NULL) {
    fprintf(stderr, "Try to free id %d but doesn't exist\n", peer_id);
    return -1;
  }

  HASH_DELETE(hh_id, peers_id, peer);
  HASH_DELETE(hh_addr, peers_addr, peer);
  return 0;
}
