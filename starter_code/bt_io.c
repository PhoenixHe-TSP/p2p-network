//
// Created by htc on 15-6-28.
//

#include <arpa/inet.h>
#include <stdio.h>
#include "bt_io.h"
#include "peer.h"
#include "uthash.h"
#include "debug.h"

#define PACKET_MAGIC 15441
#define PACKET_VERSION 1

struct io_peer {
  int id;
  struct sockaddr_in addr;
  UT_hash_handle hh;
} *peers = NULL;

void bt_io_init() {
  struct bt_peer_s* p = peer_config.peers;
  while (p) {
    struct io_peer* peer = malloc(sizeof(struct io_peer));
    peer->id = p->id;
    memcpy(&peer->addr, &p->addr, sizeof(struct sockaddr_in));
    HASH_ADD_INT(peers, id, peer);

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

int parse_packet(char* raw, struct packet_header* header, char* body) {
  memcpy(header, raw, sizeof(struct packet_header));
  packet_ntoh(header);
  if (header->magic != PACKET_MAGIC || header->version != PACKET_VERSION) {
    fprintf(stderr, "Cannot parse unknown packet with MAGIC %d and version %d\n", header->magic, header->version);
    return -1;
  }

  int body_len = header->total_len - header->header_len;
  memcpy(body, raw + header->header_len, body_len);
  return body_len;
}

int send_packet(int peer_id, int type, int seq, int ack, char* body, int body_len) {
  DPRINTF(DEBUG_SOCKETS, "send packet to peer:%d type:%d seq:%d ack:%d body_len:%d\n",
          peer_id, type, seq, ack, body_len);

  struct io_peer *peer;
  HASH_FIND_INT(peers, &peer_id, peer);
  if (peer == NULL) {
    fprintf(stderr, "Unknown peer id %d\n", peer_id);
    return -1;
  }

  char data[sizeof(struct packet_header) + body_len];
  struct packet_header *header = (struct packet_header *) data;
  header->magic = PACKET_MAGIC;
  header->version = PACKET_VERSION;
  header->header_len = sizeof(struct packet_header);
  header->type = type;
  header->seq = seq;
  header->ack = ack;
  packet_hton(header);

  memcpy(data + sizeof(struct packet_header), body, body_len);

  int ret = sendto(peer_sockfd, data, sizeof(data), MSG_NOSIGNAL, (const struct sockaddr *) &peer->addr, sizeof(struct sockaddr_in));
  if (ret == -1) {
    DEBUG_PERROR("Cannot send packet\n");
  }
  return ret;
}
