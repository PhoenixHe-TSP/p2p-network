//
// Created by htc on 15-6-28.
//

#ifndef NETWORK_BT_IO_H
#define NETWORK_BT_IO_H

#include "bt_parse.h"
#include "sha.h"

struct packet_header {
  uint16_t magic            : 16;
  unsigned int version      : 8;
  unsigned int type         : 8;
  uint16_t header_len       : 16;
  uint16_t total_len        : 16;
  unsigned int seq          : 32;
  unsigned int ack          : 32;
};

enum packet_type {
  PACKET_WHOHAS = 0,
  PACKET_IHAVE  = 1,
  PACKET_GET    = 2,
  PACKET_DATA   = 3,
  PACKET_ACK    = 4,
  PACKET_DENIED = 5
};

void bt_io_init();

int parse_packet(struct sockaddr_in* addr, char* raw, struct packet_header* packet, char* body);

int send_packet(int peer_id, int sockfd, int type, int seq, int ack, char* body, int body_len);

int free_peer_id(int peer_id);


#endif //NETWORK_BT_IO_H

