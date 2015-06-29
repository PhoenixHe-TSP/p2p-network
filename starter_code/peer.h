//
// Created by htc on 15-6-25.
//

#ifndef NETWORK_PEER_H
#define NETWORK_PEER_H

#include "bt_parse.h"

extern bt_config_t peer_config;
extern int peer_sockfd;

void process_inbound_udp(int sock);

#endif //NETWORK_PEER_H
