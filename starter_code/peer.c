/*
 * peer.c
 * 
 * Author: Tianhao Wang <thwang11@fudan.edu.cn>,
 *
 * Modified from CMU 15-441,
 * Original Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *                   Dave Andersen
 * 
 * Class: Networks (Spring 2015)
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "data.h"
#include "timeout.h"
#include "task.h"
#include "bt_io.h"
#include "flow.h"

void peer_run(bt_config_t *config);

bt_config_t peer_config;
int peer_sockfd;

int main(int argc, char **argv) {

  bt_init(&peer_config, argc, argv);

#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(peer_config.chunk_file, "chunkfile");
  strcpy(peer_config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&peer_config);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&peer_config);
  }
#endif

  data_init();
  timeout_init();
  task_init();
  bt_io_init();

  peer_run(&peer_config);
  return 0;
}


void process_inbound_udp(int sock) {
#define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN], data[BUFLEN];

  fromlen = sizeof(from);
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

  struct packet_header header;
  int peer_id = parse_packet(&from, buf, &header, data);
  if (peer_id == -1) {
    return;
  }

  switch (header.type) {
    case PACKET_WHOHAS:
      response_i_have(peer_id, data);
      break;

    case PACKET_IHAVE:
      handle_i_have(peer_id, data);
      break;

    case PACKET_GET:
      handle_get(peer_id, data);
      break;

    case PACKET_ACK:
    case PACKET_DATA:
    case PACKET_DENIED:
      new_packet(peer_id, sock, &header, data);
      break;

    default:
      fprintf(stderr, "Unknown type %d\n", header.type);
  }

}

void handle_user_input(char *line, void *cbdata) {
  char chunkf[256], outf[256];

  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));

  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      new_file_task(chunkf, outf);
    }

  } else if (strcmp(line, "BYE") == 0) {
    exit(0);

  } else {
    printf("Unknown command.\n");
  }
}


void peer_run(bt_config_t *config) {
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;

  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }

  if ((peer_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }

  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);

  if (bind(peer_sockfd, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }

  spiffy_init(config->identity, (struct sockaddr *) &myaddr, sizeof(myaddr));

  struct timeval timeout;

  while (1) {
    int nfds = peer_sockfd;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(peer_sockfd, &readfds);
    flow_set_fd(&readfds, &nfds);

    timeout_get_timeval(&timeout);
    nfds = select(1 + nfds, &readfds, NULL, NULL, &timeout);

    if (nfds > 0) {
      if (FD_ISSET(peer_sockfd, &readfds)) {
        process_inbound_udp(peer_sockfd);
      }

      flow_process_udp(&readfds);

      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                           "Currently unused");
      }
    }

    timeout_dispatch();
  }
}
