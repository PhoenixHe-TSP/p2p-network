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

void task_init();

void new_file_task(char* chunkfile, char* outputfile);

void response_i_have(int peer_id, char *body);

void handle_i_have(int peer_id, char *body);


#endif //NETWORK_TASK_H


