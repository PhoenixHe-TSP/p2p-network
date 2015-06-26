//
// Created by htc on 15-6-26.
//

#include "timeout.h"
#include "priority_queue.h"

#include <time.h>

struct timeout_task {
  int id;
  struct timespec timeout;
  void (*handler)(void* data);
  void* data;
};

static int global_task_id;
static pri_queue queue;

void timeout_init() {
  queue = priq_new(16);
  global_task_id = 1;
}

int timeout_register(uint64_t msec, void (*handler)(void* data)) {
  struct timeout_task* task = malloc(sizeof(struct timeout_struct));
  task->id = global_task_id++;

  clock_gettime(CLOCK_REALTIME, &task->timeout);
  task->timeout.tv_nsec += msec * 1000 * 1000;
  while (task->timeout.tv_nsec > 1000000000ULL) {
    task->timeout.tv_nsec -= 1000000000ULL;
    task->timeout.tv_sec++;
  }

  task->handler = handler;
  task->data = data;
}

int timeout_cancel(int timeout_id);

int timeout_dispatch();