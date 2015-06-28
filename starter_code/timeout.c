//
// Created by htc on 15-6-26.
//


#include "timeout.h"
#include "uthash.h"
#include "priority_queue.h"

#include <time.h>
#include <sys/time.h>

struct timeout_task {
  int id;
  struct timespec timeout;
  void (*handler)(void* data);
  void* data;
  UT_hash_handle hh;
} *tasks = NULL;

static int global_task_id;
static pri_queue queue;

void timeout_init() {
  queue = priq_new(16);
  global_task_id = 1;
}

int timeout_register(uint64_t msec, void (*handler)(void* data), void* data) {
  struct timeout_task* task = malloc(sizeof(struct timeout_task));
  task->id = global_task_id++;

  clock_gettime(CLOCK_MONOTONIC, &task->timeout);
  task->timeout.tv_nsec += msec * 1000 * 1000;
  while (task->timeout.tv_nsec > 1000000000ULL) {
    task->timeout.tv_nsec -= 1000000000ULL;
    task->timeout.tv_sec++;
  }

  task->handler = handler;
  task->data = data;

  priq_push(queue, task, task->timeout.tv_sec * 1000 + task->timeout.tv_nsec / 1000 / 1000);
  HASH_ADD_INT(tasks, id, task);
  return 0;
}

int timeout_cancel(int timeout_id) {
  struct timeout_task *task;
  HASH_FIND_INT(tasks, &timeout_id, task);
  if (task == NULL) {
    return 0;
  }
  task->handler = NULL;
  return 1;
}

static int time_compare(struct timespec *a, struct timespec *b) {
  if (a->tv_sec < b->tv_sec) {
    return 1;
  }
  if (a->tv_sec > b->tv_sec) {
    return 0;
  }
  return a->tv_nsec < b->tv_nsec;
}

int timeout_dispatch() {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

  while (priq_size(queue)) {
    struct timeout_task *task = priq_top(queue, NULL);
    if (time_compare(&now, &task->timeout)) {
      break;
    }

    priq_pop(queue, NULL);
    if (task->handler) {
      task->handler(task->data);
    }
    HASH_DEL(tasks, task);
    free(task);
  }

  return 0;
}