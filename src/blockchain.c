#include "blockchain.h"
#include <limits.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_THREADS 8

struct mining_args {
  struct block_core core;
  const unsigned char *difficulty;
  unsigned char *result_hash;
  uint32_t *result_nonce;
  int thread_id;
  volatile int *found;
  pthread_mutex_t *mutex;  // Added mutex for thread synchronization
};

int bc_init(struct blockchain *bc,
            unsigned char difficulty[SHA256_DIGEST_LENGTH]) {
  if (!bc || !difficulty)
    return -1;

  memset(bc, 0, sizeof(struct blockchain));  // This properly zeros bc->count
  memcpy(bc->difficulty, difficulty, SHA256_DIGEST_LENGTH);
  return 0;
}

int bc_verify(struct blockchain *bc) {
  if (!bc)
    return -1;

  for (size_t i = 0; i < bc->count; i++) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)&bc->blocks[i].core, sizeof(bc->blocks[i].core),
           hash);

    if (memcmp(bc->blocks[i].hash, hash, SHA256_DIGEST_LENGTH) != 0) {
      return -1;
    }

    if (i > 0 && memcmp(bc->blocks[i].core.p_hash, bc->blocks[i - 1].hash,
                        SHA256_DIGEST_LENGTH) != 0) {
      return -1;
    }
  }
  return 0;
}

bool is_hash_valid(const unsigned char *hash, const unsigned char *difficulty) {
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    if (hash[i] < difficulty[i]) {
      return true;  // Hash is smaller, so it meets the difficulty
    } else if (hash[i] > difficulty[i]) {
      return false;  // Hash is larger, so it doesn't meet the difficulty
    }
    // If equal, continue to next byte
  }
  return true;  // All bytes are equal, so hash meets difficulty
}
void *mine_block(void *arg) {
  struct mining_args *args = (struct mining_args *)arg;
  struct block_core local_core = args->core;
  unsigned char local_hash[SHA256_DIGEST_LENGTH];
  uint32_t nonce = args->thread_id;
  const unsigned char *difficulty = args->difficulty;

  while (1) {
    // Periodically check if another thread found a solution
    if ((nonce % 1000) == 0) {
      pthread_mutex_lock(args->mutex);
      if (*args->found) {
        pthread_mutex_unlock(args->mutex);
        break;
      }
      pthread_mutex_unlock(args->mutex);
    }
    
    // Check for overflow
    if (UINT_MAX - NUM_THREADS < nonce) {
      break;
    }
    
    local_core.nonce = nonce;
    SHA256((unsigned char *)&local_core, sizeof(local_core), local_hash);

    if (is_hash_valid(local_hash, difficulty)) {
      pthread_mutex_lock(args->mutex);
      if (!(*args->found)) {
        memcpy(args->result_hash, local_hash, SHA256_DIGEST_LENGTH);
        *args->result_nonce = nonce;
        *args->found = 1;
      }
      pthread_mutex_unlock(args->mutex);
      break;
    }
    
    nonce += NUM_THREADS;
  }
  return NULL;
}

int bc_add_block(struct blockchain *bc, const unsigned char data[DATA_SIZE]) {
  if (!bc || !data || bc->count >= BLOCKCHAIN_SIZE) {
    return -1;
  }

  struct block *b = &bc->blocks[bc->count];
  struct block_core *core = &b->core;

  memcpy(core->data, data, DATA_SIZE);
  core->index = bc->count;
  clock_gettime(CLOCK_REALTIME, &core->timestamp);

  if (bc->count > 0) {
    memcpy(core->p_hash, bc->blocks[bc->count - 1].hash, SHA256_DIGEST_LENGTH);
  } else {
    memset(core->p_hash, 0, SHA256_DIGEST_LENGTH);
  }

  pthread_t threads[NUM_THREADS];
  struct mining_args args[NUM_THREADS];
  unsigned char result_hash[SHA256_DIGEST_LENGTH];
  uint32_t result_nonce = 0;
  volatile int found = 0;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  int thread_created[NUM_THREADS] = {0};  // Track which threads were created

  for (int i = 0; i < NUM_THREADS; i++) {
    args[i].core = *core;
    args[i].difficulty = bc->difficulty;
    args[i].result_hash = result_hash;
    args[i].result_nonce = &result_nonce;
    args[i].thread_id = i;
    args[i].found = &found;
    args[i].mutex = &mutex;  // Pass the mutex to each thread
  }

  for (int i = 0; i < NUM_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, mine_block, &args[i]) != 0) {
      // Clean up already created threads if creation fails
      for (int j = 0; j < i; j++) {
        pthread_join(threads[j], NULL);
      }
      pthread_mutex_destroy(&mutex);
      return -1;
    }
    thread_created[i] = 1;
  }

  // Join all threads
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }

  // Clean up synchronization resources
  pthread_mutex_destroy(&mutex);

  if (!found) {
    return -1;
  }

  memcpy(b->hash, result_hash, SHA256_DIGEST_LENGTH);
  core->nonce = result_nonce;

  bc->count++;
  return 0;
}