#include <time.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_router.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *mapping;
    struct sr_nat_mapping *next;
    mapping = nat->mappings;
    while(mapping != NULL){
      next = mapping->next;
      if(mapping->type == nat_mapping_tcp){
        destroy_connections(nat, mapping);
        if(mapping->conns == NULL && difftime(curtime, mapping->last_updated) > 0.5){
          destroy_mapping(nat, mapping);
        }
      }else if(mapping->type == nat_mapping_icmp){
        if(difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout){
          destroy_mapping(nat, mapping);
        }
      }
      mapping = next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL, *mapping;
  mapping = nat->mappings;
  while(mapping != NULL){
    if(mapping->type == type && mapping->aux_ext == aux_ext){
      copy = mapping;
      break;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL, *mapping;
  mapping = nat->mappings;
  while(mapping != NULL){
    if(mapping->ip_int == ip_int && mapping->type == type && mapping->aux_int == aux_int){
      copy = mapping;
      break;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *next_m = nat->mappings;
  mapping = malloc(sizeof(struct sr_nat_mapping));
  assert(mapping != NULL);
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->type = type;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  nat->mappings = mapping;
  mapping->next = next_m;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/*=======destroy tcp connections========*/
void destroy_connections(struct sr_nat *nat, struct sr_nat_mapping *mapping){
  time_t curtime = time(NULL);
  struct sr_nat_connection *connection, *next;
  connection = mapping->conns;
  while(connection != NULL){
    next = connection->next;
    if(connection->tcp_state == ESTABLISHED){
      if(difftime(curtime, connection->last_updated) > nat->tcp_estb_timeout){
        struct sr_nat_connection *cur_conn = mapping->conns;
        if(cur_conn != NULL){
          if(cur_conn == connection){
            mapping->conns = connection->next;
          }else{
            while(cur_conn->next != NULL && cur_conn->next != connection){
              cur_conn = cur_conn->next;
            }
            if(cur_conn != NULL){
              cur_conn->next = connection->next;
            }
          }
          if(cur_conn != NULL){
            free(connection);
          }
        }
      }
    }else{
      if(difftime(curtime, connection->last_updated) > nat->tcp_trns_timeout){
        struct sr_nat_connection *cur_conn = mapping->conns;
        if(cur_conn != NULL){
          if(cur_conn == connection){
            mapping->conns = connection->next;
          }else{
            while(cur_conn->next != NULL && cur_conn->next != connection){
              cur_conn = cur_conn->next;
            }
            if(cur_conn != NULL){
              cur_conn->next = connection->next;
            }
          }
          if(cur_conn != NULL){
            free(connection);
          }
        }
      }
    }
    connection = next;
  }
}

/*=========destroy nat mapping===========*/
void destroy_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping){
  struct sr_nat_mapping *cur_map = nat->mappings;
  if(cur_map != NULL){
    if(cur_map == mapping){
      nat->mappings = mapping->next;
    }else{
      while(cur_map->next != NULL && cur_map->next != mapping){
        cur_map = cur_map->next;
      }
      if(cur_map == NULL){
        return;
      }
      cur_map->next = mapping->next;
    }
    if(mapping->type == nat_mapping_tcp){
      nat->available_ports[mapping->aux_ext] = 0;
    }else if(mapping->type == nat_mapping_icmp){
      nat->available_icmp_identifiers[mapping->aux_ext] = 0;
    }
    struct sr_nat_connection *conn, *next_n;
    conn = mapping->conns;
    while(conn != NULL){
      next_n = conn->next;
      free(conn);
      conn = next_n;
    }
    free(mapping);
  }
}

/*=====generate unique icmp identifier======*/
int generate_icmp_id(struct sr_nat *nat){
  pthread_mutex_lock(&(nat->lock));
  int i = MIN_ICMP_IDENTIFIER;
  uint16_t *icmp_ids = nat->available_icmp_identifiers;
  for(i = MIN_ICMP_IDENTIFIER; i <= TOTAL_ICMP_IDENTIFIERS; i++){
    if(icmp_ids[i] == 0){
      icmp_ids[i] = 1;
      pthread_mutex_unlock(&(nat->lock));
      return i;
    }
  }
  pthread_mutex_unlock(&(nat->lock));
  return -1;
}

/*=======generate unique port========*/
int generate_port(struct sr_nat *nat){
  pthread_mutex_lock(&(nat->lock));
  int i;
  uint16_t *ports = nat->available_ports;
  for(i = MIN_PORT; i <= TOTAL_PORTS; i++){
    if(ports[i] == 0){
      ports[i] = 1;
      pthread_mutex_unlock(&(nat->lock));
      return i;
    }
  }
  pthread_mutex_unlock(&(nat->lock));
  return -1;
}

/*=======get connection given ip=======*/
struct sr_nat_connection *sr_nat_lookup_tcp_connection(struct sr_nat_mapping *mapping, uint32_t ip_conn){
  struct sr_nat_connection *conn = mapping->conns;
  while(conn != NULL){
    if(conn->ip == ip_conn){
      return conn;
    }
    conn = conn->next;
  }
  return NULL;
}

/*======insert connection given ip======*/
struct sr_nat_connection *sr_nat_insert_tcp_connection(struct sr_nat_mapping *mapping, uint32_t ip_conn){
  struct sr_nat_connection *conn = NULL;
  conn = malloc(sizeof(struct sr_nat_connection));
  assert(conn != NULL);
  memset(conn, 0, sizeof(struct sr_nat_connection));
  conn->ip = ip_conn;
  conn->tcp_state = CLOSED;
  conn->last_updated = time(NULL);
  struct sr_nat_connection *next = mapping->conns;
  mapping->conns = conn;
  conn->next = next;
  return conn;
}









