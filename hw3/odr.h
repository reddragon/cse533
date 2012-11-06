#ifndef _ODR_H_
#define _ODR_H_

#include "vector.h"

// TODO Change this to something appropriate
#define TTL_MS 1000

// TODO Define ethernet_frame Type macros here
// TODO Choose a type for ODR packets

typedef struct ethernet_frame {
  // TODO Fill this up here
  // Dest MAC addr (6 bytes)
  // Src MAC addr (6 bytes)
  // Type (2 bytes)
  // Payload (upto 1518 - (6+6+2) - 4 bytes)
  // CRC
} ethernet_frame;

// TODO How do we figure out what is the length of the 
// payload?

typedef struct odr_tentry {
  unsigned short portno;
  char *sun_path;
  // Instead of having a TTL, we keep this
  uint32_t last_heard_ms; 
} odr_tentry;

// After every few seconds, this thread is spawned and it
// grabs a mutex, and cleans up all the tentries, for all
// the nodes that haven't responded for 'TTL' ms. Or maybe
// we can just call this whenever we are about to add an
// entry, but that probably would be quite too expensive.
void cleanup_tentries(vector *tentries);

#endif
