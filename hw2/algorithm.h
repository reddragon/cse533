#ifndef ALGORITHM_H
#define ALGORITHM_H

#include "vector.h"

typedef const void* (*proc_2_arg)(const void*, const void*);
typedef int (*cmpeq_t)(const void*, const void*);

/* Reduce elements in 'v' using 'val' as the initial value, and place
 * the result in 'val'.
 */
void algorithm_reduce(vector *v, proc_2_arg reducer, void *val);
int algorithm_find(vector *v, void *data, cmpeq_t cmpeq);

#endif // ALGORITHM_H
