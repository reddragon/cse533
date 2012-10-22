#include "algorithm.h"
#include <string.h>

/* Reduce elements in 'v' using 'val' as the initial value, and place
 * the result in 'val'.
 */
void algorithm_reduce(vector *v, proc_2_arg reducer, void *val) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        memcpy(val, reducer(val, vector_at(v, i)), vector_object_size(v));
    }
}

int algorithm_find(vector *v, void *data, cmpeq_t cmpeq) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        if (cmpeq(data, vector_at(v, i))) {
            return i;
        }
    }
    return -1;
}
