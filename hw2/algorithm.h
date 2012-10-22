#ifndef ALGORITHM_H
#define ALGORITHM_H

typedef void* (*proc_2_arg)(void*, void*);

/* Reduce elements in 'v' using 'val' as the initial value, and place
 * the result in 'val'.
 */
void reduce(vector *v, proc_2_arg reducer, void *val) {
    int i;
    for (i = 0; i < vector_size(v); ++i) {
        memcpy(val, reducer(val, vector_at(i)), vector_object_size(v));
    }
}

#endif // ALGORITHM_H
