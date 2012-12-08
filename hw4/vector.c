#include "vector.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "myassert.h"

void overlapping_memcpy_ltor(char *dest, const char *src, int len) {
    int i;
    assert_ge(len, 0);
    // fprintf(stderr, "overlapping_memcpy_ltor(%d)\n", len);
    for (i = 0; i < len; ++i) {
        dest[i] = src[i];
    }
}

void vector_init(vector *v, int obj_size) {
    assert_gt(obj_size, 0);
    assert_lt(obj_size, 1024);
    v->repr = NULL;
    v->obj_size = obj_size;
    v->mem_len = 0;
    v->size = 0;
}

void vector_destroy(vector *v) {
    ASSERT(v);
    free(v->repr);
    v->repr = NULL;
}

void *vector_get(vector *v, int i) {
    return (void*)(v->repr + i*v->obj_size);
}

void *vector_at(vector *v, int i) {
    assert_ge(i, 0);
    assert_lt(i, v->size);
    return vector_get(v, i);
}

void vector_reserve(vector *v, int n) {
    char *repr;
    ASSERT(v);
    assert_ge(n, 0);
    if (n <= v->mem_len) return;

    repr = malloc((n) * v->obj_size);
    ASSERT(repr);
    if (v->repr) {
        memcpy(repr, v->repr, v->obj_size * v->size);
        free(v->repr);
    }
    v->repr = repr;
    v->mem_len = n;
}

void vector_resize(vector *v, int n, void *obj) {
    ASSERT(v);
    assert_ge(n, 0);
    if (n == v->size) return;
    if (n < v->size) {
        v->size = n;
        return;
    }
    // n > v->size
    vector_reserve(v, n);
    memcpy(vector_get(v, v->size), obj, v->obj_size);
    overlapping_memcpy_ltor(vector_get(v, v->size+1), vector_get(v, v->size), v->obj_size * (n - v->size - 1));
    v->size = n;
}

void vector_push_back(vector *v, void *obj) {
    ASSERT(v);
    assert_ge(v->mem_len, v->size);
    if (v->mem_len == v->size) {
        vector_reserve(v, (v->size ? v->size * 2 : 1));
    }
    vector_resize(v, v->size + 1, obj);
}

void vector_pop_back(vector *v) {
    ASSERT(v);
    assert_gt(v->size, 0);
    vector_resize(v, v->size - 1, NULL);
}

int vector_size(vector *v) {
    ASSERT(v);
    return v->size;
}

int vector_empty(vector *v) {
    ASSERT(v);
    return vector_size(v) == 0;
}

int vector_object_size(vector *v) {
    ASSERT(v);
    return v->obj_size;
}

void vector_erase(vector *v, int i) {
    ASSERT(v);
    assert_ge(i, 0);
    assert_lt(i, v->size);
    memmove(vector_get(v, i), vector_get(v, i+1), (v->size - i - 1) * v->obj_size);
    vector_pop_back(v);
}

void vector_swap(vector *lhs, vector *rhs) {
    vector tmp;
    ASSERT(lhs);
    ASSERT(rhs);
    ASSERT(vector_object_size(lhs) == vector_object_size(rhs));
    tmp = *lhs;
    *lhs = *rhs;
    *rhs = tmp;
}
