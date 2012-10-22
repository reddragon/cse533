#ifndef VECTOR_H
#define VECTOR_H

typedef struct vector {
    char *repr;
    int obj_size;
    int mem_len;
    int size;
} vector;

void overlapping_memcpy_ltor(char *dest, const char *src, int len);
void vector_init(vector *v, int obj_size);
void *vector_get(vector *v, int i);
void *vector_at(vector *v, int i);
void vector_reserve(vector *v, int n);
void vector_resize(vector *v, int n, void *obj);
void vector_push_back(vector *v, void *obj);
void vector_pop_back(vector *v);
int vector_size(vector *v);
int vector_empty(vector *v);
int vector_object_size(vector *v);

#endif // VECTOR_H
