#ifndef TREAP_H
#define TREAP_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct treap_node {
    int key, heapkey;
    const void *data;
    struct treap_node *left, *right, *parent;
} treap_node;

typedef struct treap {
    treap_node *root;
    int size;
} treap;

void        treap_rotate_up(treap *t, treap_node *n);
void        treap_rotate_right(treap_node *n);
treap_node* treap_find(treap *t, int key);
void        treap_init(treap *t);
void        treap_insert(treap *t, int key, const void *data);
treap_node* treap_lower_bound(treap *t, int key);
void        treap_delete_leaf_node(treap *t, treap_node *n);
void        treap_delete_node(treap *t, treap_node *n);
void        treap_rotate_left(treap_node *n);
const void* treap_get_value(treap *t, int key);
void        treap_delete_leaf_or_single_child_node(treap *t, treap_node *n);
treap_node* treap_successor(treap_node *n);
treap_node* treap_predecessor(treap_node *n);
void        treap_delete(treap *t, int key);
int         treap_size(treap *t);
void        treap_print(treap_node *n);
int         treap_empty(treap *t);
treap_node* treap_largest(treap *t);

#endif // TREAP_H
