#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "treap.h"

/*
typedef struct treap_node {
    int key, heapkey;
    const void *data;
    struct treap_node *left, *right, *parent;
} treap_node;

typedef struct treap {
    treap_node *root;
    int size;
} treap;
*/

void treap_init(treap *t) {
    t->root = NULL;
    t->size = 0;
}

void treap_insert(treap *t, int key, const void *data) {
    int heapkey = rand() % 1000;
    fprintf(stderr, "treap_insert(%d, %d)\n", key, heapkey);
    treap_node *n = calloc(1, sizeof(treap_node));
    n->key = key;
    n->heapkey = heapkey;
    n->data = data;

    if (!t->root) {
        ++t->size;
        t->root = n;
        return;
    }

    treap_node *r = t->root, *prev = NULL;
    while (r) {
        prev = r;
        if (n->key == r->key) {
            // Just set the data member.
            r->data = data;
            free(n);
            return;
        }
        if (n->key < r->key) {
            r = r->left;
        } else {
            r = r->right;
        }
    }

    ++t->size;
    r = prev;
    n->parent = r;
    fprintf(stderr, "Adding [%d:%d] as the %s child of [%d:%d]\n", n->key, n->heapkey,
            (n->key < r->key ? "left" : "right"), r->key, r->heapkey);
    if (n->key < r->key) {
        r->left = n;
    } else {
        r->right = n;
    }

    // Rotate to maintain heap property.
    while (n->parent && n->heapkey < n->parent->heapkey) {
        treap_rotate_up(t, n);
    }
}

void treap_rotate_right(treap_node *n) {
    treap_node *par = n->parent;
    assert(par && par->left == n);
    treap_node *parpar = par->parent;

    par->left = n->right;
    if (n->right) {
        n->right->parent = par;
    }

    n->right = par;
    par->parent = n;

    if (parpar) {
        if (parpar->left == par) {
            parpar->left = n;
        } else {
            parpar->right = n;
        }
    }
    n->parent = parpar;
}

void treap_rotate_left(treap_node *n) {
    treap_node *par = n->parent;
    assert(par && par->right == n);
    treap_node *parpar = par->parent;

    par->right = n->left;
    if (n->left) {
        n->left->parent = par;
    }

    n->left = par;
    par->parent = n;

    if (parpar) {
        if (parpar->left == par) {
            parpar->left = n;
        } else {
            parpar->right = n;
        }
    }
    n->parent = parpar;
}

void treap_rotate_up(treap *t, treap_node *n) {
    treap_node *r = n->parent;
    if (n->parent->left == n) {
        treap_rotate_right(n);
    } else {
        treap_rotate_left(n);
    }
    if (t->root == r) {
        t->root = n;
        n->parent = NULL;
    }
}

const void* treap_get_value(treap *t, int key) {
    treap_node *n = treap_find(t, key);
    if (n) {
        return n->data;
    }
    return NULL;
}

treap_node* treap_find(treap *t, int key) {
    treap_node* n = treap_lower_bound(t, key);
    if (n && n->key == key) {
        return n;
    }
    return NULL;
}

treap_node* treap_lower_bound(treap *t, int key) {
    // Find the smallest value >= key.
    treap_node *r = t->root, *lb = NULL;
    while (r) {
        if (key <= r->key) {
            lb = r;
            r = r->left;
        } else {
            r = r->right;
        }
    }
    return lb;
}

void treap_delete_leaf_or_single_child_node(treap *t, treap_node *n) {
    fprintf(stderr, "key: %d; n->left: %p, n->right: %p\n", n->key, n->left, n->right);
    assert(!(n->left && n->right));

    if (n->left || n->right) {
        treap_node *child = n->left ? n->left : n->right;
        if (n->parent) {
            if (n->parent->left == n) {
                n->parent->left = child;
            } else {
                n->parent->right = child;
            }
            child->parent = n->parent;
        } else {
            // n is the root.
            t->root = child;
            child->parent = NULL;
        }
    } else {
        // No children.
        // Is 'n' the root?
        if (!n->parent) {
            t->root = NULL;
        } else {
            if (n->parent->left == n) {
                n->parent->left = NULL;
            } else {
                n->parent->right = NULL;
            }
        }
    }
    free(n);
}

treap_node* treap_successor(treap_node *n) {
    fprintf(stderr, "treap_successor(%d) == ", n->key);
    if (n->right) {
        n = n->right;
        while (n->left) {
            n = n->left;
        }
        fprintf(stderr, "%d\n", n->key);
        return n;
    } else {
        treap_node *par = n->parent;
        while (par && par->right == n) {
            n = par;
            par = par->parent;
        }
        fprintf(stderr, "%d\n", par ? par->key : -1);
        return par;
    }
}

treap_node* treap_predecessor(treap_node *n) {
    fprintf(stderr, "treap_predecessor(%d) == ", n->key);
    if (n->left) {
        n = n->left;
        while (n->right) {
            n = n->right;
        }
        fprintf(stderr, "{1} %d\n", n->key);
        return n;
    } else {
        treap_node *par = n->parent;
        while (par && par->left == n) {
            fprintf(stderr, "{3} %d; ", par->key);
            n = par;
            par = par->parent;
        }
        fprintf(stderr, "{2} %d\n", par ? par->key : -1);
        return par;
    }
}

void treap_delete(treap *t, int key) {
    treap_node *n = treap_find(t, key);
    if (!n) { return; }
    treap_delete_node(t, n);
}

int treap_size(treap *t) {
    return t->size;
}

int treap_empty(treap *t) {
    return t->size == 0;
}

treap_node* treap_largest(treap *t) {
    treap_node *n = &t->root;
    while (n && n->right) {
        n = n->right;
    }
    return n;
}

treap_node* treap_smallest(treap *t) {
    treap_node *n = &t->root;
    while (n && n->left) {
        n = n->left;
    }
    return n;
}

void treap_delete_node(treap *t, treap_node *n) {
    // If n is a leaf node or a node with a single child, delete it
    // directly.
    if (!(n->left && n->right)) {
        treap_delete_leaf_or_single_child_node(t, n);
    } else {
        // n has both children. Either the predecessor or successor
        // node is one with just a single child.
        treap_node *succ = treap_successor(n);
        if (succ) {
            assert(!(succ->left && succ->right));
            n->key  = succ->key;
            n->data = succ->data;
            treap_delete_leaf_or_single_child_node(t, succ);
        } else {
            treap_node *pred = treap_predecessor(n);
            assert(pred && !(pred->left && pred->right));
            n->key  = pred->key;
            n->data = pred->data;
            treap_delete_leaf_or_single_child_node(t, pred);
        }
    }
    --t->size;
}

void treap_print(treap_node *n) {
    if (!n) return;
    treap_print(n->left);
    printf("[%d:%d:%p] ", n->key, n->heapkey, n->data);
    treap_print(n->right);
}

#ifdef TEST
int main(int argc, char *argv[]) {
    treap t;
    treap_init(&t);

    int i;
    int n[ ] = { 100, 50, 200, 400, 250, 25, 55, 10 };

    printf("-- Testing Treap Insertion --\n");
    printf("-----------------------------\n");

    for (i = 0; i < sizeof(n)/sizeof(int); ++i) {
        treap_insert(&t, n[i], NULL);
        treap_print(t.root);
        printf("\n");
    }

    fflush(stdout);
    printf("\n");
    printf("-- Testing Treap Lower Bound --\n");
    printf("-------------------------------\n");

    treap_node *lb;
    int q[ ] = { 50, 16, 82, 81, 251, 249, 501, 500, 200, 25, 56, 55, 33, 0, 1000 };
    for (i = 0; i < sizeof(q)/sizeof(int); ++i) {
        lb = treap_lower_bound(&t, q[i]);
        printf("%d is the lower bound on %d\n", (lb ? lb->key : -1), q[i]);
    }

    fflush(stdout);
    printf("\n");
    printf("-- Testing Treap Deletion --\n");
    printf("----------------------------\n");

    for (i = 0; i < sizeof(n)/sizeof(int); ++i) {
        printf("Before deleting '%d'\n", n[i]);
        treap_print(t.root);
        treap_delete(&t, n[i]);

        printf("\nAfter deleting '%d'\n", n[i]);
        treap_print(t.root);
        printf("\n");
    }

    return 0;
}
#endif
