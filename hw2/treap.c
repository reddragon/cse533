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

void treap_rotate_up(treap *t, treap_node *n);
treap_node* treap_find(treap *t, int key);
void treap_init(treap *t);
void treap_insert(treap *t, int key, const void *data);
treap_node* treap_lower_bound(treap *t, int key);
void treap_delete_leaf_node(treap *t, treap_node *n);


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
    treap_node *r = n->parent;
    treap_node *nright = n->right;
    n->right = r;
    r->left = nright;
    if (r->parent) {
        if (r->parent->left == r) {
            r->parent->left = n;
        } else {
            r->parent->right = n;
        }
    }
    n->parent = r->parent;
    r->parent = n;
    if (nright) {
        nright->parent = r;
    }
}

void treap_rotate_left(treap_node *n) {
    treap_node *r = n->parent;
    treap_node *nleft = n->left;
    n->left = r;
    r->right = nleft;
    if (r->parent) {
        if (r->parent->left == r) {
            r->parent->left = n;
        } else {
            r->parent->right = n;
        }
    }
    n->parent = r->parent;
    r->parent = n;
    if (nleft) {
        nleft->parent = r;
    }
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

void treap_delete_leaf_node(treap *t, treap_node *n) {
    assert(!n->left && !n->right);
    // Is 'n' the root?
    if (!n->parent) {
        free(n);
        t->root = NULL;
    } else {
        if (n->parent->left == n) {
            n->parent->left = NULL;
        } else {
            n->parent->right = NULL;
        }
        free(n);
    }
}

treap_node* treap_successor(treap_node *n) {
    if (n->right) {
        n = n->right;
        while (n->left) {
            n = n->left;
        }
        return n;
    } else {
        while (n->parent && n->parent->right == n) {
            n = n->parent;
        }
        if (!n->parent && n->parent->right == n) {
            return NULL;
        }
        return n;
    }
}

treap_node* treap_predecessor(treap_node *n) {
    if (n->left) {
        n = n->left;
        while (n->right) {
            n = n->right;
        }
        return n;
    } else {
        while (n->parent && n->parent->left == n) {
            n = n->parent;
        }
        if (!n->parent && n->parent->left == n) {
            return NULL;
        }
        return n;
    }
}

void treap_delete(treap *t, int key) {
    treap_node *n = treap_find(t, key);
    if (!n) { return; }

    // Move element to the root.
    n->heapkey = -1;
    treap_node *r = n->parent;
    while (r && n->heapkey < r->heapkey) {
        treap_rotate_up(t, n);
        r = n->parent;
    }

    // n is now the root of the tree. Find either the predecessor or
    // successor of n and put the 'key' and 'data' members here.
    treap_node *predsucc = treap_successor(n);
    if (!predsucc) {
        predsucc = treap_predecessor(n);
    }
    if (!predsucc) {
        treap_delete_leaf_node(t, n);
    } else {
        n->key = predsucc->key;
        n->data = predsucc->data;
        treap_delete_leaf_node(t, predsucc);
    }
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

    treap_insert(&t, 100, NULL);
    treap_insert(&t, 50, NULL);

    treap_print(t.root);
    printf("\n");

    treap_insert(&t, 200, NULL);

    treap_print(t.root);
    printf("\n");

    treap_insert(&t, 400, NULL);

    treap_print(t.root);
    printf("\n");

    treap_insert(&t, 250, NULL);

    treap_print(t.root);
    printf("\n");

    treap_insert(&t, 25, NULL);
    treap_insert(&t, 55, NULL);
    treap_insert(&t, 10, NULL);

    treap_print(t.root);
    printf("\n");

    return 0;
}
#endif
