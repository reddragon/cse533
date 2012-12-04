#ifndef MYASSERT_H
#define MYASSERT_H

#include <assert.h>

#define ASSERT(X) if (!(X)) { char body[4096]; \
  sprintf(body, "Assertion '%s' FAILED in file %s, on line %d.\n", #X, __FILE__, __LINE__); \
}

#define assert_lt(L,R) if((L)>=(R)) { fprintf(stderr, "%d < %d FAILED\n", (L), (R)); ASSERT((L)<(R)); }
#define assert_le(L,R) if((L)>(R)) { fprintf(stderr, "%d <= %d FAILED\n", (L), (R)); ASSERT((L)<=(R)); }
#define assert_gt(L,R) if((L)<=(R)) { fprintf(stderr, "%d > %d FAILED\n", (L), (R)); ASSERT((L)>(R)); }
#define assert_ge(L,R) if((L)<(R)) { fprintf(stderr, "%d >= %d FAILED\n", (L), (R)); ASSERT((L)>=(R)); }
#define assert_eq(L,R) if((L)!=(R)) { fprintf(stderr, "%d == %d FAILED\n", (L), (R)); ASSERT((L)==(R)); }

#endif // MYASSERT_H
