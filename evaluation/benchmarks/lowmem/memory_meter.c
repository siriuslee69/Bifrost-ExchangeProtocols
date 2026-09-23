/* ------------------------------------------------------------------------
 * Memory Meter <- counts every heap byte and how deep the stack went
 * ------------------------------------------------------------------------
 *
 * Linked only into the low-memory probe, with
 *   -d:useMalloc  -Wl,--wrap=malloc,--wrap=free,--wrap=calloc,--wrap=realloc
 * so every allocation passes through here first:
 *
 *   program --malloc--> __wrap_malloc --> __real_malloc (the C library)
 *                           |
 *                           +--> live += size ; peak = max(peak, live)
 *
 * Stack: before the work, a block below the current frame is painted with
 * one byte value. After the work, the first byte that is no longer that
 * value tells how far down the stack reached.
 *
 *   high address  [ caller frame ]
 *                 [ painted .... touched by work .... ]  <- deepest write
 *                 [ painted .... untouched ..........]
 *   low address
 */
#include <stddef.h>
#include <string.h>
#include <malloc.h>

void *__real_malloc(size_t n);
void  __real_free(void *p);
void *__real_calloc(size_t n, size_t m);
void *__real_realloc(void *p, size_t n);

static size_t meterLive = 0;
static size_t meterPeak = 0;

static void meterAdd(void *p) {
  if (p == NULL) return;
  meterLive += malloc_usable_size(p);
  if (meterLive > meterPeak) meterPeak = meterLive;
}

static void meterSub(void *p) {
  if (p == NULL) return;
  meterLive -= malloc_usable_size(p);
}

void *__wrap_malloc(size_t n) {
  void *p = __real_malloc(n);
  meterAdd(p);
  return p;
}

void __wrap_free(void *p) {
  meterSub(p);
  __real_free(p);
}

void *__wrap_calloc(size_t n, size_t m) {
  void *p = __real_calloc(n, m);
  meterAdd(p);
  return p;
}

void *__wrap_realloc(void *p, size_t n) {
  void *q = NULL;
  meterSub(p);
  q = __real_realloc(p, n);
  meterAdd(q != NULL ? q : (n == 0 ? NULL : p));
  return q;
}

size_t meterHeapPeak(void) { return meterPeak; }
size_t meterHeapLive(void) { return meterLive; }
void   meterHeapReset(void) { meterPeak = meterLive; }

#define METER_STACK_SPAN (512 * 1024)
#define METER_PAINT 0xA5

/* Painted from a frame that is gone again when the work runs, so the work
 * reuses exactly these bytes. noinline keeps the frames where we expect. */
__attribute__((noinline)) void meterStackPaint(void) {
  volatile unsigned char block[METER_STACK_SPAN];
  size_t i = 0;
  while (i < sizeof(block)) { block[i] = METER_PAINT; i++; }
}

__attribute__((noinline)) size_t meterStackUsed(void) {
  volatile unsigned char block[METER_STACK_SPAN];
  size_t i = 0;
  while (i < sizeof(block) && block[i] == METER_PAINT) i++;
  return sizeof(block) - i;
}
