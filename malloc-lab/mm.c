/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "이지윤",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "고민지",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/* Basic constants and macros(매크로) */
#define WSIZE 4             /* Word(워드) , header/footer 사이즈 (바이트) */
#define DSIZE 8             /* Double word size (바이트) */
#define CHUNKSIZE (1 << 12) /* heap 늘릴때의 기본 크기 (바이트) */

#define MAX(x, y) ((x) > (y) ? (x) : (y)) /*x랑 y중에 더 큰 수 찾기 */

/* 크기(size)와 할당 여부(allocated bit)을 하나의 워드로 합친다 */
#define PACK(size, alloc) ((size) | (alloc))

/* 주소 포인터 p가 가리키는 워드(4바이트) 값을 읽고 val에 저장한다 */
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

/* 주소 p에서 size와 할당 여부(allocated) 비트만 추출한다 */
#define GET_SIZE(p) (GET(p) & ~0x7) /* 하위 3비트를 제외한 사이즈 추출한다  64 32 16 8 | 4 2 1*/
#define GET_ALLOC(p) (GET(p) & 0x1) /* 할당 여부 비트 추출 -> 제일 마지막 비트 */

/* bp(block pointer, payload 영역의 시작 주소를 가리킴)로 부터 header, footer 주소를 계산한다 */
#define HDRP(bp) ((char *)(bp) - WSIZE)                      /* 헤더는 bp기준 4바이트 앞 */
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) /* 푸터는 블록 끝에서 8바이트 전*/

/* bp부터 다음 블록과 이전 블록을 계산 */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) /* bp - WSIZE 는 헤더 주소*/
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

// heap_listp 전역 변수로 선언
static char *heap_listp = NULL;

/* 함수 선언*/
static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;

    /*
     * 초기 힙 구성 (alignment padding + 프롤로그 블록 + 에필로그 블록):
     *
     * [패딩][프롤로그 헤더][프롤로그 푸터][에필로그 헤더]
     *   0         8               8             0
     */

    PUT(heap_listp, 0);                            // 패딩 : 8 바이트 정렬 맞추기 용
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); // 프롤로그 헤더 (크기=8, 할당됨으로 표시)
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1)); // 프롤로그 푸터 (크기=8, 할당됨으로 표시)
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));     // 에필로그 헤더 (크기=0, 할당됨으로 표시)

    heap_listp += (2 * WSIZE); // payload 영역의 시작점(bp)으로 포인터 이동

    // 실제 힙을 CHUNKSIZE(힙을 확장할 기본 단위) 만큼 확장하여 실제로 사용 가능 한 초기 free 블록 생성
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;

    return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;      // 조정된 블록 크기 (헤더/푸터 포함, 정렬 고려)
    size_t extendsize; // 힙을 확장해야 할 경우 사용할 크기
    char *bp;          // 반환할 블록의 포인터 (payload 시작점)

    if (size == 0)
        return NULL;

    // 요청 크기가 DSIZE(8바이트) 이하라면 최소 블록 크기 16바이트로 설정
    if (size <= DSIZE)
        asize = 2 * DSIZE;
    else
        // size + 헤더/푸터 정렬 고려하여 8의 배수로 올림
        asize = DSIZE * ((size + DSIZE + (DSIZE - 1)) / DSIZE);

    // 적당한 free 블록을 implicit free list에서 탐색
    if ((bp = find_fit(asize)) != NULL)
    {
        // 찾았으면 그 자리에 블록 배치하고 반환
        place(bp, asize);
        return bp;
    }

    // 못 찾았으면 힙을 확장
    extendsize = MAX(asize, CHUNKSIZE); // 요청 크기 or 기본 확장 크기 중 큰 값
    if ((bp = extend_heap(extendsize / WSIZE)) == NULL)
        return NULL;

    // 확장한 힙에서 블록 배치
    place(bp, asize);
    return bp;
}

static void *extend_heap(size_t words)
{
    char *bp;
    size_t size;

    /* 8 바이트로 정렬해야하기 떄문에 사이즈가 홀수라면 짝수로 만들어준다 */
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
    /* 힙을 size만큼 확장한다 */
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    /* free header/ footer & epilogue header를 초기화 시킨다 */
    PUT(HDRP(bp), PACK(size, 0));         /* 헤더 사이즈는 size , 할당 안됨*/
    PUT(FTRP(bp), PACK(size, 0));         /* 푸터 사이즈는 size , 할당 안됨*/
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* 새로운 에필로그 헤더 생성. 다음 블록(에필로그) 헤더 크기 : 0 , 할당 됨*/

    return coalesce(bp);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
    /* 전체 블록 크기 정보를 가져온다 */
    size_t size = GET_SIZE(HDRP(bp));

    /* 블록을 free 상태로 표시한다*/
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));

    coalesce(bp);
}

static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    /* Case 1: 앞, 뒤 모두 할당 되어있어서 병합 불가능함 */
    if (prev_alloc && next_alloc)
    {
        return bp;
    }

    /* Case 2: 앞은 할당 되있구 뒤는 free, 뒤쪽 블록과 병합한다 */
    else if (prev_alloc && !next_alloc)
    {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp))); // 크기를 합친다
        PUT(HDRP(bp), PACK(size, 0));          // 새로운 헤더 작성한다
        PUT(FTRP(bp), PACK(size, 0));          // 새로운 푸터 작성한다
    }

    /* Case 3: 앞을 free, 뒤는 할당 됨 */
    else if (!prev_alloc && next_alloc)
    {
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));            // 푸터를 새 블록 끝에 작성한다
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0)); // 헤더를 앞 블록에 작성한다
        bp = PREV_BLKP(bp);                      // bp를 병합된 블록 시작접으로 이동시킨다
    }

    /* Case 4: 앞과 뒤 모두 free, 전체 블록을 병합 */
    else
    {
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) +
                GET_SIZE(FTRP(NEXT_BLKP(bp)));   // 전체 크기를 합침
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0)); // 헤더 앞 블록 위치에 작성
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0)); // 푸터 뒤쪽 블록 끝에 작성
        bp = PREV_BLKP(bp);                      // bp는 병합된 블록 시작점으로 이동
    }

    return bp;
}

/*
 * find_fit - 암시적 free list에서 첫 번째로 맞는 free 블록을 찾아 반환
 *           (first-fit 방식)
 */
static void *find_fit(size_t asize)
{
    void *bp = heap_listp; // 프롤로그 블록 바로 다음부터 탐색 시작

    // 에필로그 전까지 블록들을 순차적으로 확인
    while (GET_SIZE(HDRP(bp)) > 0)
    {

        // 현재 블록이 free 상태이고 크기가 요청 asize 이상이면 반환
        if (!GET_ALLOC(HDRP(bp)) && (GET_SIZE(HDRP(bp)) >= asize))
        {
            return bp;
        }

        // 다음 블록으로 이동
        bp = NEXT_BLKP(bp);
    }

    // 못 찾으면 NULL 반환
    return NULL;
}

/*
 * place - 찾은 free 블록(bp)에 asize만큼 공간을 할당하고,
 *         남는 공간이 충분하면 free 블록으로 분할한다.
 */
static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp)); // 현재 free 블록의 전체 크기

    // 블록을 분할할 수 있을 만큼 충분히 크면 분할
    if ((csize - asize) >= (2 * DSIZE))
    {
        // 앞부분: 요청된 크기로 할당
        PUT(HDRP(bp), PACK(asize, 1)); // 헤더에 크기+할당 표시
        PUT(FTRP(bp), PACK(asize, 1)); // 푸터에도 동일하게

        // 뒷부분: 남은 공간을 새로운 free 블록으로 설정
        bp = NEXT_BLKP(bp);                    // 남은 공간의 시작점으로 이동
        PUT(HDRP(bp), PACK(csize - asize, 0)); // 헤더: 남은 크기, free
        PUT(FTRP(bp), PACK(csize - asize, 0)); // 푸터: 남은 크기, free
    }
    else
    {
        // 분할하지 않고 전체 블록을 그대로 할당
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;

    newptr = mm_malloc(size);
    if (newptr == NULL)
        return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
        copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}