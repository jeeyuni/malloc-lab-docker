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
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
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

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *) -1)
        return -1;

    /*
     * 초기 힙 구성 (alignment padding + 프롤로그 블록 + 에필로그 블록):
     *
     * [패딩][프롤로그 헤더][프롤로그 푸터][에필로그 헤더]
     *   0         8               8             0
     */

    PUT(heap_listp, 0); // 패딩 : 8 바이트 정렬 맞추기 용 
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1));     // 프롤로그 헤더 (크기=8, 할당됨으로 표시)
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1));     // 프롤로그 푸터 (크기=8, 할당됨으로 표시)
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));         // 에필로그 헤더 (크기=0, 할당됨으로 표시)

    heap_listp += (2 * WSIZE);  // payload 영역의 시작점(bp)으로 포인터 이동

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
    int newsize = ALIGN(size + SIZE_T_SIZE);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1)
        return NULL;
    else
    {
        *(size_t *)p = size;
        return (void *)((char *)p + SIZE_T_SIZE);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
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