/*
 * Copyright (c) 2025 Stamelos Vasilis
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _ARENA_H
#define _ARENA_H

#include <stdint.h> /* uintptr_t */
#ifdef NOSTDLIB
    typedef unsigned int arena_size_t;
#else
    #include <stdlib.h> /* malloc free */
    #include <stdio.h> /* va_list printf vsnprintf */
    #include <stdarg.h> /* va_start va_end */
    #include <string.h> /* memset memcpy strlen */
    typedef size_t arena_size_t;
#endif

#define ARENA_BACKEND_LIBC_MALLOC 0
#define ARENA_BACKEND_LINUX_MMAP 1
#define ARENA_BACKEND_WIN32_VIRTUALALLOC 2
/* expects this functions to be defined:
 * void* arena__internal_malloc(arena_size_t sz);
 * void arena__internal_free(void* ptr, arena_size_t sz);
 */
#define ARENA_BACKEND_CUSTOM 3
/* not implemented yet because i need to figure out how to make a heap allocator on top of __heap_base */
#define ARENA_BACKEND_WASM_HEAPBASE 4

#ifndef ARENA_BACKEND
#define ARENA_BACKEND ARENA_BACKEND_LIBC_MALLOC
#endif /* ARENA_BACKEND */

#ifndef ARENA_API
#define ARENA_API
#endif /* ARENA_API */

typedef enum Arena_Error {
    ARENA_NONE = 0,
    ARENA_OUT_OF_MEMORY = 1,
    ARENA_INVALID_SIZE = 2,
    ARENA_INVALID_ALIGNMENT = 3,
    ARENA_INVALID_FORMAT = 4
} Arena_Error;

typedef struct Arena_Page {
    char* start;
    arena_size_t mark;
    arena_size_t capacity;
    struct Arena_Page* prev_page;
} Arena_Page;

typedef struct Arena {
    Arena_Error error;
    arena_size_t min_page_capacity;
    arena_size_t mark;
    char* last_allocated_ptr;
    Arena_Page* last_page;
    Arena_Page* unused_pages;
} Arena;

ARENA_API Arena arena_create(arena_size_t page_size);
ARENA_API void arena_destroy(Arena* arena);

ARENA_API arena_size_t arena_get_usage(Arena* arena); /* wasted memory chunks is also added to this */
ARENA_API arena_size_t arena_get_checkpoint(Arena* arena);
ARENA_API void arena_rewind(Arena* arena, arena_size_t checkpoint);
ARENA_API void arena_reset(Arena* arena);
ARENA_API void arena_reset_and_zero(Arena* arena);

ARENA_API void* arena_malloc(Arena* arena, arena_size_t size);
ARENA_API void* arena_memalign(Arena* arena, arena_size_t size, arena_size_t alignment);
ARENA_API void* arena_calloc(Arena* arena, arena_size_t count, arena_size_t size);
ARENA_API void* arena_realloc(Arena* arena, void* ptr, arena_size_t old_size, arena_size_t new_size);
ARENA_API void arena_free(Arena* arena, void* ptr); /* can only deallocate the last allocated chunk */

ARENA_API char* arena_strdup(Arena* arena, const char* str);
ARENA_API char* arena_strndup(Arena* arena, const char* str, arena_size_t n);
ARENA_API void* arena_memdup(Arena* arena, const void* buffer, arena_size_t buffer_size);
ARENA_API char* arena_strcat(Arena* arena, const char* str1, const char* str2);

const char* arena_error_to_string(const Arena_Error error);

#ifndef ARENA_NOSTDLIB
    ARENA_API void arena_print_pages(Arena* arena);
    ARENA_API char* arena_sprintf(Arena* arena, const char* format, ...);
#endif /* ARENA_NOSTDLIB */

#endif /* _ARENA_H */

#ifdef ARENA_IMPLEMENTATION

#if ARENA_BACKEND == ARENA_BACKEND_LIBC_MALLOC
    #ifdef ARENA_NOSTDLIB
        #error "libc malloc cant be used when ARENA_NOSTDLIB is defined"
    #endif /* ARENA_NOSTDLIB */
    
    static void* arena__internal_malloc(arena_size_t sz) {
        return malloc(sz);
    } 
    
    static void arena__internal_free(void* ptr, arena_size_t sz) {
        (void) sz;
        free(ptr);
    }
#elif ARENA_BACKEND == ARENA_BACKEND_LINUX_MMAP
    #include <unistd.h>
    #include <sys/mman.h>
    
    static void* arena__internal_malloc(arena_size_t sz) {
        void* ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED) {
            return NULL;
        }
        return ptr;
    } 
    
    static void arena__internal_free(void* ptr, arena_size_t sz) {
        munmap(ptr, sz);
    }
#elif ARENA_BACKEND == ARENA_BACKEND_WIN32_VIRTUALALLOC
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif /* WIN32_LEAN_AND_MEAN */
    #include <windows.h>
    
    static void* arena__internal_malloc(arena_size_t sz) {
        void* ptr = VirtualAllocEx(
            GetCurrentProcess(),      /* Allocate in current process address space */
            NULL,                     /* Unknown position */
            sz,                       /* Bytes to allocate */
            MEM_COMMIT | MEM_RESERVE, /* Reserve and commit allocated page */
            PAGE_READWRITE            /* Permissions ( Read/Write )*/
        );
        if (ptr == NULL || ptr == INVALID_HANDLE_VALUE) {
            return NULL;
        }
        return ptr;
    } 
    
    static void arena__internal_free(void* ptr, arena_size_t sz) {
        (void) sz;
        VirtualFreeEx(
            GetCurrentProcess(),        /* Deallocate from current process address space */
            (LPVOID)ptr,                /* Address to deallocate */
            0,                          /* Bytes to deallocate ( Unknown, deallocate entire page ) */
            MEM_RELEASE                 /* Release the page ( And implicitly decommit it ) */
        );
    }
#elif ARENA_BACKEND == ARENA_BACKEND_CUSTOM
    void* arena__internal_malloc(arena_size_t sz);
    void arena__internal_free(void* ptr, arena_size_t sz);
#elif ARENA_BACKEND == ARENA_BACKEND_WASM_HEAPBASE
    #error "unsuported arena backend"
#else
    #error "unsuported arena backend"
#endif

#ifdef ARENA_NOSTDLIB
    static void* arena__internal_memcpy(void* dst, const void* src, arena_size_t n) {
        unsigned char* d = dst;
        const unsigned char* s = src;
        for (; n; n--) {
            *d++ = *s++;
        }
        return dst;
    }
    
    static void* arena__internal_memset(void* dst, unsigned char c, arena_size_t n) {
        void* d = dst;
        for (; n; n--) {
            *d = c;
            d++;
        }
        return dst;
    }
    
    static arena_size_t arena__internal_strlen(const char* string) {
        char* s = string;
        for (; *s; s++);
        return s - string
    }
#else /* ARENA_NOSTDLIB */    
    #define arena__internal_memcpy memcpy
    #define arena__internal_memset memset
    #define arena__internal_strlen strlen
    
    void arena__print_page(Arena_Page* page) {
        if (page == NULL) {
            return;
        }
        
        arena__print_page(page->prev_page);
        
        printf("============PAGE============\n");
        printf("capacity: %d\n", (int)page->capacity);
        printf("used: %d\n", (int)page->mark);
        printf("status: %s\n", page->capacity == page->mark ? "FULL" : "NOT FULL");
    }
#endif /* ARENA_NOSTDLIB */

static arena_size_t arena__internal_strnlen(const char* string, arena_size_t n) {
    arena_size_t result = 0;
    
    for (; *string && result < n; string++) {
        result++;
    }
    
    return result;
}

static arena_size_t arena__get_running_mark(Arena_Page* page) {
    arena_size_t running_mark = 0;
    
    while (page) {
        running_mark += page->mark;
        page = page->prev_page;
    }
    
    return running_mark;
}

static Arena_Page* arena___new_page(arena_size_t page_size) {
    Arena_Page* page = (Arena_Page*)arena__internal_malloc(sizeof(*page));
    page->start = arena__internal_malloc(page_size);
    page->mark = 0;
    page->capacity = page_size;
    page->prev_page = NULL;
    
    return page;
}

static void arena__add_page(Arena_Page* page, Arena_Page* in) {
    if (page->prev_page == NULL) {
        page->prev_page = in;
        return;
    }
    arena__add_page(page, in);
}

static void arena__free_page(Arena_Page* page) {
    if (page == NULL) {
        return;
    }
    arena__free_page(page->prev_page);
    arena__internal_free(page->start, page->capacity);
    arena__internal_free(page, sizeof(*page));
}

ARENA_API Arena arena_create(arena_size_t page_size) {
    Arena self;
    
    self.error = ARENA_NONE;
    self.min_page_capacity = page_size;
    self.mark = 0;
    self.last_allocated_ptr = NULL;
    self.last_page = arena___new_page(page_size);
    self.unused_pages = NULL;
    
    return self;
}

ARENA_API void arena_destroy(Arena* self) {
    arena__free_page(self->last_page);
    arena__free_page(self->unused_pages);
}

ARENA_API arena_size_t arena_get_usage(Arena* self) {
    self->error = ARENA_NONE;
    
    return self->mark;
}

ARENA_API arena_size_t arena_get_checkpoint(Arena* self) {
    self->error = ARENA_NONE;
    
    return self->mark;
}

ARENA_API void arena_rewind(Arena* self, arena_size_t checkpoint) {
    Arena_Page* page;
    Arena_Page* other_page;
    arena_size_t running_mark;
    
    self->error = ARENA_NONE;
    
    /* if it is more then the mark it is invalid and if it is equal to mark there is no work to do */
    if (checkpoint >= self->mark) {
        return;
    }
    
    page = self->last_page;
    
    while (page) {
        running_mark = arena__get_running_mark(page);

        /* if the checkpoint is between the running mark and the running mark at the start of the page */
        if (running_mark - page->mark <= checkpoint && checkpoint <= running_mark) {
            if (page == self->last_page) { /* the checkpoint was refering to the first page */
                self->last_page->mark -= self->mark - checkpoint;
                self->mark = checkpoint;
                self->last_allocated_ptr = NULL;
                break;
            } else { /* the checkpoint refers to a page other then the first */
                /* search for the page before the one that holds the checkpoint */
                for (other_page = self->last_page;; other_page = other_page->prev_page) {
                    if (other_page->prev_page == page) {
                        other_page->prev_page = NULL;
                        if (self->unused_pages == NULL) {
                            self->unused_pages = self->last_page;
                        } else {
                            arena__add_page(self->unused_pages, self->last_page);
                        }
                        
                        break;
                    }
                }
                self->last_page = page;
                self->last_page->mark = checkpoint - arena__get_running_mark(self->last_page->prev_page);
                self->mark = checkpoint;
                self->last_allocated_ptr = NULL;
                break;
            }
        }
        
        page = page->prev_page;
    }
}

ARENA_API void arena_reset(Arena* self) {
    self->error = ARENA_NONE;
    
    if (self->unused_pages == NULL) {
        self->unused_pages = self->last_page;
    } else {
        arena__add_page(self->unused_pages, self->last_page);
    }
    
    self->last_page = self->unused_pages;  
    self->unused_pages = self->unused_pages->prev_page;
    self->last_page->prev_page = NULL;
    
    self->mark = 0;
    self->last_page->mark = 0;
    self->last_allocated_ptr = NULL;
}

ARENA_API void arena_reset_and_zero(Arena* self) {
    Arena_Page* page;
    
    self->error = ARENA_NONE;
    
    arena_reset(self);
    
    arena__internal_memset(self->last_page->start, 0, self->last_page->capacity);
    
    for (page = self->unused_pages; page; page = page->prev_page) {
        arena__internal_memset(page->start, 0, page->capacity);
    }
}

ARENA_API void* arena_malloc(Arena* self, arena_size_t size) {
    Arena_Page* new_page = NULL;
    Arena_Page* prev_page = NULL;

    self->error = ARENA_NONE;
    
    /* (1) check if the size is valid */
    if (size == 0) {
        self->error = ARENA_INVALID_SIZE;
        return NULL;
    }
    /* (2) provide a simple chunk */
    if (self->last_page->mark + size <= self->last_page->capacity) {
        self->last_allocated_ptr = self->last_page->start + self->last_page->mark;
        self->last_page->mark += size;
        self->mark += size;
        return self->last_page->start + self->last_page->mark - size; 
    } else { /* (3) not enough space for the chunk */
        /* (4) search for an unused page with enough capacity */
        if (self->unused_pages != NULL) {
            prev_page = NULL;
            for (new_page = self->unused_pages; new_page; new_page = new_page->prev_page) {
                if (new_page->capacity >= size) {
                    if (prev_page == NULL) {
                        self->unused_pages = new_page->prev_page;
                    } else {
                        prev_page->prev_page = new_page->prev_page;
                    }
                    break;
                }
                prev_page = new_page;
            }
        }
        
        if (new_page == NULL) {
            new_page = arena___new_page(size > self->min_page_capacity ? size : self->min_page_capacity);
            if (new_page == NULL) {
                self->error = ARENA_OUT_OF_MEMORY;
                return NULL;
            }
        }
        
        self->mark = self->mark - self->last_page->mark + self->last_page->capacity;
        self->last_page->mark = self->last_page->capacity;
        
        new_page->prev_page = self->last_page;
        self->last_page = new_page;
        new_page->mark = 0;
        /* (5) it will go to (2) so no reason to duplicate code */
        return arena_malloc(self, size);
    }
}

ARENA_API void* arena_memalign(Arena* self, arena_size_t size, arena_size_t alignment) {
    char* address;
    size_t allocation_size;
    
    self->error = ARENA_NONE;
    
    /* no alignment */
    if (alignment <= 1) {
        return arena_malloc(self, size);
    }
    /* not power of 2 */
    if (alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0) {
        self->error = ARENA_INVALID_ALIGNMENT;
        return NULL;
    }
    if (size == 0) {
        self->error = ARENA_INVALID_SIZE;
        return NULL;
    }
    
    if ((uintptr_t)self->last_page->start + self->last_page->mark + size <= self->last_page->capacity) {
        if (((uintptr_t)self->last_page->start + self->last_page->mark) % alignment) {
            return arena_malloc(self, size);
        }
    }
    allocation_size = size + alignment - 1;
    address = arena_malloc(self, allocation_size);
    address = (char*)(address + (alignment - (uintptr_t)address % alignment));
    
    self->last_allocated_ptr = address;
    
    return address;
}

ARENA_API void* arena_calloc(Arena* arena, arena_size_t count, arena_size_t size) {
    void* ptr = arena_malloc(arena, count*size);
    
    if (ptr == NULL) {
        return NULL;
    }
    
    return arena__internal_memset(ptr, 0, count*size);
}

ARENA_API void* arena_realloc(Arena* self, void* ptr, arena_size_t old_size, arena_size_t new_size) {
    arena_size_t last_allocation_size;
    void* new_ptr;
    
    self->error = ARENA_NONE;
    
    /* if the ptr is NULL then allocate new_size bytes */
    if (ptr == NULL) {
        return arena_malloc(self, new_size);
    } else if (ptr != NULL && new_size == 0) {
        /* free the pointer if the new_size is 0 */
        arena_free(self, ptr);
        return NULL;
    } else {
        /* if it was not the last allocation then it cant be extended */
        if (self->last_allocated_ptr != ptr) {
            new_ptr = arena_malloc(self, new_size);
            if (new_ptr == NULL) {
                return NULL;
            }
            return arena__internal_memcpy(new_ptr, ptr, old_size);
        } else {
            /* ptr can be possibly extended */
            /* last_allocation_size = (start + mark) - ptr; */
            last_allocation_size = (arena_size_t)self->last_page->start + self->last_page->mark - (arena_size_t)ptr;

            /* the new size is less then the old size */
            if (last_allocation_size >= new_size) {
                self->last_page->mark -= last_allocation_size - new_size;
                self->mark -= last_allocation_size - new_size;
                return ptr;
            } else {
                /* check if the current page can hold extra data */
                if (new_size - last_allocation_size + self->last_page->mark <= self->last_page->capacity) {
                    self->last_page->mark += new_size - last_allocation_size;
                    self->mark += new_size - last_allocation_size;
                    return ptr;
                } else {
                    /* womp womp */
                    new_ptr = arena_malloc(self, new_size);
                    if (new_ptr == NULL) {
                        return NULL;
                    }
                    return arena__internal_memcpy(new_ptr, ptr, old_size);
                }
            }
        }
    }
}

ARENA_API void arena_free(Arena* self, void* ptr) {
    self->error = ARENA_NONE;
    
    /* self->last_allocated_ptr might be null */
    if (ptr == NULL) {
        return;
    }
    
    /* try to reclaim the memory if it was the last allocation made */
    if (ptr == self->last_allocated_ptr) {
        /* last_allocation_size = (start + mark) - ptr; */
        self->mark -= (arena_size_t)self->last_page->start + self->last_page->mark - (arena_size_t)ptr;
        self->last_page->mark -= (arena_size_t)self->last_page->start + self->last_page->mark - (arena_size_t)ptr;
        /* some safety to guard against double free */
        self->last_allocated_ptr = NULL;
    }
}

ARENA_API char* arena_strdup(Arena* self, const char* str) {
    arena_size_t str_size;
    char* ptr;
    
    self->error = ARENA_NONE;
    
    str_size = arena__internal_strlen(str);
    ptr = arena_malloc(self, str_size + 1);
    
    if (ptr == NULL) {
        return NULL;
    }
    
    return arena__internal_memcpy(ptr, str, str_size + 1);
}

ARENA_API char* arena_strndup(Arena* arena, const char* str, arena_size_t n) {
    arena_size_t len = arena__internal_strnlen(str, n);
    char* copy = (char*)arena_malloc(arena, len + 1);
    if (copy) {
        arena__internal_memcpy(copy, str, len);
        copy[len] = '\0';
    }
    return copy;
}

ARENA_API void* arena_memdup(Arena* arena, const void* buffer, arena_size_t buffer_size) {
    void* ptr = arena_malloc(arena, buffer_size);
    if (ptr == NULL) {
        return NULL;
    }
    return arena__internal_memcpy(ptr, buffer, buffer_size);
}

ARENA_API char* arena_strcat(Arena* arena, const char* str1, const char* str2) {
    arena_size_t len1 = arena__internal_strlen(str1);
    arena_size_t len2 = arena__internal_strlen(str2);
    char* result = (char*)arena_malloc(arena, len1 + len2 + 1);
    if (result) {
        arena__internal_memcpy(result, str1, len1);
        arena__internal_memcpy(result + len1, str2, len2);
        result[len1 + len2] = '\0';
    }
    return result;
}

ARENA_API const char* arena_error_to_string(const Arena_Error error) {
    switch (error) {
    case ARENA_NONE: return "NONE";
    case ARENA_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
    case ARENA_INVALID_SIZE: return "INVALID_SIZE";
    case ARENA_INVALID_ALIGNMENT: return "INVALID_ALIGNMENT";
    case ARENA_INVALID_FORMAT: return "INVALID_FORMAT";
    default: return "UNKNOWN_ERROR";
    }
}

#ifndef ARENA_NOSTDLIB    
    ARENA_API void arena_print_pages(Arena* self) {
        self->error = ARENA_NONE;
        
        arena__print_page(self->last_page);
        printf("============================\n");
    }
    
    ARENA_API char* arena_sprintf(Arena* self, const char* format, ...) {
        va_list args;
        char* result;
        int n;
        
        self->error = ARENA_NONE;
        
        va_start(args, format);
        n = vsnprintf(NULL, 0, format, args);
        va_end(args);
    
        if (n < 0) {
            self->error = ARENA_INVALID_FORMAT;
            return NULL;
        }
        
        result = (char*)arena_malloc(self, n + 1);
        if (result == NULL) {
            return NULL;
        }
        va_start(args, format);
        vsnprintf(result, n + 1, format, args);
        va_end(args);
    
        return result;
    }
#endif /* ARENA_NOSTDLIB */

#endif /* ARENA_IMPLEMENTATION */
