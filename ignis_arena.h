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

#ifndef IGNIS__ARENA_H
#define IGNIS__ARENA_H

/*
 * a headers only implementation of an Arena allocator.
 * define IG_ARENA_IMPLEMENTATION for implementation.
 *
 * [macro name] [description] [where it should be defined]
 * IG_ARENA_SIZE_T a custom size type [definition|implementation]
 * IG_ARENA_NO_VARGS removes all variadic macros and functions [definition|implementation]
 * IG_ARENA_C89 removes variadic macros (you will have to manually pass NULL to IgArena_strcat and IgArena_join_strings) and does not implement IgArena_sprintf if IG_ARENA_CUSTOM_VSNPRINTF is not defined [definition|implementation]
 * IG_ARENA_UINTPTR_T a custom uintptr_t type [implementation]
 * IG_ARENA_BACKEND which backing allocator to use [implementation]
 * IG_ARENA_CUSTOM_VSNPRINTF a custom vsnprintf function int(*)(char* buf, size_t maxlen, const char* fmt, va_list args) [implementation]
 * IG_ARENA_NOSTDLIB, does not include string.h (`memset` `memcpy` `strlen`) and stdio.h (`vsnprintf` if IG_ARENA_CUSTOM_VSNPRINTF is not defined) [implementation]
 *
 * for the arena to be 100% stdlib free you need to define: IG_ARENA_SIZE_T, IG_ARENA_NO_VARGS, IG_ARENA_UINTPTR_T, IG_ARENA_CUSTOM_VSNPRINTF, IG_ARENA_NOSTDLIB and IG_ARENA_BACKEND with one of the custom backends
 */

#ifdef IG_ARENA_SIZE_T
    typedef IG_ARENA_SIZE_T arena_size_t;
#else /* IG_ARENA_SIZE_T */
    #include <stddef.h> /* size_t */
    typedef size_t arena_size_t;
#endif /* IG_ARENA_SIZE_T */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IG_ARENA_BACKEND_LIBC_MALLOC 0
#define IG_ARENA_BACKEND_LINUX_MMAP 1
#define IG_ARENA_BACKEND_WIN32_VIRTUALALLOC 2
#define IG_ARENA_BACKEND_WASM_HEAPBASE 3
/* expects this functions to be defined:
 * void* IgArena__internal_malloc(arena_size_t sz);
 * void IgArena__internal_free(void* ptr, arena_size_t sz);
 */
#define IG_ARENA_BACKEND_CUSTOM 4

#ifndef IG_ARENA_BACKEND
#define IG_ARENA_BACKEND IG_ARENA_BACKEND_LIBC_MALLOC
#endif /* IG_ARENA_BACKEND */

#ifndef IG_ARENA_API
#define IG_ARENA_API
#endif /* IG_ARENA_API */

typedef enum IgArena_Error {
    IG_ARENA_NONE              = 0,
    IG_ARENA_OUT_OF_MEMORY     = 1,
    IG_ARENA_INVALID_SIZE      = 2,
    IG_ARENA_INVALID_ALIGNMENT = 3,
    IG_ARENA_INVALID_FORMAT    = 4
} IgArena_Error;

typedef struct IgArena_Page {
    struct IgArena_Page* prev_page;
    char*                start;
    arena_size_t         capacity;
    arena_size_t         mark;
} IgArena_Page;

typedef struct IgArena {
    IgArena_Page* last_page;
    IgArena_Page* unused_pages;
    char*         last_allocated_ptr;
    arena_size_t  last_allocation_size;
    arena_size_t  min_page_capacity;
    arena_size_t  mark;
    char          _padding[4];
    IgArena_Error error;
} IgArena;

#ifdef __has_attribute
    #if __has_attribute(alloc_size)
        #define IG_ARENA_ATTR_ALLOC_SIZE1(x) __attribute__((alloc_size(x)))
        #define IG_ARENA_ATTR_ALLOC_SIZE2(x, y) __attribute__((alloc_size(x,y)))
    #endif /* __has_attribute(alloc_size) */
#endif /* __has_attribute */
#ifndef IG_ARENA_ATTR_ALLOC_SIZE1
    #define IG_ARENA_ATTR_ALLOC_SIZE1(x)
    #define IG_ARENA_ATTR_ALLOC_SIZE2(x, y)
#endif /* IG_ARENA_ATTR_ALLOC_SIZE1 */

IG_ARENA_API IgArena IgArena_create(arena_size_t page_size);
IG_ARENA_API void IgArena_destroy(IgArena* arena);

IG_ARENA_API arena_size_t IgArena_get_checkpoint(IgArena* arena);
IG_ARENA_API void IgArena_rewind(IgArena* arena, arena_size_t checkpoint);
IG_ARENA_API void IgArena_reset(IgArena* arena);
IG_ARENA_API void IgArena_reset_and_zero(IgArena* arena);

IG_ARENA_API void* IgArena_alloc(IgArena* arena, arena_size_t size) IG_ARENA_ATTR_ALLOC_SIZE1(2);
IG_ARENA_API void* IgArena_memalign(IgArena* arena, arena_size_t size, arena_size_t alignment) IG_ARENA_ATTR_ALLOC_SIZE1(2);
IG_ARENA_API void* IgArena_calloc(IgArena* arena, arena_size_t count, arena_size_t size) IG_ARENA_ATTR_ALLOC_SIZE2(2, 3);
IG_ARENA_API void* IgArena_realloc(IgArena* arena, void* ptr, arena_size_t old_size, arena_size_t new_size) IG_ARENA_ATTR_ALLOC_SIZE1(4);
IG_ARENA_API void IgArena_free(IgArena* arena, void* ptr); /* can only reclaim the last allocated chunk */

IG_ARENA_API char* IgArena_strdup(IgArena* arena, const char* str);
IG_ARENA_API char* IgArena_strndup(IgArena* arena, const char* str, arena_size_t n);
IG_ARENA_API void* IgArena_memdup(IgArena* arena, const void* buffer, arena_size_t buffer_size);
#ifdef IG_ARENA_NO_VARGS
    IG_ARENA_API char* IgArena_strcat(IgArena* arena, const char* str1, const char* str2);
    IG_ARENA_API char* IgArena_join_strings(IgArena* arena, const char* sep, const char* str1, const char* str2);
#else /* IG_ARENA_NO_VARGS */
    #ifdef IG_ARENA_C89
        IG_ARENA_API char* IgArena_strcat(IgArena* arena, const char* str1, ...);
        IG_ARENA_API char* IgArena_join_strings(IgArena* arena, const char* sep, const char* str1, ...);
    #else /* IG_ARENA_C89 */
        #define IgArena_strcat(arena, str1, ...) IgArena__strcat(arena, str1, __VA_ARGS__, NULL)
        #define IgArena_join_strings(arena, sep, str1, ...) IgArena__join_strings(arena, sep, str1, __VA_ARGS__, NULL)
        IG_ARENA_API char* IgArena__strcat(IgArena* arena, const char* str1, ...);
        IG_ARENA_API char* IgArena__join_strings(IgArena* arena, const char* sep, const char* str1, ...);
    #endif /* IG_ARENA_C89 */
#endif /* IG_ARENA_NO_VARGS */

IG_ARENA_API const char* IgArena_error_to_string(IgArena_Error error);

#ifndef IG_ARENA_NO_VARGS
    /* you can define IG_ARENA_CUSTOM_VSNPRINTF with your own implementation for vsnprintf ex. stb's implementation
    * this works even when IG_ARENA_NOSTDLIB is defined */
    #ifdef __has_attribute
        #if __has_attribute(format)
            #define IG_ARENA_ATTR_FORMAT(fmt, va) __attribute__((format(printf,fmt,va)))
        #endif /* __has_attribute(format) */
    #endif /* __has_attribute */
    #ifndef IG_ARENA_ATTR_FORMAT
        #define IG_ARENA_ATTR_FORMAT(fmt, va)
    #endif /* IG_ARENA_ATTR_FORMAT */
    IG_ARENA_API char* IgArena_sprintf(IgArena* arena, const char* format, ...) IG_ARENA_ATTR_FORMAT(2, 3);
    #undef IG_ARENA_ATTR_FORMAT
#endif /* IG_ARENA_NO_VARGS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IGNIS__ARENA_H */

#ifdef IG_ARENA_IMPLEMENTATION

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif /* __clang__ */

#define IG_ARENA_PRIVATE_DEF static

#ifndef IG_ARENA_NO_VARGS
    #include <stdarg.h> /* va_list va_start va_end */
#endif /* IG_ARENA_NO_VARGS */

#if IG_ARENA_BACKEND != IG_ARENA_BACKEND_CUSTOM
IG_ARENA_PRIVATE_DEF void* IgArena__internal_malloc(arena_size_t sz) IG_ARENA_ATTR_ALLOC_SIZE1(1);
IG_ARENA_PRIVATE_DEF void IgArena__internal_free(void* ptr, arena_size_t sz);
#endif /* IG_ARENA_BACKEND != IG_ARENA_BACKEND_CUSTOM */

#if IG_ARENA_BACKEND == IG_ARENA_BACKEND_LIBC_MALLOC
    #ifdef IG_ARENA_NOSTDLIB
    #error "libc malloc cant be used when IG_ARENA_NOSTDLIB is defined"
    #endif /* IG_ARENA_NOSTDLIB */
    #include <stdlib.h> /* malloc free */
    
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_malloc(arena_size_t sz) {
        return malloc(sz);
    } 
    
    IG_ARENA_PRIVATE_DEF void IgArena__internal_free(void* ptr, arena_size_t sz) {
        (void) sz;
        free(ptr);
    }
#elif IG_ARENA_BACKEND == IG_ARENA_BACKEND_LINUX_MMAP
    #include <unistd.h>
    #include <sys/mman.h>
    
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_malloc(arena_size_t sz) {
        void* ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED) {
            return NULL;
        }
        return ptr;
    } 
    
    IG_ARENA_PRIVATE_DEF void IgArena__internal_free(void* ptr, arena_size_t sz) {
        munmap(ptr, sz);
    }
#elif IG_ARENA_BACKEND == IG_ARENA_BACKEND_WIN32_VIRTUALALLOC
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif /* WIN32_LEAN_AND_MEAN */
    #include <windows.h>
    
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_malloc(arena_size_t sz) {
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
    
    IG_ARENA_PRIVATE_DEF void IgArena__internal_free(void* ptr, arena_size_t sz) {
        (void) sz;
        VirtualFreeEx(
            GetCurrentProcess(),        /* Deallocate from current process address space */
            (LPVOID)ptr,                /* Address to deallocate */
            0,                          /* Bytes to deallocate ( Unknown, deallocate entire page ) */
            MEM_RELEASE                 /* Release the page ( And implicitly decommit it ) */
        );
    }
#elif IG_ARENA_BACKEND == IG_ARENA_BACKEND_WASM_HEAPBASE
    extern unsigned char __heap_base;
    unsigned char* bump_pointer = &__heap_base;
    
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_malloc(arena_size_t sz) {
        const unsigned int WASM_PAGE_SIZE = 1024*64;
        const unsigned int WASM_MEMORY_INDEX = 0;
        void* ptr = (void*)bump_pointer;
        
        arena_size_t current_memory_size = WASM_PAGE_SIZE * __builtin_wasm_memory_size(WASM_MEMORY_INDEX);
        arena_size_t desired_memory_size = (arena_size_t)bump_pointer + sz;
        if (desired_memory_size > current_memory_size) {
            arena_size_t delta_bytes = desired_memory_size - current_memory_size;
            arena_size_t delta_pages = (delta_bytes + (WASM_PAGE_SIZE - 1))/WASM_PAGE_SIZE;
            if (__builtin_wasm_memory_grow(WASM_MEMORY_INDEX, delta_pages) < 0) {
                return NULL;
            }
        }
    
        bump_pointer += sz;
    
        return ptr;
    }

    IG_ARENA_PRIVATE_DEF void IgArena__internal_free(void* ptr, arena_size_t sz) {
        // no-op for Wasm
        (void) ptr;
        (void) sz;
    }
#elif IG_ARENA_BACKEND == IG_ARENA_BACKEND_CUSTOM
    void* IgArena__internal_malloc(arena_size_t sz);
    void IgArena__internal_free(void* ptr, arena_size_t sz);
#else
    #error "unsuported arena backend"
#endif

#ifdef IG_ARENA_NOSTDLIB
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_memcpy(void* dst, const void* src, arena_size_t n);
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_memset(void* dst, unsigned char c, arena_size_t n);
    IG_ARENA_PRIVATE_DEF arena_size_t IgArena__internal_strlen(const char* string);

    IG_ARENA_PRIVATE_DEF void* IgArena__internal_memcpy(void* dst, const void* src, arena_size_t n) {
        unsigned char* d = dst;
        const unsigned char* s = src;
        for (; n; n--) {
            *d++ = *s++;
        }
        return dst;
    }
    
    IG_ARENA_PRIVATE_DEF void* IgArena__internal_memset(void* dst, unsigned char c, arena_size_t n) {
        void* d = dst;
        for (; n; n--) {
            *d = c;
            d++;
        }
        return dst;
    }
    
    IG_ARENA_PRIVATE_DEF arena_size_t IgArena__internal_strlen(const char* string) {
        char* s = string;
        for (; *s; s++);
        return s - string;
    }
#else /* IG_ARENA_NOSTDLIB */
    #include <string.h> /* memset memcpy strlen */
    
    #define IgArena__internal_memcpy memcpy
    #define IgArena__internal_memset memset
    #define IgArena__internal_strlen strlen
#endif /* IG_ARENA_NOSTDLIB */

/* is part of POSIX so cant depend on it */
IG_ARENA_PRIVATE_DEF arena_size_t IgArena__internal_strnlen(const char* string, arena_size_t n);
IG_ARENA_PRIVATE_DEF arena_size_t IgArena__internal_strnlen(const char* string, arena_size_t n) {
    arena_size_t result = 0;
    
    for (; result < n && string[result] != '\0'; result++);
    
    return result;
}

IG_ARENA_PRIVATE_DEF arena_size_t IgArena__get_running_mark(IgArena_Page* page) {
    arena_size_t running_mark = 0;
    
    while (page) {
        running_mark += page->mark;
        page = page->prev_page;
    }
    
    return running_mark;
}

IG_ARENA_PRIVATE_DEF IgArena_Page* IgArena__new_page(arena_size_t page_size) {
    IgArena_Page* page = (IgArena_Page*)IgArena__internal_malloc(sizeof(*page) + page_size);
    if (page == NULL) {
        return NULL;
    }
    page->prev_page = NULL;
    page->capacity = page_size;
    page->mark = 0;
    page->start = (void*)(page + 1);
    
    return page;
}

IG_ARENA_PRIVATE_DEF void IgArena__add_page(IgArena_Page* page, IgArena_Page* in) {
    while (page) {
        if (page->prev_page != NULL) {
            page->prev_page = in;
            return;
        }
        page = page->prev_page;
    }
}

IG_ARENA_PRIVATE_DEF void IgArena__free_page(IgArena_Page* page) {
    if (page == NULL) {
        return;
    }
    IgArena__free_page(page->prev_page);
    IgArena__internal_free(page, sizeof(*page));
}

IG_ARENA_API IgArena IgArena_create(arena_size_t page_size) {
    IgArena self;
    
    self.error = IG_ARENA_NONE;
    self.min_page_capacity = page_size;
    self.mark = 0;
    self.last_allocated_ptr = NULL;
    self.last_allocation_size = 0;
    self.last_page = IgArena__new_page(page_size);
    self.unused_pages = NULL;
    
    if (self.last_page == NULL) {
        self.error = IG_ARENA_OUT_OF_MEMORY;
        return self;
    }
    
    return self;
}

IG_ARENA_API void IgArena_destroy(IgArena* self) {
    IgArena__free_page(self->last_page);
    IgArena__free_page(self->unused_pages);
}

IG_ARENA_API arena_size_t IgArena_get_checkpoint(IgArena* self) {
    self->error = IG_ARENA_NONE;
    
    return self->mark;
}

IG_ARENA_API void IgArena_rewind(IgArena* self, arena_size_t checkpoint) {
    IgArena_Page* page;
    IgArena_Page* other_page;
    arena_size_t running_mark;
    
    self->error = IG_ARENA_NONE;
    
    /* if it is more then the mark it is invalid and if it is equal to mark there is no work to do */
    if (checkpoint >= self->mark) {
        return;
    }
    
    page = self->last_page;
    
    while (page) {
        running_mark = IgArena__get_running_mark(page);

        /* if the checkpoint is between the running mark and the running mark at the start of the page */
        if (running_mark - page->mark <= checkpoint && checkpoint <= running_mark) {
            if (page == self->last_page) { /* the checkpoint was refering to the first page */
                self->last_page->mark -= self->mark - checkpoint;
                self->mark = checkpoint;
                self->last_allocated_ptr = NULL;
                self->last_allocation_size = 0;
                break;
            } else { /* the checkpoint refers to a page other then the first */
                /* search for the page before the one that holds the checkpoint */
                for (other_page = self->last_page;; other_page = other_page->prev_page) {
                    if (other_page->prev_page == page) {
                        other_page->prev_page = NULL;
                        if (self->unused_pages == NULL) {
                            self->unused_pages = self->last_page;
                        } else {
                            IgArena__add_page(self->unused_pages, self->last_page);
                        }
                        
                        break;
                    }
                }
                self->last_page = page;
                self->last_page->mark = checkpoint - IgArena__get_running_mark(self->last_page->prev_page);
                self->mark = checkpoint;
                self->last_allocated_ptr = NULL;
                self->last_allocation_size = 0;
                break;
            }
        }
        
        page = page->prev_page;
    }
}

IG_ARENA_API void IgArena_reset(IgArena* self) {
    self->error = IG_ARENA_NONE;
    
    if (self->unused_pages == NULL) {
        self->unused_pages = self->last_page;
    } else {
        IgArena__add_page(self->unused_pages, self->last_page);
    }
    
    self->last_page = self->unused_pages;  
    self->unused_pages = self->unused_pages->prev_page;
    self->last_page->prev_page = NULL;
    
    self->mark = 0;
    self->last_page->mark = 0;
    self->last_allocated_ptr = NULL;
}

IG_ARENA_API void IgArena_reset_and_zero(IgArena* self) {
    IgArena_Page* page;
    
    self->error = IG_ARENA_NONE;
    
    IgArena_reset(self);
    
    IgArena__internal_memset(self->last_page->start, 0, self->last_page->capacity);
    
    for (page = self->unused_pages; page; page = page->prev_page) {
        IgArena__internal_memset(page->start, 0, page->capacity);
    }
}

IG_ARENA_API void* IgArena_alloc(IgArena* self, arena_size_t size) {
    IgArena_Page* new_page = NULL;
    IgArena_Page* prev_page = NULL;

    self->error = IG_ARENA_NONE;
    
    /* (1) check if the size is valid */
    if (size == 0) {
        self->error = IG_ARENA_INVALID_SIZE;
        return NULL;
    }
    /* (2) provide a simple chunk */
    if (self->last_page->mark + size <= self->last_page->capacity) {
        self->last_allocated_ptr = self->last_page->start + self->last_page->mark;
        self->last_allocation_size = size;
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
            new_page = IgArena__new_page(size > self->min_page_capacity ? size : self->min_page_capacity);
            if (new_page == NULL) {
                self->error = IG_ARENA_OUT_OF_MEMORY;
                return NULL;
            }
        }
        
        self->mark = self->mark - self->last_page->mark + self->last_page->capacity;
        self->last_page->mark = self->last_page->capacity;
        
        new_page->prev_page = self->last_page;
        self->last_page = new_page;
        new_page->mark = 0;
        /* (5) it will go to (2) so no reason to duplicate code */
        return IgArena_alloc(self, size);
    }
}

#ifndef IG_ARENA_UINTPTR_T
    #include <stdint.h> /* uintptr_t */
    #define IG_ARENA_UINTPTR_T uintptr_t
#endif /* IG_ARENA_UINTPTR_T */
IG_ARENA_API void* IgArena_memalign(IgArena* self, arena_size_t size, arena_size_t alignment) {
    char* address;
    arena_size_t allocation_size;
    
    self->error = IG_ARENA_NONE;
    
    /* no alignment */
    if (alignment <= 1) {
        return IgArena_alloc(self, size);
    }
    /* not power of 2 or smaller then the size of a pointer */
    if (alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0) {
        self->error = IG_ARENA_INVALID_ALIGNMENT;
        return NULL;
    }
    if (size == 0) {
        self->error = IG_ARENA_INVALID_SIZE;
        return NULL;
    }
    
    if ((IG_ARENA_UINTPTR_T)self->last_page->start + self->last_page->mark + size <= self->last_page->capacity) {
        if (((IG_ARENA_UINTPTR_T)self->last_page->start + self->last_page->mark) % alignment == 0) {
            return IgArena_alloc(self, size);
        }
    }
    allocation_size = size + alignment - 1;
    address = IgArena_alloc(self, allocation_size);
    address = (char*)(address + (alignment - (IG_ARENA_UINTPTR_T)address % alignment));
    
    self->last_allocated_ptr = address;
    self->last_allocation_size = size;
    
    return address;
}

IG_ARENA_API void* IgArena_calloc(IgArena* arena, arena_size_t count, arena_size_t size) {
    void* ptr = IgArena_alloc(arena, count*size);
    
    if (ptr == NULL) {
        return NULL;
    }
    
    return IgArena__internal_memset(ptr, 0, count*size);
}

IG_ARENA_API void* IgArena_realloc(IgArena* self, void* ptr, arena_size_t old_size, arena_size_t new_size) {
    void* new_ptr;
    
    self->error = IG_ARENA_NONE;
    
    /* if the ptr is NULL then allocate new_size bytes */
    if (ptr == NULL) {
        return IgArena_alloc(self, new_size);
    } else if (ptr != NULL && new_size == 0) {
        /* free the pointer if the new_size is 0 */
        IgArena_free(self, ptr);
        return NULL;
    } else {
        /* if it was not the last allocation then it cant be extended */
        if (self->last_allocated_ptr != ptr) {
            new_ptr = IgArena_alloc(self, new_size);
            if (new_ptr == NULL) {
                return NULL;
            }
            return IgArena__internal_memcpy(new_ptr, ptr, old_size);
        } else {
            /* the new size is less then the old size */
            if (self->last_allocation_size >= new_size) {
                self->last_page->mark -= self->last_allocation_size - new_size;
                self->mark -= self->last_allocation_size - new_size;
                self->last_allocation_size = new_size;
                return ptr;
            } else {
                /* check if the current page can hold extra data */
                if (new_size - self->last_allocation_size + self->last_page->mark <= self->last_page->capacity) {
                    self->last_page->mark += new_size - self->last_allocation_size;
                    self->mark += new_size - self->last_allocation_size;
                    self->last_allocation_size = new_size;
                    return ptr;
                } else {
                    /* womp womp */
                    new_ptr = IgArena_alloc(self, new_size);
                    if (new_ptr == NULL) {
                        return NULL;
                    }
                    return IgArena__internal_memcpy(new_ptr, ptr, old_size);
                }
            }
        }
    }
}

IG_ARENA_API void IgArena_free(IgArena* self, void* ptr) {
    self->error = IG_ARENA_NONE;
    
    /* self->last_allocated_ptr might be null */
    if (ptr == NULL) {
        return;
    }
    
    /* try to reclaim the memory if it was the last allocation made */
    if (ptr == self->last_allocated_ptr) {
        /* last_allocation_size = (start + mark) - ptr; */
        self->mark -= self->last_allocation_size;
        self->last_page->mark -= self->last_allocation_size;
        /* some safety to guard against double free */
        self->last_allocated_ptr = NULL;
        self->last_allocation_size = 0;
    }
}

IG_ARENA_API char* IgArena_strdup(IgArena* self, const char* str) {
    arena_size_t str_size;
    char* ptr;
    
    self->error = IG_ARENA_NONE;
    
    str_size = IgArena__internal_strlen(str);
    ptr = IgArena_alloc(self, str_size + 1);
    
    if (ptr == NULL) {
        return NULL;
    }
    
    return IgArena__internal_memcpy(ptr, str, str_size + 1);
}

IG_ARENA_API char* IgArena_strndup(IgArena* arena, const char* str, arena_size_t n) {
    arena_size_t len = IgArena__internal_strnlen(str, n);
    char* copy = (char*)IgArena_alloc(arena, len + 1);
    if (copy) {
        IgArena__internal_memcpy(copy, str, len);
        copy[len] = '\0';
    }
    return copy;
}

IG_ARENA_API void* IgArena_memdup(IgArena* arena, const void* buffer, arena_size_t buffer_size) {
    void* ptr = IgArena_alloc(arena, buffer_size);
    if (ptr == NULL) {
        return NULL;
    }
    return IgArena__internal_memcpy(ptr, buffer, buffer_size);
}

#ifdef IG_ARENA_NO_VARGS
    IG_ARENA_API char* IgArena_strcat(IgArena* arena, const char* str1, const char* str2) {
        arena_size_t str1_size = IgArena__internal_strlen(str1);
        arena_size_t str2_size = IgArena__internal_strlen(str2);
        arena_size_t result_len = str1_size + str2_size;
        char* result;
        
        result = IgArena_alloc(arena, result_len + 1);
        if (!result) {
            return NULL;
        }
        
        IgArena__internal_memcpy(result, str1, str1_size);
        IgArena__internal_memcpy(result + str1_size, str2, str2_size);
        result[result_len] = 0;
        
        return result;
    }
    
    IG_ARENA_API char* IgArena_join_strings(IgArena* arena, const char* sep, const char* str1, const char* str2) {
        arena_size_t str1_size = IgArena__internal_strlen(str1);
        arena_size_t sep_size = IgArena__internal_strlen(sep);
        arena_size_t str2_size = IgArena__internal_strlen(str2);
        arena_size_t result_len = str1_size + sep_size + str2_size;
        char* result;
        
        result = IgArena_alloc(arena, result_len + 1);
        if (!result) {
            return NULL;
        }
        
        IgArena__internal_memcpy(result, str1, str1_size);
        IgArena__internal_memcpy(result + str1_size, sep, sep_size);
        IgArena__internal_memcpy(result + str1_size + sep_size, str2, str2_size);
        result[result_len] = 0;
        
        return result;
    }
#else /* IG_ARENA_NO_VARGS */
    #ifdef IG_ARENA_C89
        IG_ARENA_API char* IgArena_strcat(IgArena* arena, const char* str1, ...) {
            va_list vargs;
            char* result;
            const char* string;
            arena_size_t result_len = IgArena__internal_strlen(str1);
            arena_size_t offset;
            
            va_start(vargs, str1);
            for (string = va_arg(vargs, const char*); string; string = va_arg(vargs, const char*)) {
                result_len += IgArena__internal_strlen(string);
            }
            va_end(vargs);
            
            result = IgArena_alloc(arena, result_len + 1);
            if (!result) {
                return NULL;
            }
            
            offset = IgArena__internal_strlen(str1);
            IgArena__internal_memcpy(result, str1, offset);
            result[result_len] = '\0';
            
            va_start(vargs, str1);
            for (string = va_arg(vargs, const char*); string; string = va_arg(vargs, const char*)) {
                arena_size_t string_len = IgArena__internal_strlen(string);
                IgArena__internal_memcpy(result + offset, string, string_len);
                offset += string_len;
            }
            va_end(vargs);
            
            return result;
        }
        
        IG_ARENA_API char* IgArena_join_strings(IgArena* arena, const char* sep, const char* str1, ...) {
            va_list vargs;
            char* final_string;
            arena_size_t final_string_len;
            arena_size_t offset;
            const char* strarg;
            
            va_start(vargs, str1);
                final_string_len = 0;
                final_string_len += strlen(str1);
                
                strarg = va_arg(vargs, const char*);
                for (; strarg; strarg = va_arg(vargs, const char*)) {
                    final_string_len += strlen(sep);
                    final_string_len += strlen(strarg);
                }
            va_end(vargs);
            final_string = IgArena_alloc(arena, final_string_len + 1);
            
            if (final_string == NULL) {
                return NULL;
            }
            
            va_start(vargs, str1);
                offset = 0;
                IgArena__internal_memcpy(final_string + offset, str1, strlen(str1));
                offset += strlen(str1);
                
                strarg = va_arg(vargs, const char*);
                for (; strarg; strarg = va_arg(vargs, const char*)) {
                    IgArena__internal_memcpy(final_string + offset, sep, strlen(sep));
                    offset += strlen(sep);
                    IgArena__internal_memcpy(final_string + offset, strarg, strlen(strarg));
                    offset += strlen(strarg);
                }
            va_end(vargs);
            
            final_string[final_string_len] = 0;
            
            return final_string;
        }
    #else /* IG_ARENA_C89 */
        IG_ARENA_API char* IgArena__strcat(IgArena* arena, const char* str1, ...) {
            va_list vargs;
            char* result;
            const char* string;
            arena_size_t result_len = IgArena__internal_strlen(str1);
            arena_size_t offset;
            
            va_start(vargs, str1);
            for (string = va_arg(vargs, const char*); string; string = va_arg(vargs, const char*)) {
                result_len += IgArena__internal_strlen(string);
            }
            va_end(vargs);
            
            result = IgArena_alloc(arena, result_len + 1);
            if (!result) {
                return NULL;
            }
            
            offset = IgArena__internal_strlen(str1);
            IgArena__internal_memcpy(result, str1, offset);
            result[result_len] = '\0';
            
            va_start(vargs, str1);
            for (string = va_arg(vargs, const char*); string; string = va_arg(vargs, const char*)) {
                arena_size_t string_len = IgArena__internal_strlen(string);
                IgArena__internal_memcpy(result + offset, string, string_len);
                offset += string_len;
            }
            va_end(vargs);
            
            return result;
        }
        
        IG_ARENA_API char* IgArena__join_strings(IgArena* arena, const char* sep, const char* str1, ...) {
            va_list vargs;
            char* final_string;
            arena_size_t final_string_len;
            arena_size_t offset;
            const char* strarg;
            
            va_start(vargs, str1);
                final_string_len = 0;
                final_string_len += strlen(str1);
                
                strarg = va_arg(vargs, const char*);
                for (; strarg; strarg = va_arg(vargs, const char*)) {
                    final_string_len += strlen(sep);
                    final_string_len += strlen(strarg);
                }
            va_end(vargs);
            final_string = IgArena_alloc(arena, final_string_len + 1);
            
            if (final_string == NULL) {
                return NULL;
            }
            
            va_start(vargs, str1);
                offset = 0;
                IgArena__internal_memcpy(final_string + offset, str1, strlen(str1));
                offset += strlen(str1);
                
                strarg = va_arg(vargs, const char*);
                for (; strarg; strarg = va_arg(vargs, const char*)) {
                    IgArena__internal_memcpy(final_string + offset, sep, strlen(sep));
                    offset += strlen(sep);
                    IgArena__internal_memcpy(final_string + offset, strarg, strlen(strarg));
                    offset += strlen(strarg);
                }
            va_end(vargs);
            
            final_string[final_string_len] = 0;
            
            return final_string;
        }
    #endif /* IG_ARENA_C89 */
#endif /* IG_ARENA_NO_VARGS */

IG_ARENA_API const char* IgArena_error_to_string(IgArena_Error error) {
    if (error == IG_ARENA_NONE) return "NONE";
    if (error == IG_ARENA_OUT_OF_MEMORY) return "OUT_OF_MEMORY";
    if (error == IG_ARENA_INVALID_SIZE) return "INVALID_SIZE";
    if (error == IG_ARENA_INVALID_ALIGNMENT) return "INVALID_ALIGNMENT";
    if (error == IG_ARENA_INVALID_FORMAT) return "INVALID_FORMAT";
    return "UNKNOWN_ERROR";
}

#ifndef IG_ARENA_NO_VARGS
    #if (!defined(IG_ARENA_NOSTDLIB) && !defined(IG_ARENA_C89)) || (defined(IG_ARENA_C89) && defined(IG_ARENA_CUSTOM_VSNPRINTF)) || defined(IG_ARENA_CUSTOM_VSNPRINTF)
        #if !defined(IG_ARENA_NOSTDLIB) && !defined(IG_ARENA_CUSTOM_VSNPRINTF)
            #include <stdio.h> /* vsnprintf */
        #endif /* !defined(IG_ARENA_NOSTDLIB) && !defined(IG_ARENA_CUSTOM_VSNPRINTF) */
            
        IG_ARENA_API char* IgArena_sprintf(IgArena* self, const char* format, ...) {
            va_list args;
            char* result;
            int n;
            
            self->error = IG_ARENA_NONE;
            
            va_start(args, format);
            #ifdef IG_ARENA_CUSTOM_VSNPRINTF
                n = IG_ARENA_CUSTOM_VSNPRINTF(NULL, 0, format, args);
            #else
                n = vsnprintf(NULL, 0, format, args);
            #endif
            va_end(args);
        
            if (n < 0) {
                self->error = IG_ARENA_INVALID_FORMAT;
                return NULL;
            }
            
            result = (char*)IgArena_alloc(self, (arena_size_t)n + 1);
            if (result == NULL) {
                return NULL;
            }
            va_start(args, format);
            #ifdef IG_ARENA_CUSTOM_VSNPRINTF
                IG_ARENA_CUSTOM_VSNPRINTF(result, (arena_size_t)n + 1, format, args);
            #else
                vsnprintf(result, (arena_size_t)n + 1, format, args);
            #endif
            va_end(args);
        
            return result;
        }
    #endif /* (!defined(IG_ARENA_NOSTDLIB) && !defined(IG_ARENA_C89)) || (defined(IG_ARENA_C89) && defined(IG_ARENA_CUSTOM_VSNPRINTF)) || defined(IG_ARENA_CUSTOM_VSNPRINTF) */
#endif /* IG_ARENA_NO_VARGS */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IG_ARENA_IMPLEMENTATION */
