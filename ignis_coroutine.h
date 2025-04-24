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

/**
 * @file ignis_coroutine.h
 * @brief Lightweight coroutine library for cooperative multitasking.
 * @author Stamelos Vasilis
 * @copyright MIT License
 */
 
/*
 * What are coroutines:
 * Coroutines are computer program components that allow execution to be suspended and resumed,
 * generalizing subroutines for cooperative multitasking. Coroutines are well-suited for 
 * implementing familiar program components such as cooperative tasks, exceptions, event loops,
 * iterators, infinite lists and pipes.
 *
 * what this implementation offers:
 * this implementation offers 2 APIs:
 * - Coroutine API
 *     minimal implementation for coroutines such as yield, start, suspend, resume
 * - Scheduler API
 *     more "advanced" features such as timeout, sleep for a specific duration and more built on top of the Coroutine API.
*/
 
#ifndef IGNIS__COROUTINE_H_
#define IGNIS__COROUTINE_H_

#ifndef IG_COROUTINE_STACK_SIZE
#define IG_COROUTINE_STACK_SIZE (64*1024)
#endif /* IG_COROUTINE_STACK_SIZE */

/* currently supported platforms: x86_64-linux x86_64-windows */
/* currently supported compilers: clang gcc */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#endif /* __clang__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup coroutine_api Coroutine API
 *  @brief Primary interface for creating and managing coroutines.
 *  @{
 */
/**
 * @brief Coroutine function type.
 * @param arg User-provided argument passed to the coroutine.
 */
typedef void (*IgCoroutineFn)(void* arg);
/**
 * @brief Yields execution to the next coroutine.
 * @details This function suspends the current coroutine and switches to the next one.
 */
void IgCoroutine_yield(void);
/**
 * @brief Starts a new coroutine.
 * @param func The coroutine function to execute.
 * @param arg Argument passed to `func`.
 * @return The ID of the newly created coroutine, or -1 on failure (happens when it runs out of memory).
 * @warning The stack size is fixed (default: 64KB). Ensure `func` does not overflow it.
 */
int IgCoroutine_start(IgCoroutineFn func, void* arg);
/**
 * @brief Gets the ID of the currently executing coroutine.
 * @return The coroutine ID (≥ 0), 0 refers to the main thread/primary coroutine.
 */
int IgCoroutine_id(void);
/**
 * @brief Gets the number of currently active coroutines.
 * @return Count of coroutines in the active queue.
 */
int IgCoroutine_active_count(void);
/**
 * @brief Gets the number of sleeping coroutines.
 * @return Count of coroutines in the sleeping queue.
 */
int IgCoroutine_sleeping_count(void);
/**
 * @brief Suspends the execution of a coroutine.
 * @param id The ID of the coroutine to suspend.
 * @note The coroutine will not execute until `IgCoroutine_resume()` is called.
 */
void IgCoroutine_suspend(int id);
/**
 * @brief Resumes the execution of a suspended coroutine.
 * @param id The ID of the coroutine to resume.
 * @note The coroutine re-enters the active queue.
 */
void IgCoroutine_resume(int id);
/**
 * @brief Terminates a coroutine.
 * @param id The ID of the coroutine to kill.
 */
void IgCoroutine_terminate(int id);
/**
 * @brief Blocks until all coroutines complete execution.
 * @ingroup coroutine_api
 * 
 * @details
 * This function yields control repeatedly until only the main execution context remains
 * (i.e., when `IgCoroutine_active_count()` returns 1). It is typically used in the main
 * thread to wait for all spawned coroutines to finish.
 * 
 * @note
 * - New coroutines can still be spawned while `IgCoroutine_join()` is active.
 * - This is a cooperative join; coroutines must eventually yield or terminate.
 */
void IgCoroutine_join(void);
/** @} */ /* End of coroutine_api group */


#ifndef IG_COROUTINE_DISABLE_SCHEDULER
/**
 * @defgroup scheduler_api Scheduler API 
 * @brief Cooperative scheduler for timed and guarded coroutine execution.
 * @note Disable with `#define IG_COROUTINE_DISABLE_SCHEDULER`.
 * @{
 */
/**
 * @brief Guard function type for conditional coroutine wakeup.
 * @param arg User-provided argument.
 * @return 1 if the coroutine should wake, 0 to keep sleeping.
 */
typedef int(*IgCorouineSchedulerGuardFn)(void* arg);
/**
 * @brief Timeout callback function type.
 * @param arg User-provided argument passed during timeout setup.
 */
typedef void(*IgCoroutineSchedulerTimeoutFn)(void* arg);
/**
 * @brief similar to IgCoroutine_join but it adds the functionality of the scheduler.
 * @param ms_timeout Idle sleep duration (milliseconds) when no coroutines are active.
 * @warning Only one scheduler instance is allowed.
 */
void IgCoroutineScheduler_join(long int ms_timeout);
/**
 * @brief Suspends the current coroutine until a condition is met.
 * @param fn Guard function called periodically to check wakeup conditions.
 * @param arg Argument passed to `fn`.
 */
void IgCoroutineScheduler_guard(IgCorouineSchedulerGuardFn fn, void* arg);
/**
 * @brief Suspends the current coroutine for a fixed duration.
 * @param ms Sleep duration in milliseconds.
 * @note Actual wakeup may be slightly delayed due to scheduler granularity.
 */
void IgCoroutineScheduler_sleep(unsigned int ms);
/**
 * @brief Starts a coroutine with a timeout.
 * @param func Coroutine function to execute.
 * @param arg Argument passed to `func`.
 * @param timeoutfn Callback invoked if the coroutine times out (optional).
 * @param timeoutarg Argument passed to `timeoutfn`.
 * @param timeout_ms Maximum runtime before termination (milliseconds).
 */
void IgCoroutineScheduler_timeout(IgCoroutineFn func, void* arg, 
                                  IgCoroutineSchedulerTimeoutFn timeoutfn, 
                                  void* timeoutarg, 
                                  unsigned int timeout_ms);
/** @} */ /* End of scheduler_api group */
#endif /* IG_COROUTINE_DISABLE_SCHEDULER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IGNIS__COROUTINE_H_ */

/* simple counter */
#if 0
    #include <stdio.h>
    #define IG_COROUTINE_IMPLEMENTATION
    #include "ignis_coroutine.h"
    
    static void func(void* arg) {
        unsigned long i;
        
        for (i = (unsigned long)arg; i < 10; i++) {
            printf("[%d] %lu\n", IgCoroutine_id(), i);
            if (i == 4) {
                IgCoroutine_start(func, (void*)7);
                IgCoroutine_terminate(IgCoroutine_id());
            }
            IgCoroutine_yield();
        }
    }
    
    int main(void) {
        IgCoroutine_start(func, (void*)0);
        IgCoroutine_start(func, (void*)5);
    
        IgCoroutine_join();
        
        return 0;
    }
#endif /* 0 */

/* on linux-x86_64 AT&T is default, to produce intel syntax define IG_COROUTINE_INTEL when compiling this file */
/* on windows-x86_64 AT&T is default (unless msvc compiler is detected), to produce intel syntax define IG_COROUTINE_INTEL when compiling this file */
/* define IG_COROUTINE_INTEL to produce intel assembly instead of AT&T when compiling for x86_x64 */

#ifdef IG_COROUTINE_IMPLEMENTATION

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#include <sys/mman.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wcast-align"
#endif /* __clang__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(__GNUC__)
    #define IG_COROUTINE_GCC
#elif defined(__clang__)
    #define IG_COROUTINE_CLANG
#else
    #error "Unsupported compiler (clang/gnu required)"
#endif

#if defined(__x86_64__) || defined(_M_X64)
    #define IG_COROUTINE_ARCH_X86_64
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define IG_COROUTINE_ARCH_AARCH64
#else 
    #error "Unsupported architecture (only x86_64 and AArch64 are supported)"
#endif

#if defined(IG_COROUTINE_ARCH_X86_64)
    #if defined(__linux__) || defined(__linux)
        #define IG_COROUTINE_X86_64_LINUX
    #elif defined(_WIN32) || defined(_WIN64)
        #define IG_COROUTINE_X86_64_WINDOWS
    #else
        #error "x86_64 architecture detected, but OS is not supported (Linux/Windows required)"
    #endif
#elif defined(IG_COROUTINE_ARCH_AARCH64)
    #if defined(__linux__)
        #define IG_COROUTINE_AARCH64_LINUX
    #elif defined(_WIN32) || defined(_WIN64)
        #define IG_COROUTINE_AARCH64_WINDOWS
    #elif defined(__APPLE__) && defined(__MACH__)
        #define IG_COROUTINE_AARCH64_MACOS
    #else
        #error "AArch64 architecture detected, but OS is not supported (Linux/macOS/Windows required)"
    #endif
#else
    #error "Internal error, unreachable"
#endif

#if defined(IG_COROUTINE_ARCH_X86_64)
    #if defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG)
        #ifdef IG_COROUTINE_INTEL
            #define IG_COROUTINE_ASM_PUSH(reg)     asm volatile("    push " #reg "\n")
            #define IG_COROUTINE_ASM_POP(reg)      asm volatile("    pop " #reg "\n")
            #define IG_COROUTINE_ASM_RET()         asm volatile("    ret\n")
            #define IG_COROUTINE_ASM_MOV(from, to) asm volatile("    mov " #to ", " #from "\n")
            #define IG_COROUTINE_ASM_JMP(to)       asm volatile("    jmp " #to "\n")
        #else /* IG_COROUTINE_INTEL */
            #define IG_COROUTINE_ASM_PUSH(reg)     asm volatile("    pushq %" #reg "\n")
            #define IG_COROUTINE_ASM_POP(reg)      asm volatile("    popq %" #reg "\n")
            #define IG_COROUTINE_ASM_RET()         asm volatile("    ret\n")
            #define IG_COROUTINE_ASM_MOV(from, to) asm volatile("    movq %" #from ", %" #to "\n")
            #define IG_COROUTINE_ASM_JMP(to)       asm volatile("    jmp " #to "\n")
        #endif /* IG_COROUTINE_INTEL */
    #else /* defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG) */
        #if defined(_MSC_VER)
            #error "msvc is not supported because it doesnt allow inline x86_64 assembly"
        #else /* _MSC_VER */
            #error "only clang, gcc and msvc are supported"
        #endif /* _MSC_VER */
    #endif /* defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG) */
#endif /* defined(IG_COROUTINE_ARCH_X86_64) */

#if defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG)
    #define IG_COROUTINE_NAKED __attribute__((naked))
#elif defined(_MSC_VER)
    #define IG_COROUTINE_NAKED __declspec(naked)
#else
    #define IG_COROUTINE_NAKED
#endif

#if defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG)
    #define IG_COROUTINE_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
    #define IG_COROUTINE_NOINLINE __declspec(noinline)
#else
    #define IG_COROUTINE_NOINLINE
#endif

#if defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG)
    #define IG_COROUTINE_KEEP_FUNCTION __attribute__((used))
#elif defined(_MSC_VER)
    #define IG_COROUTINE_KEEP_FUNCTION __declspec(selectany)
#else
    #define IG_COROUTINE_KEEP_FUNCTION
#endif

#if defined(IG_COROUTINE_GCC) || defined(IG_COROUTINE_CLANG)
    #define IG_COROUTINE_UNUSED __attribute__((unused))
#elif defined(_MSC_VER)
    #define IG_COROUTINE_UNUSED __declspec(unused)
#else
    #define IG_COROUTINE_UNUSED
#endif

typedef struct IgCoroutineContext {
    void* stack_base; /* the pointer that was allocated */
    void* rsp;        /* rsp starts at the "end" and moves backwards */
} IgCoroutineContext;

typedef struct IgCoroutineContexts {
    IgCoroutineContext* contexts;
    size_t size;
    size_t capacity;
} IgCoroutineContexts;

typedef struct IgCoroutineIndices {
    int* indices;
    size_t size;
    size_t capacity;
} IgCoroutineIndices;

static IgCoroutineIndices  IgCoroutine__active   = {0};
static IgCoroutineIndices  IgCoroutine__dead     = {0};
static IgCoroutineIndices  IgCoroutine__sleeping = {0};
static IgCoroutineContexts IgCoroutine__contexts = {0};
static int                 IgCoroutine__current  =  0 ;

static void IgCoroutineIndices__append(IgCoroutineIndices* indices, int id) {
    if (indices->size >= indices->capacity) {
        indices->capacity += 256;
        indices->indices = realloc(indices->indices, indices->capacity * sizeof(int));
    }
    indices->indices[indices->size++] = id;
}

static void IgCoroutineIndices__pop(IgCoroutineIndices* indices, size_t i) {
    if (i < indices->size) {
        indices->indices[i] = indices->indices[--indices->size];
    }
}

static void IgCoroutineContexts__add_new(IgCoroutineContexts* contexts) {
    if (contexts->size >= contexts->capacity) {
        contexts->capacity += 256;
        contexts->contexts = realloc(contexts->contexts, contexts->capacity * sizeof(IgCoroutineContext));
    }
    contexts->contexts[contexts->size].stack_base = NULL;
    contexts->contexts[contexts->size].rsp = NULL;
    contexts->size++;
}

IG_COROUTINE_NAKED IG_COROUTINE_NOINLINE void IgCoroutine_yield(void) {
    /* savest the required registers to perform the jump and **jumps** IgCoroutine_switch_context(rsp) */
    #if defined(IG_COROUTINE_X86_64_LINUX)
        IG_COROUTINE_ASM_PUSH(rdi);
        IG_COROUTINE_ASM_PUSH(rbp);
        IG_COROUTINE_ASM_PUSH(rbx);
        IG_COROUTINE_ASM_PUSH(r12);
        IG_COROUTINE_ASM_PUSH(r13);
        IG_COROUTINE_ASM_PUSH(r14);
        IG_COROUTINE_ASM_PUSH(r15);
        IG_COROUTINE_ASM_MOV(rsp, rdi);
        IG_COROUTINE_ASM_JMP(IgCoroutine_switch_context);
    #elif defined(IG_COROUTINE_X86_64_WINDOWS)
        IG_COROUTINE_ASM_PUSH(rcx);
        IG_COROUTINE_ASM_PUSH(rbx);
        IG_COROUTINE_ASM_PUSH(rbp);
        IG_COROUTINE_ASM_PUSH(rdi);
        IG_COROUTINE_ASM_PUSH(rsi);
        IG_COROUTINE_ASM_PUSH(r12);
        IG_COROUTINE_ASM_PUSH(r13);
        IG_COROUTINE_ASM_PUSH(r14);
        IG_COROUTINE_ASM_PUSH(r15);
        IG_COROUTINE_ASM_MOVE(rsp, rcx);
        IG_COROUTINE_ASM_JMP(IgCoroutine_switch_context);
    #else
        #error "this platform isnt supported yet"
    #endif
}

static IG_COROUTINE_NAKED IG_COROUTINE_NOINLINE void IgCoroutine_restore_context(void *rsp IG_COROUTINE_UNUSED) {
    /* to call restore_context means that yield was called and the return address is saved
     * so it only needs to reverse the yield operation and return */
     
    /* the rest of the registers are "volatile" and they are expected to be changed */
    #if defined(IG_COROUTINE_X86_64_LINUX)
        IG_COROUTINE_ASM_MOV(rdi, rsp);
        IG_COROUTINE_ASM_POP(r15);
        IG_COROUTINE_ASM_POP(r14);
        IG_COROUTINE_ASM_POP(r13);
        IG_COROUTINE_ASM_POP(r12);
        IG_COROUTINE_ASM_POP(rbx);
        IG_COROUTINE_ASM_POP(rbp);
        IG_COROUTINE_ASM_POP(rdi);
        IG_COROUTINE_ASM_RET();
    #elif defined(IG_COROUTINE_X86_64_WINDOWS)
        IG_COROUTINE_ASM_MOV(rcx, rsp);
        IG_COROUTINE_ASM_POP(r15);
        IG_COROUTINE_ASM_POP(r14);
        IG_COROUTINE_ASM_POP(r13);
        IG_COROUTINE_ASM_POP(r12);
        IG_COROUTINE_ASM_POP(rsi);
        IG_COROUTINE_ASM_POP(rdi);
        IG_COROUTINE_ASM_POP(rbp);
        IG_COROUTINE_ASM_POP(rbx);
        IG_COROUTINE_ASM_POP(rcx);
        IG_COROUTINE_ASM_RET();
    #else
        #error "this platform isnt supported yet"
    #endif
}

static IG_COROUTINE_NOINLINE IG_COROUTINE_KEEP_FUNCTION void IgCoroutine_switch_context(void *rsp) {
    IgCoroutine__contexts.contexts[IgCoroutine__active.indices[IgCoroutine__current]].rsp = rsp;

    IgCoroutine__current = (IgCoroutine__current + 1) % (int)IgCoroutine__active.size;

    IgCoroutine_restore_context(IgCoroutine__contexts.contexts[IgCoroutine__active.indices[IgCoroutine__current]].rsp);
}

static void IgCoroutine__finish_current(void) {
    IgCoroutineIndices__append(&IgCoroutine__dead, IgCoroutine__active.indices[IgCoroutine__current]);
    IgCoroutineIndices__pop(&IgCoroutine__active, (size_t)IgCoroutine__current);

    IgCoroutine__current %= IgCoroutine__active.size;
    IgCoroutine_restore_context(IgCoroutine__contexts.contexts[IgCoroutine__active.indices[IgCoroutine__current]].rsp);
}

static void* IgCoroutine__allocate_stack(size_t size) {
    void* ptr;
    
    #ifdef _WIN32
        SYSTEM_INFO si;
        DWORD page_size;
        DWORD protect_size;
        void* guard_page;
        if (!VirtualProtect(guard_page, page_size, PAGE_READWRITE | PAGE_GUARD, &old_protect)) {
        
        GetSystemInfo(&si);
        page_size = si.dwPageSize;
        
        protect_size = (DWORD)size + page_size;
        
        ptr = VirtualAlloc(NULL, protect_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr == NULL) {
            return NULL;
        }
        
        guard_page = ptr;
        DWORD old_protect;
            VirtualFree(ptr, 0, MEM_RELEASE);
            return NULL;
        }
        
        ptr = (char*)ptr + page_size;
    #else /* _WIN32 */
        #ifdef __linux__
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                      MAP_STACK | MAP_GROWSDOWN | MAP_PRIVATE | MAP_ANONYMOUS, 
                      -1, 0);
            if (ptr == MAP_FAILED) {
                return NULL;
            }
            
        #else /* __linux__ */
            size_t page_size = (size_t)getpagesize();
            
            ptr = mmap(NULL, size + page_size, PROT_READ | PROT_WRITE, 
                      MAP_PRIVATE | MAP_ANONYMOUS, 
                      -1, 0);
            if (ptr == MAP_FAILED) {
                return NULL;
            }
            
            // Add manual guard page for non-Linux POSIX systems
            if (mprotect(ptr, page_size, PROT_NONE)) {
                munmap(ptr, size + page_size);
                return NULL;
            }
            ptr += page_size;
        #endif /* __linux__ */
    #endif /* _WIN32 */
    
    return ptr;
}

static void IgCoroutine__free_stack(void* stack, size_t size) {
    #ifdef _WIN32
        SYSTEM_INFO si;
        void* original_ptr = (char*)stack - si.dwPageSize;
        GetSystemInfo(&si);
        VirtualFree(original_ptr, 0, MEM_RELEASE);
    #else
        #ifdef __linux__
            munmap(stack, size);
        #else
            size_t page_size = (size_t)getpagesize();
            stack = (char*)stack - page_size;
            mprotect(stack, page_size, PROT_READ | PROT_WRITE);
            munmap(stack, size + page_size);
        #endif
    #endif
}

int IgCoroutine_start(IgCoroutineFn func, void* arg) {
    int id;
    void** rsp;
    
    if (IgCoroutine__contexts.size == 0) {
        IgCoroutineContexts__add_new(&IgCoroutine__contexts);
        IgCoroutineIndices__append(&IgCoroutine__active, 0);
    }
    
    if (IgCoroutine__dead.size > 0) {
        id = IgCoroutine__dead.indices[--IgCoroutine__dead.size];
    } else {
        IgCoroutineContexts__add_new(&IgCoroutine__contexts);
        id = (int)IgCoroutine__contexts.size-1;
        IgCoroutine__contexts.contexts[id].stack_base = IgCoroutine__allocate_stack(IG_COROUTINE_STACK_SIZE);
        assert(IgCoroutine__contexts.contexts[id].stack_base != NULL);
    }

    rsp = (void**)((char*)IgCoroutine__contexts.contexts[id].stack_base + IG_COROUTINE_STACK_SIZE);

    /* a shim yield */
    #if defined(IG_COROUTINE_X86_64_LINUX)
        *(--rsp) = (void*)(uintptr_t)IgCoroutine__finish_current;
        *(--rsp) = (void*)(uintptr_t)func;
        *(--rsp) = arg; /* push rdi */
        *(--rsp) = 0;   /* push rbp */
        *(--rsp) = 0;   /* push rbx */
        *(--rsp) = 0;   /* push r12 */
        *(--rsp) = 0;   /* push r13 */
        *(--rsp) = 0;   /* push r14 */
        *(--rsp) = 0;   /* push r15 */
    #elif defined(IG_COROUTINE_X86_64_WINDOWS)
        *(--rsp) = (void*)(uintptr_t)IgCoroutine__finish_current;
        *(--rsp) = (void*)(uintptr_t)func;
        *(--rsp) = arg; /* push rcx */
        *(--rsp) = 0;   /* push rbx */
        *(--rsp) = 0;   /* push rbp */
        *(--rsp) = 0;   /* push rdi */
        *(--rsp) = 0;   /* push rsi */
        *(--rsp) = 0;   /* push r12 */
        *(--rsp) = 0;   /* push r13 */
        *(--rsp) = 0;   /* push r14 */
        *(--rsp) = 0;   /* push r15 */
    #else 
        #error "this platform is not supported yet"
    #endif 
    IgCoroutine__contexts.contexts[id].rsp = rsp;

    IgCoroutineIndices__append(&IgCoroutine__active, id);
    
    return id;
}

int IgCoroutine_id(void) {
    return IgCoroutine__active.indices[IgCoroutine__current];
}

int IgCoroutine_active_count(void) {
    return (int)IgCoroutine__active.size;
}

int IgCoroutine_sleeping_count(void) {
    return (int)IgCoroutine__sleeping.size;
}

void IgCoroutine_suspend(int id) {
    size_t i;
    
    for (i = 0; i < IgCoroutine__active.size; i++) {
        if (IgCoroutine__active.indices[i] == id) {
            IgCoroutineIndices__pop(&IgCoroutine__active, i);
            IgCoroutineIndices__append(&IgCoroutine__sleeping, id);
            return;
        }
    }
}

void IgCoroutine_resume(int id) {
    size_t i;
    for (i = 0; i < IgCoroutine__sleeping.size; i++) {
        if (IgCoroutine__sleeping.indices[i] == id) {
            IgCoroutineIndices__pop(&IgCoroutine__sleeping, i);
            IgCoroutineIndices__append(&IgCoroutine__active, id);
            return;
        }
    }
}

void IgCoroutine_terminate(int id) {
    size_t i;
    if (id == IgCoroutine_id()) {
        IgCoroutine__finish_current();
        return;
    }
    for (i = 0; i < IgCoroutine__active.size; i++) {
        if (IgCoroutine__active.indices[i] == id) {
            IgCoroutineIndices__pop(&IgCoroutine__active, i);
            IgCoroutineIndices__append(&IgCoroutine__dead, id);
            return;
        }
    }
    for (i = 0; i < IgCoroutine__sleeping.size; i++) {
        if (IgCoroutine__sleeping.indices[i] == id) {
            IgCoroutineIndices__pop(&IgCoroutine__sleeping, i);
            IgCoroutineIndices__append(&IgCoroutine__dead, id);
            return;
        }
    }
}

void IgCoroutine_join(void) {
    while (IgCoroutine_active_count() > 1) IgCoroutine_yield();
}


#ifndef IG_COROUTINE_DISABLE_SCHEDULER
    typedef enum IgCorouineSchedulerTaskType {
        IG_COROUTINE_SCHEDULER_TASK_TYPE_GUARD,
        IG_COROUTINE_SCHEDULER_TASK_TYPE_DEADLINE,
        IG_COROUTINE_SCHEDULER_TASK_TYPE_TIMEOUT
    } IgCorouineSchedulerTaskType;
    
    typedef union IgCorouineSchedulerTaskParam {
        void* guard;
        uint64_t deadline;
        struct {
            IgCoroutineSchedulerTimeoutFn timeoutfn;
            void* arg;
            uint64_t deadline;
        } timeout;
    } IgCorouineSchedulerTaskParam;
    
    typedef struct IgCorouineSchedulerTask {
        IgCorouineSchedulerTaskType type;
        IgCorouineSchedulerGuardFn guard;
        IgCorouineSchedulerTaskParam param;
        int id;
    } IgCorouineSchedulerTask;
    
    typedef struct IgCorouineSchedulerTasks {
        IgCorouineSchedulerTask* tasks;
        size_t size;
        size_t capacity;
    } IgCorouineSchedulerTasks;
    
    static IgCorouineSchedulerTasks IgCoroutineScheduler__tasks = {0};
    
    static uint64_t IgCoroutineScheduler__get_ms(void) {
        #ifdef _WIN32
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            return time / 10000 - 11644473600000LL; /* Convert to Unix time in milliseconds */
        #else
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
        #endif
    }
    
    void IgCoroutineScheduler_join(long int ms_timeout) {
        int i;
        uint64_t now;
        #ifndef _WIN32
            struct timespec ts;
            ts.tv_sec = ms_timeout / 1000;
            ts.tv_nsec = (ms_timeout % 1000) * 1000000L;
        #endif /* _WIN32 */
        
        if (IgCoroutine_active_count() == 0) return;
        
        while ((size_t)IgCoroutine_active_count() + IgCoroutineScheduler__tasks.size > 1) {
            now = IgCoroutineScheduler__get_ms();
            for (i = 0; i < (int)IgCoroutineScheduler__tasks.size;) {
                if (IgCoroutineScheduler__tasks.tasks[i].type == IG_COROUTINE_SCHEDULER_TASK_TYPE_GUARD) {
                    if (IgCoroutineScheduler__tasks.tasks[i].guard(IgCoroutineScheduler__tasks.tasks[i].param.guard)) {
                        IgCoroutine_resume(IgCoroutineScheduler__tasks.tasks[i].id);
                        IgCoroutineScheduler__tasks.tasks[i] = IgCoroutineScheduler__tasks.tasks[--IgCoroutineScheduler__tasks.size];
                        continue;
                    } else {
                        IgCoroutine_suspend(IgCoroutineScheduler__tasks.tasks[i].id);
                    }
                } else if (IgCoroutineScheduler__tasks.tasks[i].type == IG_COROUTINE_SCHEDULER_TASK_TYPE_DEADLINE) {
                    if (IgCoroutineScheduler__tasks.tasks[i].param.deadline <= now) {
                        IgCoroutine_resume(IgCoroutineScheduler__tasks.tasks[i].id);
                        IgCoroutineScheduler__tasks.tasks[i] = IgCoroutineScheduler__tasks.tasks[--IgCoroutineScheduler__tasks.size];
                        continue;
                    } else {
                        IgCoroutine_suspend(IgCoroutineScheduler__tasks.tasks[i].id);
                    }
                } else if (IgCoroutineScheduler__tasks.tasks[i].type == IG_COROUTINE_SCHEDULER_TASK_TYPE_TIMEOUT) {
                    if (IgCoroutineScheduler__tasks.tasks[i].param.timeout.deadline < now) {
                        if (IgCoroutineScheduler__tasks.tasks[i].param.timeout.timeoutfn != NULL) {
                            IgCoroutineScheduler__tasks.tasks[i].param.timeout.timeoutfn(IgCoroutineScheduler__tasks.tasks[i].param.timeout.arg);
                        }
                        IgCoroutine_terminate(IgCoroutineScheduler__tasks.tasks[i].id);
                        IgCoroutineScheduler__tasks.tasks[i] = IgCoroutineScheduler__tasks.tasks[--IgCoroutineScheduler__tasks.size];
                        continue;
                    }
                }
                
                i++;
            }
            
            if (IgCoroutine_active_count() == 1) {
                /* if it is the only true coroutine running then wait for new events to appear */
                #ifdef _WIN32
                    Sleep(ms_timeout);
                #else /* _WIN32 */
                    nanosleep(&ts, NULL);
                #endif /* _WIN32 */
                continue;
            }
            IgCoroutine_yield();
        }
    }
    
    void IgCoroutineScheduler_guard(IgCorouineSchedulerGuardFn fn, void* arg) {
        /* if it can continue right away ignis will not yield the cpu */
        if (fn(arg)) {
            return;
        }
        
        if (IgCoroutineScheduler__tasks.size == IgCoroutineScheduler__tasks.capacity) {
            IgCoroutineScheduler__tasks.capacity = IgCoroutineScheduler__tasks.capacity ? IgCoroutineScheduler__tasks.capacity * 2 : 1;
            IgCoroutineScheduler__tasks.tasks = realloc(IgCoroutineScheduler__tasks.tasks, IgCoroutineScheduler__tasks.capacity * sizeof(*IgCoroutineScheduler__tasks.tasks));
        }
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].guard = fn;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].type = IG_COROUTINE_SCHEDULER_TASK_TYPE_GUARD;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].param.guard = arg;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].id = IgCoroutine_id();
        IgCoroutineScheduler__tasks.size++;
        
        IgCoroutine_yield();
    }
    
    void IgCoroutineScheduler_sleep(unsigned int ms) {
        if (IgCoroutineScheduler__tasks.size == IgCoroutineScheduler__tasks.capacity) {
            IgCoroutineScheduler__tasks.capacity = IgCoroutineScheduler__tasks.capacity ? IgCoroutineScheduler__tasks.capacity * 2 : 1;
            IgCoroutineScheduler__tasks.tasks = realloc(IgCoroutineScheduler__tasks.tasks, IgCoroutineScheduler__tasks.capacity * sizeof(*IgCoroutineScheduler__tasks.tasks));
        }
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].type = IG_COROUTINE_SCHEDULER_TASK_TYPE_DEADLINE;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].param.deadline = IgCoroutineScheduler__get_ms() + (uint64_t)ms;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].id = IgCoroutine_id();
        IgCoroutineScheduler__tasks.size++;
        
        IgCoroutine_yield();
    }
    
    void IgCoroutineScheduler_timeout(IgCoroutineFn func, void* arg, IgCoroutineSchedulerTimeoutFn timeoutfn, void* timeoutarg, unsigned int timeout_ms) {
        if (IgCoroutineScheduler__tasks.size == IgCoroutineScheduler__tasks.capacity) {
            IgCoroutineScheduler__tasks.capacity = IgCoroutineScheduler__tasks.capacity ? IgCoroutineScheduler__tasks.capacity * 2 : 1;
            IgCoroutineScheduler__tasks.tasks = realloc(IgCoroutineScheduler__tasks.tasks, IgCoroutineScheduler__tasks.capacity * sizeof(*IgCoroutineScheduler__tasks.tasks));
        }
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].type = IG_COROUTINE_SCHEDULER_TASK_TYPE_TIMEOUT;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].param.timeout.timeoutfn = timeoutfn;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].param.timeout.arg = timeoutarg;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].param.timeout.deadline = IgCoroutineScheduler__get_ms() + (uint64_t)timeout_ms;
        IgCoroutineScheduler__tasks.tasks[IgCoroutineScheduler__tasks.size].id = IgCoroutine_start(func, arg);
        IgCoroutineScheduler__tasks.size++;
    }
#endif /* IG_COROUTINE_DISABLE_SCHEDULER */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IG_COROUTINE_IMPLEMENTATION */
