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
 
#ifndef IGNIS__THREADING_H
#define IGNIS__THREADING_H

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#endif /* __clang__ */

#include <stdlib.h>

#ifndef IG_THREADING_API
#define IG_THREADING_API
#endif /* IG_THREADING_API */

#ifndef IG_THREADING_MALLOC
#define IG_THREADING_MALLOC(size) malloc(size)
#define IG_THREADING_FREE(ptr) free(ptr)
#endif /* IG_THREADING_MALLOC */
#ifndef IG_THREADING_FREE
#error "IG_THREADING_FREE must be defined when IG_THREADING_MALLOC is defined"
#endif /* IG_THREADING_FREE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct IgThread IgThread;
typedef struct IgMutex IgMutex;
typedef struct IgSemaphore IgSemaphore;

typedef struct IgThreadCreateInfo {
    size_t stack_size;
} IgThreadCreateInfo;

typedef void(*IgThreadFunc)(void*);

IG_THREADING_API IgThread* IgThread_create(IgThreadFunc func, void* arg, IgThreadCreateInfo* create_info);
IG_THREADING_API void IgThread_destroy(IgThread* thread);
IG_THREADING_API int IgThread_join(IgThread* thread);
IG_THREADING_API int IgThread_is_alive(IgThread* thread);

IG_THREADING_API IgMutex* IgMutex_create(void);
IG_THREADING_API void IgMutex_destroy(IgMutex* mutex);
IG_THREADING_API void IgMutex_lock(IgMutex* mutex);
IG_THREADING_API void IgMutex_unlock(IgMutex* mutex);
IG_THREADING_API int IgMutex_trylock(IgMutex* mutex);
IG_THREADING_API int IgMutex_is_locked(IgMutex* mutex);

IG_THREADING_API IgSemaphore* IgSemaphore_create(unsigned int initial_count);
IG_THREADING_API void IgSemaphore_destroy(IgSemaphore* semaphore);
IG_THREADING_API unsigned int IgSemaphore_get_count(IgSemaphore* semaphore);
IG_THREADING_API void IgSemaphore_wait(IgSemaphore* semaphore);
IG_THREADING_API int IgSemaphore_trywait(IgSemaphore* semaphore);
IG_THREADING_API void IgSemaphore_post(IgSemaphore* semaphore);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IGNIS__THREADING_H */

#ifdef IG_PROCESS_IMPLEMENTATION

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#pragma clang diagnostic ignored "-Wpadded"
#endif /* __clang__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
#else /* _WIN32 */
    #include <semaphore.h>
    #include <pthread.h>
    #include <signal.h>
    #include <errno.h>
#endif /* _WIN32 */

#ifdef _WIN32
#define IG_THREADING_INTERNAL_CALL(func) func##_win32
#else /* _WIN32 */
#define IG_THREADING_INTERNAL_CALL(func) func##_posix
#endif /* _WIN32 */

struct IgThread {
    IgThreadFunc func;
    void* arg;
    int was_joined;
    
    #ifdef _WIN32
        HANDLE handle;
    #else /* _WIN32 */
        pthread_t handle;
    #endif /* _WIN32 */
};

struct IgMutex {
    #ifdef _WIN32
        HANDLE handle;
    #else /* _WIN32 */
        pthread_mutex_t handle;
    #endif /* _WIN32 */
};

struct IgSemaphore {
    #ifdef _WIN32
        unsigned int count;
        HANDLE handle;
    #else /* _WIN32 */
        sem_t handle;
    #endif /* _WIN32 */
};

#ifdef _WIN32

static int IgThread_create_win32(IgThread* thread, IgThreadCreateInfo* create_info) {
    SIZE_T stack_size = create_info ? create_info->stack_size : 0;
    unsigned (__stdcall* func)(void*) = (unsigned (__stdcall *)(void*))(void*)thread->func;
    
    if (0 < stack_size && stack_size < 65536) {
        stack_size = 65536;
    }

    thread->handle = (HANDLE)_beginthreadex(
        NULL,                                         /* Security attributes */
        stack_size,                                   /* Stack size (0 = default) */
        func,  /* Thread function */
        thread->arg,                                  /* Argument */
        STACK_SIZE_PARAM_IS_A_RESERVATION,            /* Stack size parameter is reservation */
        NULL                                          /* Thread ID (we don't need it) */
    );

    if (thread->handle == NULL) return 0;

    thread->was_joined = 0;
    return 1;
}

static void IgThread_destroy_win32(IgThread* thread) {
    if (!thread->was_joined) {
        IgThread_join(thread);
    }
    
    CloseHandle(thread->handle);
}

static int IgThread_join_win32(IgThread* thread) {
    if (thread->was_joined) return 1;

    if (WaitForSingleObject(thread->handle, INFINITE) != WAIT_OBJECT_0) {
        return 0;
    }

    thread->was_joined = 1;
    return 1;
}

static int IgThread_is_alive_win32(IgThread* thread) {
    DWORD exit_code;
    if (!GetExitCodeThread(thread->handle, &exit_code)) {
        return 0;
    }

    return (exit_code == STILL_ACTIVE) ? 1 : 0;
}

static int IgMutex_create_win32(IgMutex* mutex) {
    mutex->handle = CreateMutex(NULL, FALSE, NULL);
    return (mutex->handle != NULL) ? 1 : 0;
}

static void IgMutex_destroy_win32(IgMutex* mutex) {
    CloseHandle(mutex->handle);
    mutex->handle = NULL;
}

static void IgMutex_lock_win32(IgMutex* mutex) {
    WaitForSingleObject(mutex->handle, INFINITE);
}

static void IgMutex_unlock_win32(IgMutex* mutex) {
    ReleaseMutex(mutex->handle);
}

static int IgMutex_trylock_win32(IgMutex* mutex) {
    DWORD result = WaitForSingleObject(mutex->handle, 0);
    return (result == WAIT_OBJECT_0) ? 1 : 0;
}

static int IgMutex_is_locked_win32(IgMutex* mutex) {
    DWORD result = WaitForSingleObject(mutex->handle, 0);
    
    if (result == WAIT_OBJECT_0) {
        ReleaseMutex(mutex->handle);
        return 0;
    }
    return 1;
}

static int IgSemaphore_create_win32(IgSemaphore* semaphore, unsigned int initial_count) {
    semaphore->handle = CreateSemaphore(NULL, initial_count, LONG_MAX, NULL);
    semaphore->count = initial_count;
    return (semaphore->handle != NULL) ? 1 : 0;
}

static void IgSemaphore_destroy_win32(IgSemaphore* semaphore) {
    CloseHandle(semaphore->handle);
}

static unsigned int IgSemaphore_get_count_win32(IgSemaphore* semaphore) {
    return semaphore->count;
}

static void IgSemaphore_wait_win32(IgSemaphore* semaphore) {
    WaitForSingleObject(semaphore->handle, INFINITE);
    semaphore->count--;
}

static int IgSemaphore_trywait_win32(IgSemaphore* semaphore) {
    DWORD result = WaitForSingleObject(semaphore->handle, 0);
    if (result == WAIT_OBJECT_0) {
        semaphore->count--;
        return 1;
    }
    return 0;
}

static void IgSemaphore_post_win32(IgSemaphore* semaphore) {
    ReleaseSemaphore(semaphore->handle, 1, (LPLONG)&semaphore->count);
    semaphore->count++;
}

#else /* _WIN32 */

static int IgThread_create_posix(IgThread* thread, IgThreadCreateInfo* create_info) {
    pthread_attr_t attr;
    
    if (pthread_attr_init(&attr) != 0) return 0;
    
    if (create_info) {
        if (create_info->stack_size != 0) {
            if (pthread_attr_setstacksize(&attr, create_info->stack_size < PTHREAD_STACK_MIN ? PTHREAD_STACK_MIN : create_info->stack_size) != 0) {
                pthread_attr_destroy(&attr);
                return 0;
            }
        }
    }
    
    if (pthread_create(&thread->handle, &attr, (void *(*)(void *))(void*)thread->func, thread->arg) != 0) {
        pthread_attr_destroy(&attr);
        return 0;
    }
    
    pthread_attr_destroy(&attr);
    return 1;
}

static void IgThread_destroy_posix(IgThread* thread) {
    IgThread_join(thread);
}

static int IgThread_join_posix(IgThread* thread) {
    if (!thread) return -1;
    return pthread_join(thread->handle, NULL) == 0;
}

static int IgThread_is_alive_posix(IgThread* thread) {
    int rc = pthread_kill(thread->handle, 0);
    
    switch (rc) {
        case 0:
            return 1;
            
        case ESRCH:
            return 0;
            
        default:
            return 0;
    }
}

static int IgMutex_create_posix(IgMutex* mutex) {
    return pthread_mutex_init(&mutex->handle, NULL) == 0;
}

static void IgMutex_destroy_posix(IgMutex* mutex) {
    pthread_mutex_destroy(&mutex->handle);
}

static void IgMutex_lock_posix(IgMutex* mutex) {
    pthread_mutex_lock(&mutex->handle);
}

static void IgMutex_unlock_posix(IgMutex* mutex) {
    pthread_mutex_unlock(&mutex->handle);
}

static int IgMutex_trylock_posix(IgMutex* mutex) {
    return pthread_mutex_trylock(&mutex->handle) == 0;
}

static int IgMutex_is_locked_posix(IgMutex* mutex) {
    int rc = pthread_mutex_trylock(&mutex->handle);
    if (rc == EBUSY) return 1;
    if (rc == 0) pthread_mutex_unlock(&mutex->handle);
    return 0;
}

static int IgSemaphore_create_posix(IgSemaphore* semaphore, unsigned int initial_count) {
    return sem_init(&semaphore->handle, 1, initial_count) == 0;
}

static void IgSemaphore_destroy_posix(IgSemaphore* semaphore) {
    sem_destroy(&semaphore->handle);
}

static unsigned int IgSemaphore_get_count_posix(IgSemaphore* semaphore) {
    int count;
    sem_getvalue(&semaphore->handle, &count);
    return (unsigned int)(count <= 0 ? 0 : count);
}

static void IgSemaphore_wait_posix(IgSemaphore* semaphore) {
    sem_wait(&semaphore->handle);
}

static int IgSemaphore_trywait_posix(IgSemaphore* semaphore) {
    return sem_trywait(&semaphore->handle) == 0;
}

static void IgSemaphore_post_posix(IgSemaphore* semaphore) {
    sem_post(&semaphore->handle);
}

#endif /* _WIN32 */

IG_THREADING_API IgThread* IgThread_create(IgThreadFunc func, void* arg, IgThreadCreateInfo* create_info) {
    IgThread* thread = IG_THREADING_MALLOC(sizeof(*thread));
    if (!thread) {
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));
    thread->func = func;
    thread->arg = arg;
    
    if (!IG_THREADING_INTERNAL_CALL(IgThread_create)(thread, create_info)) {
        IG_THREADING_FREE(thread);
        return NULL;
    }
    
    return thread;
}

IG_THREADING_API void IgThread_destroy(IgThread* thread) {
    IG_THREADING_INTERNAL_CALL(IgThread_destroy)(thread);
    IG_THREADING_FREE(thread);
}

IG_THREADING_API int IgThread_join(IgThread* thread) {
    if (!thread) return 1;
    if (thread->was_joined) return 1; 
    if (IG_THREADING_INTERNAL_CALL(IgThread_join)(thread)) {
        thread->was_joined = 1;
        return 1;
    }
    return 0;
}

IG_THREADING_API int IgThread_is_alive(IgThread* thread) {
    if (!thread) return 0;
    
    return IG_THREADING_INTERNAL_CALL(IgThread_is_alive)(thread);
}

IG_THREADING_API IgMutex* IgMutex_create(void) {
    IgMutex* mutex = IG_THREADING_MALLOC(sizeof(*mutex));
    
    if (!mutex) return NULL;
    memset(mutex, 0, sizeof(*mutex));
    
    if (!IG_THREADING_INTERNAL_CALL(IgMutex_create)(mutex)) {
        IG_THREADING_FREE(mutex);
        return NULL;
    }
    
    return mutex;
}

IG_THREADING_API void IgMutex_destroy(IgMutex* mutex) {
    IG_THREADING_INTERNAL_CALL(IgMutex_destroy)(mutex);
}

IG_THREADING_API void IgMutex_lock(IgMutex* mutex) {
    IG_THREADING_INTERNAL_CALL(IgMutex_lock)(mutex);
}

IG_THREADING_API void IgMutex_unlock(IgMutex* mutex) {
    IG_THREADING_INTERNAL_CALL(IgMutex_unlock)(mutex);
}

IG_THREADING_API int IgMutex_trylock(IgMutex* mutex) {
    return IG_THREADING_INTERNAL_CALL(IgMutex_trylock)(mutex);
}

IG_THREADING_API int IgMutex_is_locked(IgMutex* mutex) {
    return IG_THREADING_INTERNAL_CALL(IgMutex_is_locked)(mutex);
}

IG_THREADING_API IgSemaphore* IgSemaphore_create(unsigned int initial_count) {
    IgSemaphore* semaphore = IG_THREADING_MALLOC(sizeof(*semaphore));
    
    if (!semaphore) return NULL;
    memset(semaphore, 0, sizeof(*semaphore));
    
    if (!IG_THREADING_INTERNAL_CALL(IgSemaphore_create)(semaphore, initial_count)) {
        IG_THREADING_FREE(semaphore);
        return NULL;
    }
    
    return semaphore;
}

IG_THREADING_API void IgSemaphore_destroy(IgSemaphore* semaphore) {
    IG_THREADING_INTERNAL_CALL(IgSemaphore_destroy)(semaphore);
}

IG_THREADING_API unsigned int IgSemaphore_get_count(IgSemaphore* semaphore) {
    return IG_THREADING_INTERNAL_CALL(IgSemaphore_get_count)(semaphore);
}

IG_THREADING_API void IgSemaphore_wait(IgSemaphore* semaphore) {
    IG_THREADING_INTERNAL_CALL(IgSemaphore_wait)(semaphore);
}

IG_THREADING_API int IgSemaphore_trywait(IgSemaphore* semaphore) {
    return IG_THREADING_INTERNAL_CALL(IgSemaphore_trywait)(semaphore);
}

IG_THREADING_API void IgSemaphore_post(IgSemaphore* semaphore) {
    IG_THREADING_INTERNAL_CALL(IgSemaphore_post)(semaphore);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IG_PROCESS_IMPLEMENTATION */
