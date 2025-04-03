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

#ifndef IGNIS__PROCESS_H
#define IGNIS__PROCESS_H

#ifndef IG_PROCESS_API
#define IG_PROCESS_API
#endif /* IG_PROCESS_API */

#ifndef IG_PROCESS_MALLOC
#define IG_PROCESS_MALLOC(sz) malloc(sz)
#define IG_PROCESS_FREE(p) free(p)
#elif !defined(IG_PROCESS_FREE)
#error "IG_PROCESS_FREE must be defined if IG_PROCESS_MALLOC is defined"
#else /* IG_PROCESS_MALLOC */
#ifndef IG_PROCESS_FREE
#errror "IG_PROCESS_FREE must be defined if IG_PROCESS_MALLOC is defined"
#endif
#endif /* IG_PROCESS_MALLOC */

#include <stdio.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#endif /* __clang__ */

typedef struct IgProcess IgProcess;

/* if in/out/error are NULL or use_parent_streams is 1 then you cant read/write to the streams */
typedef struct IgProcessCreateInfo {
    char* const* argv; /* argv[argc] == NULL */
    const char* cwd; /* optional new cwd */
    int use_parent_streams; /* if this is 1 the reset of the options will be ignored */
    int redirect_to_files; /* if this is 1 it will use the in/out/[error] handles */
    int combine_stdout_stderr; /* if this is 1 `error` will be ignored, this option is ignored when redirect_to_files is 1 */
    /* they all must be NULL or valid FILE* except when combine_stdout_stderr is 1 then `error` is ignored */
    FILE* in;
    FILE* out;
    FILE* error;
} IgProcessCreateInfo;

IG_PROCESS_API IgProcess* IgProcess_create(IgProcessCreateInfo* create_info);
IG_PROCESS_API void IgProcess_destroy(IgProcess* process);
IG_PROCESS_API int IgProcess_wait_for_completion(IgProcess* process, int* returncode);
/* returncode will be 0 otherwise it will be the return code of the first process that failed */
IG_PROCESS_API int IgProcess_wait_for_completion_many(IgProcess* const* processes, int count, int* returncode);
IG_PROCESS_API int IgProcess_get_returncode(IgProcess* process, int* returncode);
IG_PROCESS_API int IgProcess_is_alive(IgProcess* process, int* alive);
IG_PROCESS_API int IgProcess_terminate(IgProcess* process);

/* return the amount of bytes actually written to buffer, if the function failed it returns -1 */
IG_PROCESS_API int IgProcess_read_stdout(const IgProcess* process, char* buffer, size_t size);
IG_PROCESS_API int IgProcess_read_stderr(const IgProcess* process, char* buffer, size_t size);

/* attemps to read from the handles, on success it returns the amount of bytes written to buffer and -1 on error */
IG_PROCESS_API int IgProcess_try_read_stdout(const IgProcess* process, char* buffer, size_t size);
IG_PROCESS_API int IgProcess_try_read_stderr(const IgProcess* process, char* buffer, size_t size);

IG_PROCESS_API int IgProcess_is_stdout_empty(const IgProcess* process);
IG_PROCESS_API int IgProcess_is_stderr_empty(const IgProcess* process);

/* will also wake up when the process is finished */
IG_PROCESS_API int IgProcess_sleep_until_stdout_is_ready_for_read(const IgProcess* process);
IG_PROCESS_API int IgProcess_sleep_until_stderr_is_ready_for_read(const IgProcess* process);

IG_PROCESS_API FILE* IgProcess_get_stdin_handle(const IgProcess* process);
IG_PROCESS_API FILE* IgProcess_get_stdout_handle(const IgProcess* process);
IG_PROCESS_API FILE* IgProcess_get_stderr_handle(const IgProcess* process);

/* argv must be NULL terminated */
IG_PROCESS_API char* IgProcess_stringify_argv(const char* const* argv);
IG_PROCESS_API void IgProcess_free_buffer(void* buffer);

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IGNIS__PROCESS_H */

#ifdef IG_PROCESS_IMPLEMENTATION

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif /* __clang__ */

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
#else /* _WIN32 */
    #ifdef __linux__
        #ifdef __clang__
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wreserved-macro-identifier"
        #endif /* __clang__ */
        #ifndef __USE_GNU
            #define __USE_GNU
        #endif /* __USE_GNU */
        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif /* __clang__ */
    #endif /* __linux__ */
    #include <sys/wait.h>
    #include <unistd.h>
    #include <spawn.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <poll.h>
#endif /* _WIN32 */
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define IG_INTERNAL_CALL(funcname) funcname##_win32
#else /* _WIN32 */
#define IG_INTERNAL_CALL(funcname) funcname##_posix
#endif /* _WIN32 */

#ifndef IG_PROCESS_PIPE_CAPACITY_LINUX
#define IG_PROCESS_PIPE_CAPACITY_LINUX (1*1024*1024)
#endif /* IG_PROCESS_PIPE_CAPACITY_LINUX */

struct IgProcess {
    FILE* stdin_file;
    FILE* stdout_file;
    FILE* stderr_file;
    
    int was_process_completed;
    int returncode;
    
    #ifdef _WIN32
      void* process_handle;
      void* stdin_handle;
      void* event_output_handle;
      void* event_error_handle;
    #else /* _WIN32 */
        pid_t pid;
    #endif /* _WIN32 */
};

#ifdef _WIN32

#define IG_PROCESS_NAMED_PIPE_NAME_SIZE_WIN32 58
static void IgProcess_construct_pipe_name_win32(char* buffer, unsigned int value1, unsigned int value2, unsigned int value3) {
    const char prefix[] = "\\\\.\\pipe\\IgProcess__named_pipe.";
    const char hexdigits[] = "0123456789abcdef";
    memcpy(buffer, prefix, 31);
    
    buffer[31] = hexdigits[(value1 >> 28) & 0xF];
    buffer[32] = hexdigits[(value1 >> 24) & 0xF];
    buffer[33] = hexdigits[(value1 >> 20) & 0xF];
    buffer[34] = hexdigits[(value1 >> 16) & 0xF];
    buffer[35] = hexdigits[(value1 >> 12) & 0xF];
    buffer[36] = hexdigits[(value1 >> 8) & 0xF];
    buffer[37] = hexdigits[(value1 >> 4) & 0xF];
    buffer[38] = hexdigits[value1 & 0xF];
    buffer[39] = '.';
    
    buffer[40] = hexdigits[(value2 >> 28) & 0xF];
    buffer[41] = hexdigits[(value2 >> 24) & 0xF];
    buffer[42] = hexdigits[(value2 >> 20) & 0xF];
    buffer[43] = hexdigits[(value2 >> 16) & 0xF];
    buffer[44] = hexdigits[(value2 >> 12) & 0xF];
    buffer[45] = hexdigits[(value2 >> 8) & 0xF];
    buffer[46] = hexdigits[(value2 >> 4) & 0xF];
    buffer[47] = hexdigits[value2 & 0xF];
    buffer[48] = '.';
    
    buffer[49] = hexdigits[(value3 >> 28) & 0xF];
    buffer[50] = hexdigits[(value3 >> 24) & 0xF];
    buffer[51] = hexdigits[(value3 >> 20) & 0xF];
    buffer[52] = hexdigits[(value3 >> 16) & 0xF];
    buffer[53] = hexdigits[(value3 >> 12) & 0xF];
    buffer[54] = hexdigits[(value3 >> 8) & 0xF];
    buffer[55] = hexdigits[(value3 >> 4) & 0xF];
    buffer[56] = hexdigits[value3 & 0xF];
    buffer[57] = '\0';
}

static int IgProcess_create_named_pipe_helper_win32(void **rd, void **wr) {
    SECURITY_ATTRIBUTES saAttr = {sizeof(saAttr), NULL, 1};
    char name[IG_PROCESS_NAMED_PIPE_NAME_SIZE_WIN32];
    /* @TODO(IgProcess_win32): thread local */
    static long index = 0;
    const long unique = index++;
    
    IgProcess_construct_pipe_name_win32(name, GetCurrentProcessId(), GetCurrentThreadId(), unique);
    
    *rd = CreateNamedPipeA(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, 
                           PIPE_TYPE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, &saAttr);
    
    if (*rd == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    *wr = CreateFileA(name, GENERIC_WRITE, 0, &saAttr, 
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (*wr == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    return 1;
}

static int IgProcess_create_win32(IgProcess* process, IgProcessCreateInfo* create_info) {
    int fd;
    void *rd, *wr;
    char *stringified_argv;
    PROCESS_INFORMATION processInfo;
    SECURITY_ATTRIBUTES saAttr = {sizeof(saAttr), NULL, 1};
    char *used_environment = "\0\0";
    STARTUPINFOA start_info;
  
    ZeroMemory(&processInfo, sizeof(processInfo));
    
    start_info.cb = sizeof(start_info);
    start_info.lpReserved = NULL;
    start_info.lpDesktop = NULL;
    start_info.lpTitle = NULL;
    start_info.dwX = 0;
    start_info.dwY = 0;
    start_info.dwXSize = 0;
    start_info.dwYSize = 0;
    start_info.dwXCountChars = 0;
    start_info.dwYCountChars = 0;
    start_info.dwFillAttribute = 0;
    start_info.dwFlags =  STARTF_USESTDHANDLES;
    start_info.wShowWindow = 0;
    start_info.cbReserved2 = 0;
    start_info.lpReserved2 = NULL;
    start_info.hStdInput = NULL;
    start_info.hStdOutput = NULL;
    start_info.hStdError = NULL;
  
    if (create_info->use_parent_streams) {
        start_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        start_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        start_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);  
    } else if (create_info->redirect_to_files) {
        start_info.hStdInput = (HANDLE)_get_osfhandle(_fileno(create_info->in));
        start_info.hStdOutput = (HANDLE)_get_osfhandle(_fileno(create_info->out));
        start_info.hStdError = (HANDLE)_get_osfhandle(_fileno(create_info->error));  
    } else {
        if (!CreatePipe(&rd, &wr, &saAttr, 0)) {
            return 0;
        }
    
        if (!SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0)) {
            return 0;
        }
    
        fd = _open_osfhandle((intptr_t)wr, 0);
    
        if (fd != -1) {
            process->stdin_file = _fdopen(fd, "wb");
            
            if (process->stdin_file == NULL) {
                return 0;
            }
        }
    
        start_info.hStdInput = rd;
    
        if (!IgProcess_create_named_pipe_helper_win32(&rd, &wr)) {
            return 0;
        }
    
        if (!SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)) {
            return 0;
        }
    
        fd = _open_osfhandle((intptr_t)rd, 0);
    
        if (fd != -1) {
            process->stdout_file = _fdopen(fd, "rb");
            
            if (process->stdout_file == NULL) {
                return 0;
            }
        }
    
        start_info.hStdOutput = wr;
    
        if (create_info->combine_stdout_stderr) {
            process->stderr_file = process->stdout_file;
            start_info.hStdError = start_info.hStdOutput;
        } else {
            if (!IgProcess_create_named_pipe_helper_win32(&rd, &wr)) {
                return 0;
            }
            
            if (!SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)) {
                return 0;
            }
            
            fd = _open_osfhandle((intptr_t)rd, 0);
            
            if (fd != -1) {
                process->stderr_file = _fdopen(fd, "rb");
                
                if (process->stderr_file == NULL) {
                    return 0;
                }
            }
            start_info.hStdError = wr;
        }

        process->event_output_handle = CreateEventA(&saAttr, 1, 1, NULL);
        process->event_error_handle = CreateEventA(&saAttr, 1, 1, NULL);
    }
    
    stringified_argv = IgProcess_stringify_argv((const char* const*)create_info->argv);
  
    /* @TODO(IgProcess_win32): investigate CREATE_NO_WINDOW */
    if (!CreateProcessA(NULL, stringified_argv, NULL, NULL, TRUE, 
                        (create_info->use_parent_streams || create_info->redirect_to_files) ? 0 : CREATE_NO_WINDOW, 
                        used_environment, create_info->cwd, &start_info, &processInfo)) {
        IgProcess_free_buffer(stringified_argv);
      return 0;
    }
    IgProcess_free_buffer(stringified_argv);
    CloseHandle(processInfo.hThread);
    process->process_handle = processInfo.hProcess;
  
    if (!create_info->use_parent_streams && !create_info->redirect_to_files) {
        process->stdin_handle = start_info.hStdInput;
        if (start_info.hStdOutput != NULL) {
            CloseHandle(start_info.hStdOutput);
            
            if (start_info.hStdError != start_info.hStdOutput) {
                CloseHandle(start_info.hStdError);
            }
        }
    }
  
    return 1;
}

static void IgProcess_destroy_win32(IgProcess* process) {
    if (process->stdin_file) {
        fclose(process->stdin_file);
    }
    if (process->stdout_file) {
        fclose(process->stdout_file);
    }
    if (process->stderr_file && process->stderr_file != process->stdout_file) {
        fclose(process->stderr_file);
    }
    
    CloseHandle(process->process_handle);
    if(process->stdin_handle) CloseHandle(process->stdin_handle);
    if(process->event_output_handle) CloseHandle(process->event_output_handle);
    if(process->event_error_handle) CloseHandle(process->event_error_handle);
}

static int IgProcess_wait_for_completion_win32(IgProcess* process, int* returncode) {
    DWORD result = WaitForSingleObject(process->process_handle, INFINITE);

    if (result == WAIT_FAILED) {
        return 0;
    }
    
    process->was_process_completed = 1;

    if (!GetExitCodeProcess(process->process_handle, (LPDWORD)&process->returncode)) {
        return 0;
    }
    if (returncode) *returncode = process->returncode;

    return 1;
}

static int IgProcess_is_alive_win32(IgProcess* process, int* alive) {
    if (WaitForSingleObject(process->process_handle, 0) == WAIT_TIMEOUT) {
        return 0;        
    }
    process->was_process_completed = 1;
    *alive = 0;
    return 1;
}

static int IgProcess_terminate_win32(IgProcess* process) {
    if (!TerminateProcess(process->process_handle, 1)) {
        if (GetLastError() == ERROR_INVALID_HANDLE) {
            return 1;
        }
        return 0;
    }
    process->was_process_completed = 1;
    return 1;
}

static int IgProcess_read_stdout_win32(const IgProcess* process, char* buffer, size_t size) {
    void *handle;
    unsigned long bytes_read = 0;
    unsigned long error;
    OVERLAPPED overlapped = {0, 0, {{0, 0}}, NULL};
    overlapped.hEvent = process->event_output_handle;
  
    handle =  (void*)_get_osfhandle(_fileno(process->stdout_file));
  
    if (!ReadFile(handle, buffer, size, &bytes_read, &overlapped)) {
        error = GetLastError();
    
        if (error == ERROR_IO_PENDING) {
            if (!GetOverlappedResult(handle, &overlapped, &bytes_read, 1)) {
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                error = GetLastError();
        
                if ((error != errorIoIncomplete) && (error != errorHandleEOF)) {
                    return 0;
                }
            }
        }
    }
    return bytes_read;
}

static int IgProcess_read_stderr_win32(const IgProcess* process, char* buffer, size_t size) {
    void *handle;
    unsigned long bytes_read = 0;
    unsigned long error;
    OVERLAPPED overlapped = {0, 0, {{0, 0}}, NULL};
    overlapped.hEvent = process->event_error_handle;
    
    handle =  (void*)_get_osfhandle(_fileno(process->stderr_file));
    
    if (!ReadFile(handle, buffer, size, &bytes_read, &overlapped)) {
        error = GetLastError();
    
        if (error == ERROR_IO_PENDING) {
            if (!GetOverlappedResult(handle, &overlapped, &bytes_read, 1)) {
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                error = GetLastError();
        
                if ((error != errorIoIncomplete) && (error != errorHandleEOF)) {
                    return 0;
                }
            }
        }
    }
    return bytes_read;
}

static int IgProcess_try_read_stdout_win32(const IgProcess* process, char* buffer, size_t size) {
    void* handle;
    unsigned long bytes_read = 0;
    unsigned long error;
    OVERLAPPED overlapped = {0, 0, {{0, 0}}, NULL};
    overlapped.hEvent = process->event_output_handle;
  
    handle = (void*)_get_osfhandle(_fileno(process->stdout_file));
  
    if (!ReadFile(handle, buffer, size, &bytes_read, &overlapped)) {
        error = GetLastError();
    
        if (error == ERROR_IO_PENDING) {
            if (!GetOverlappedResult(handle, &overlapped, &bytes_read, FALSE)) {
                error = GetLastError();
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                
                if (error == errorIoIncomplete) {
                    CancelIo(handle);
                    return 0;
                } else if (error != errorHandleEOF) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
    
    return (int)bytes_read;
}

static int IgProcess_try_read_stderr_win32(const IgProcess* process, char* buffer, size_t size) {
    void* handle;
    unsigned long bytes_read = 0;
    unsigned long error;
    OVERLAPPED overlapped = {0, 0, {{0, 0}}, NULL};
    overlapped.hEvent = process->event_error_handle;
    
    handle = (void*)_get_osfhandle(_fileno(process->stderr_file));
    
    if (!ReadFile(handle, buffer, size, &bytes_read, &overlapped)) {
        error = GetLastError();
    
        if (error == ERROR_IO_PENDING) {
            if (!GetOverlappedResult(handle, &overlapped, &bytes_read, FALSE)) {
                error = GetLastError();
                const unsigned long errorIoIncomplete = 996;
                const unsigned long errorHandleEOF = 38;
                
                if (error == errorIoIncomplete) {
                    CancelIo(handle);
                    return 0;
                } else if (error != errorHandleEOF) {
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
    
    return (int)bytes_read;
}

static int IgProcess_is_stdout_empty_win32(const IgProcess* process) {
    void* handle = (void*)_get_osfhandle(_fileno(process->stdout_file));
    DWORD bytes_available = 0;

    if (!PeekNamedPipe(handle, NULL, 0, NULL, &bytes_available, NULL)) {
        DWORD error = GetLastError();
        
        if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
            return 1;
        }
        return -1;
    }

    return (bytes_available == 0) ? 1 : 0;
}

static int IgProcess_is_stderr_empty_win32(const IgProcess* process) {
    void* handle = (void*)_get_osfhandle(_fileno(process->stderr_file));
    DWORD bytes_available = 0;

    if (!PeekNamedPipe(handle, NULL, 0, NULL, &bytes_available, NULL)) {
        DWORD error = GetLastError();
        
        if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA) {
            return 1;
        }
        return -1;
    }

    return (bytes_available == 0) ? 1 : 0;
}

static int IgProcess_sleep_until_stdout_is_ready_for_read_win32(const IgProcess* process) {
    HANDLE handles[2] = {
        process->event_output_handle,  /* Signaled when I/O completes */
        process->process_handle        /* Signaled when process terminates */
    };

    /* Wait for either data available or process termination */
    DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

    switch (result) {
        case WAIT_OBJECT_0:         /* data available */
            return 1;               /* Success - ready to read */
            case WAIT_OBJECT_0 + 1: /* process terminated */
            return 1;               /* No more data coming */
            case WAIT_FAILED:       /* error */
        default:
            return 0;               /* Error case */
    }
}

static int IgProcess_sleep_until_stderr_is_ready_for_read_win32(const IgProcess* process) {
    HANDLE handles[2] = {
        process->event_error_handle,   /* Signaled when I/O completes */
        process->process_handle        /* Signaled when process terminates */
    };

    /* Wait for either data available or process termination */
    DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

    switch (result) {
        case WAIT_OBJECT_0:         /* data available */
            return 1;               /* Success - ready to read */
            case WAIT_OBJECT_0 + 1: /* process terminated */
            return 1;               /* No more data coming */
            case WAIT_FAILED:       /* error */
        default:
            return 0;               /* Error case */
    }
}

#else /* _WIN32 */

static int IgProcess_is_fd_empty_posix(int fd) {
    int ret;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    ret = poll(&pfd, 1, 0);
    
    if (ret == 1 && (pfd.revents & POLLIN)) {
        return 0;
    }
    return 1;
}

static int IgProcess_create_posix(IgProcess* process, IgProcessCreateInfo* create_info) {
    int stdinfd[2];
    int stdoutfd[2];
    int stderrfd[2];
    int errorfd[2];
    
    if (!create_info->use_parent_streams && !create_info->redirect_to_files) {
        if (pipe(stdinfd) != 0) {
            return 0;
        }
        if (pipe(stdoutfd) != 0) {
            close(stdinfd[0]);
            close(stdinfd[1]);
            return 0;
        }
        if (!create_info->combine_stdout_stderr) {
            if (pipe(stderrfd) != 0) {
                close(stdinfd[0]);
                close(stdinfd[1]);
                close(stdoutfd[0]);
                close(stdoutfd[1]);
                return 0;
            }
        } else {
            stderrfd[0] = -1;
            stderrfd[1] = -1;
        }
        #ifdef __linux__
            fcntl(stdoutfd[0], F_SETPIPE_SZ, IG_PROCESS_PIPE_CAPACITY_LINUX);
            if (!create_info->combine_stdout_stderr) {
                fcntl(stderrfd[0], F_SETPIPE_SZ, IG_PROCESS_PIPE_CAPACITY_LINUX);
            }
        #endif /* __linux__ */
    }
    
    if (pipe(errorfd) != 0) {
        close(stdinfd[0]);
        close(stdinfd[1]);
        close(stdoutfd[0]);
        close(stdoutfd[1]);
        if (!create_info->combine_stdout_stderr) {
            close(stderrfd[0]);
            close(stderrfd[1]);
        }
        return 0;
    }
    
    process->pid = fork();
    if (process->pid < 0) {
        close(stdinfd[0]);
        close(stdinfd[1]);
        close(stdoutfd[0]);
        close(stdoutfd[1]);
        if (!create_info->combine_stdout_stderr) {
            close(stderrfd[0]);
            close(stderrfd[1]);
        }
        close(errorfd[0]);
        close(errorfd[1]);
        return 0;
    }
    if (process->pid == 0) {
        close(errorfd[0]);
        
        if (create_info->cwd != NULL) {
            if (chdir(create_info->cwd) != 0) {
                goto child_exit_code;
            }
        }
        if (!create_info->use_parent_streams) {
            if (create_info->redirect_to_files) {
                if (dup2(fileno(create_info->in), STDIN_FILENO) < 0) {
                    goto child_exit_code;
                }
    
                if (dup2(fileno(create_info->out), STDOUT_FILENO) < 0) {
                    goto child_exit_code;
                }
        
                if (dup2(fileno(create_info->error), STDERR_FILENO) < 0) {
                    goto child_exit_code;
                }
            } else {                
                if (dup2(stdinfd[0], STDIN_FILENO) < 0) {
                    goto child_exit_code;
                }
    
                if (dup2(stdoutfd[1], STDOUT_FILENO) < 0) {
                    goto child_exit_code;
                }
        
                if (create_info->combine_stdout_stderr) {
                    if (dup2(stdoutfd[1], STDERR_FILENO) < 0) {
                        goto child_exit_code;
                    }
                } else {
                    if (dup2(stderrfd[1], STDERR_FILENO) < 0) {
                        goto child_exit_code;
                    }
                }
                close(stdinfd[1]); 
                close(stdoutfd[0]); 
                if (!create_info->combine_stdout_stderr) {
                    close(stderrfd[0]); 
                }
            }
        }
        
        execvp(create_info->argv[0], (char * const*)create_info->argv);
        
        /* not reachable unless the above functions failed */
        child_exit_code:
        write(errorfd[1], &errno, sizeof(errno));
        close(errorfd[1]);
        _exit(127);
    } else {
        close(errorfd[1]);
        if (!IgProcess_is_fd_empty_posix(errorfd[0])) {
            close(stdinfd[0]);
            close(stdinfd[1]);
            close(stdoutfd[0]);
            close(stdoutfd[1]);
            if (!create_info->combine_stdout_stderr) {
                close(stderrfd[0]);
                close(stderrfd[1]);
            }
            close(errorfd[0]);
            close(errorfd[1]);
            return 0;
        }
        close(errorfd[0]);
        
        if (!create_info->use_parent_streams && !create_info->redirect_to_files) {
            close(stdinfd[0]);
            close(stdoutfd[1]);
            if (!create_info->combine_stdout_stderr) {
                close(stderrfd[1]);
            }
            process->stdin_file = fdopen(stdinfd[1], "w");
            process->stdout_file = fdopen(stdoutfd[0], "r");
            if (create_info->combine_stdout_stderr) {
                process->stderr_file = fdopen(stderrfd[0], "r");
            } else {
                process->stderr_file = process->stdout_file;
            }
        }
    }
    
    return 1;
}

static void IgProcess_destroy_posix(const IgProcess* process) {
    if (process->stdin_file) {
        fclose(process->stdin_file);
    }
    if (process->stdout_file) {
        fclose(process->stdout_file);
    }
    if (process->stderr_file && process->stderr_file != process->stdout_file) {
        fclose(process->stderr_file);
    }
}

static int IgProcess_wait_for_completion_posix(IgProcess* process, int* returncode) {
    int wstatus;
    
    if (process->was_process_completed) {
        if (returncode) {
            *returncode = process->returncode;
        }
        return 1;
    }
    
    for (;;) {
        wstatus = 0;
        if (waitpid(process->pid, &wstatus, 0) != process->pid) {
            return 0;
        }
    
        if (WIFEXITED(wstatus)) {
            process->returncode = WEXITSTATUS(wstatus);
            if (returncode) {
                *returncode = process->returncode;
            }
            process->was_process_completed = 1;
            return 1;
        }
    }
}

static int IgProcess_is_alive_posix(IgProcess* process, int* alive) {
    int status;
    int result = waitpid(process->pid, &status, WNOHANG);

    if (result == 0) {
        *alive = 1;
        return 1;
    }
    else if (result == -1) {
        if (errno == ECHILD) {
            process->was_process_completed = 1;
            *alive = 0;
            return 1;
        }
        return 0;
    }
    else {
        process->was_process_completed = 1;
        *alive = 0;
        return 1;
    }
}

static int IgProcess_terminate_posix(IgProcess* process) {
    int result = kill(process->pid, -9);
    process->was_process_completed = result == 0;
    return result == 0;
}

static int IgProcess_read_stdout_posix(const IgProcess* process, char* buffer, size_t size) {
    const int fd = fileno(process->stdout_file);
    const ssize_t bytes_read = read(fd, buffer, size);
    
    if (bytes_read < 0) {
        return 0;
    }
    
    return (int)bytes_read;
}

static int IgProcess_read_stderr_posix(const IgProcess* process, char* buffer, size_t size) {
    const int fd = fileno(process->stderr_file);
    const ssize_t bytes_read = read(fd, buffer, size);
  
    if (bytes_read < 0) {
      return 0;
    }
  
    return (int)bytes_read;
}

static int IgProcess_try_read_stdout_posix(const IgProcess* process, char* buffer, size_t size) {
    int fd = fileno(process->stdout_file);
    ssize_t bytes_read;
    int ready;
    struct pollfd pfd;
    if (fd == -1) return -1;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    ready = poll(&pfd, 1, 0);
    if (ready == -1) return -1;
    if (ready == 0) return 0;

    bytes_read = read(fd, buffer, size);
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    return (int)bytes_read;
}

static int IgProcess_try_read_stderr_posix(const IgProcess* process, char* buffer, size_t size) {
    int fd = fileno(process->stderr_file);
    ssize_t bytes_read;
    int ready;
    struct pollfd pfd;
    if (fd == -1) return -1;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    ready = poll(&pfd, 1, 0);
    if (ready == -1) return -1;
    if (ready == 0) return 0;

    bytes_read = read(fd, buffer, size);
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    return (int)bytes_read;
}

static int IgProcess_is_stdout_empty_posix(const IgProcess* process) {
    return IgProcess_is_fd_empty_posix(fileno(process->stdout_file));
}

static int IgProcess_is_stderr_empty_posix(const IgProcess* process) {
    return IgProcess_is_fd_empty_posix(fileno(process->stderr_file));
}

static int IgProcess_sleep_until_stdout_is_ready_for_read_posix(const IgProcess* process) {
    int fd = fileno(process->stdout_file);
    int ret;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;
    pfd.revents = 0;
   
    ret = poll(&pfd, 1, -1);
    
    if (ret == -1) {
        return 0;
    }

    return 1;
}

static int IgProcess_sleep_until_stderr_is_ready_for_read_posix(const IgProcess* process) {
    int fd = fileno(process->stderr_file);
    int ret;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;
    pfd.revents = 0;
    
    ret = poll(&pfd, 1, -1);
    
    if (ret == -1) {
        return 0;
    }

    return 1;
}

#endif /* _WIN32 */

IG_PROCESS_API IgProcess* IgProcess_create(IgProcessCreateInfo* create_info) {
    IgProcess* process;
    
    process = (IgProcess*)IG_PROCESS_MALLOC(sizeof(*process));
    if (!process) return NULL;
    
    memset(process, 0, sizeof(*process));
    
    if (!IG_INTERNAL_CALL(IgProcess_create)(process, create_info)) {
        IG_PROCESS_FREE(process);
        return NULL;
    }
    
    return process;
}

IG_PROCESS_API void IgProcess_destroy(IgProcess* process) {
    IgProcess_terminate(process);
    
    IG_INTERNAL_CALL(IgProcess_destroy)(process);
    IgProcess_free_buffer(process);
}

IG_PROCESS_API int IgProcess_wait_for_completion(IgProcess* process, int* returncode) {
    if (process->was_process_completed) {
        if (returncode) {
            *returncode = process->returncode;
        }
        return 1;
    }
    if (process->stdin_file) {
        fclose(process->stdin_file);
        process->stdin_file = NULL;
    }
    return IG_INTERNAL_CALL(IgProcess_wait_for_completion)(process, returncode);
}

IG_PROCESS_API int IgProcess_wait_for_completion_many(IgProcess* const* processes, int count, int* returncode) {
    int i, retc;
    int* retcp = returncode;
    
    for (i = 0; i < count; i++) {
        if (!IgProcess_wait_for_completion(processes[i], retcp)) {
            return 0;
        }
        if (*retcp != 0) {
            retcp = &retc;
        }
    }
    return 1;
}

IG_PROCESS_API int IgProcess_get_returncode(IgProcess* process, int* returncode) {
    if (process->was_process_completed) {
        *returncode = process->returncode;
        return 1;
    }
    if (!IgProcess_wait_for_completion(process, returncode)) {
        return 0;
    }
    return 1;
}

IG_PROCESS_API int IgProcess_is_alive(IgProcess* process, int* alive) {
    if (process->was_process_completed) {
        *alive = 0;
        return 1;
    }

    return IG_INTERNAL_CALL(IgProcess_is_alive)(process, alive);
}

IG_PROCESS_API int IgProcess_terminate(IgProcess* process) {
    if (process->was_process_completed) return 1;
    return IG_INTERNAL_CALL(IgProcess_terminate)(process);
}

IG_PROCESS_API int IgProcess_read_stdout(const IgProcess* process, char* buffer, size_t size) {
    if (process->stdout_file == NULL) return -1;
    if (!IG_INTERNAL_CALL(IgProcess_sleep_until_stdout_is_ready_for_read)(process)) return -1;
    return IG_INTERNAL_CALL(IgProcess_read_stdout)(process, buffer, size);
}

IG_PROCESS_API int IgProcess_read_stderr(const IgProcess* process, char* buffer, size_t size) {
    if (process->stderr_file == NULL) return -1;
    if (!IG_INTERNAL_CALL(IgProcess_sleep_until_stderr_is_ready_for_read)(process)) return -1;
    return IG_INTERNAL_CALL(IgProcess_read_stderr)(process, buffer, size);
}

IG_PROCESS_API int IgProcess_try_read_stdout(const IgProcess* process, char* buffer, size_t size) {
    if (process->stdout_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_try_read_stdout)(process, buffer, size);
    
}
IG_PROCESS_API int IgProcess_try_read_stderr(const IgProcess* process, char* buffer, size_t size) {
    if (process->stderr_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_try_read_stderr)(process, buffer, size);
}

IG_PROCESS_API int IgProcess_is_stdout_empty(const IgProcess* process) {
    if (process->stdout_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_is_stdout_empty)(process);
}

IG_PROCESS_API int IgProcess_is_stderr_empty(const IgProcess* process) {
    if (process->stderr_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_is_stderr_empty)(process);
}

IG_PROCESS_API int IgProcess_sleep_until_stdout_is_ready_for_read(const IgProcess* process) {
    if (process->stdout_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_sleep_until_stdout_is_ready_for_read)(process);
}

IG_PROCESS_API int IgProcess_sleep_until_stderr_is_ready_for_read(const IgProcess* process) {
    if (process->stderr_file == NULL) return -1;
    return IG_INTERNAL_CALL(IgProcess_sleep_until_stderr_is_ready_for_read)(process);
}

IG_PROCESS_API FILE* IgProcess_get_stdin_handle(const IgProcess* process) {
    return process->stdin_file;
}

IG_PROCESS_API FILE* IgProcess_get_stdout_handle(const IgProcess* process) {
    return process->stdout_file;
}

IG_PROCESS_API FILE* IgProcess_get_stderr_handle(const IgProcess* process) {
    return process->stderr_file;
}

IG_PROCESS_API char* IgProcess_stringify_argv(const char* const* argv) {
    char* stringified_command_line;
    unsigned int len = 0;
    int need_quoting;
    int i, j;
    for (i = 0; argv[i]; i++) {
        len++;
        
        if (strpbrk(argv[i], "\t\v ") != NULL || argv[i][0] == 0) {
            len += 2;
        }
        
        for (j = 0; '\0' != argv[i][j]; j++) {
            switch (argv[i][j]) {
            case '\\':
                if (argv[i][j + 1] == '"') {
                    len++;
                }
                break;
            case '"':
                len++;
                break;
            default:
                break;
            }
            len++;
        }
    }
    
    stringified_command_line = IG_PROCESS_MALLOC(len);
    
    if (!stringified_command_line) return NULL;
    
    len = 0;
    
    for (i = 0; argv[i]; i++) {
        if (0 != i) {
            stringified_command_line[len++] = ' ';
        }
        
        need_quoting = strpbrk(argv[i], "\t\v ") != NULL || argv[i][0] == 0;
        if (need_quoting) {
            stringified_command_line[len++] = '"';
        }
        
        for (j = 0; '\0' != argv[i][j]; j++) {
            switch (argv[i][j]) {
            case '\\':
                if (argv[i][j + 1] == '"') {
                    stringified_command_line[len++] = '\\';
                }
            break;
            case '"':
                stringified_command_line[len++] = '\\';
                break;
            default:
                break;
            }
            
            stringified_command_line[len++] = argv[i][j];
        }
        if (need_quoting) {
            stringified_command_line[len++] = '"';
        }
    }
    
    stringified_command_line[len] = '\0';
    
    return stringified_command_line;
}

IG_PROCESS_API void IgProcess_free_buffer(void* buffer) {
    IG_PROCESS_FREE(buffer);
}

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IG_PROCESS_IMPLEMENTATION */
