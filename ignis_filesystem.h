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

#ifndef IGNIS__FILESYSTEM_H
#define IGNIS__FILESYSTEM_H

#include <stdio.h>
#ifndef IG_FS_MALLOC
#define IG_FS_MALLOC(size) malloc(size)
#define IG_FS_REALLOC(ptr, old_size, new_size) realloc(ptr, new_size)
#define IG_FS_FREE(ptr) free(ptr)
#else /* IG_FS_MALLOC */
#ifndef IG_FS_REALLOC
#error "IG_FS_REALLOC must be defined when IG_FS_MALLOC is defined"
#endif /* IG_FS_REALLOC */
#ifndef IG_FS_FREE
#error "IG_FS_FREE must be defined when IG_FS_MALLOC is defined"
#endif /* IG_FS_FREE */
#endif /* IG_FS_MALLOC */

#ifndef IG_FS_API
#define IG_FS_API
#endif /* IG_FS_API */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IG_FS_PURE /* requires no OS supports, just string manipulation */
#define IG_FS_OS   /* requires OS support */
#define IG_FS_NULLABLE /* null pointers are allowed */

IG_FS_API char* IgFs_cwd(void) IG_FS_OS;
IG_FS_API char* IgFs_home(void) IG_FS_OS;
IG_FS_API char* IgFs_temp(void) IG_FS_OS;
IG_FS_API int IgFs_exists(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_dir(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_file(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_symlink(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_symlink_target_eq(const char* path, const char* target) IG_FS_OS;
IG_FS_API char* IgFs_get_symlink_target(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_mount(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_block_device(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_char_device(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_socket(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_fifo(const char* path) IG_FS_OS;
IG_FS_API int IgFs_is_absolute(const char* path) IG_FS_PURE;
IG_FS_API int IgFs_is_absolute_posix(const char* path) IG_FS_PURE;
IG_FS_API int IgFs_is_absolute_win32(const char* path) IG_FS_PURE;
IG_FS_API int IgFs_is_relative(const char* root, const char* path) IG_FS_PURE;
IG_FS_API char* IgFs_suffix(const char* path) IG_FS_PURE;
IG_FS_API char** IgFs_suffixes(const char* path, IG_FS_NULLABLE int* suffix_count) IG_FS_PURE;
IG_FS_API char* IgFs_with_suffix(const char* path, const char* suffix) IG_FS_PURE;
IG_FS_API char* IgFs_stem(const char* path) IG_FS_PURE;
IG_FS_API char* IgFs_parent(const char* path) IG_FS_PURE;
IG_FS_API char* IgFs_name(const char* path) IG_FS_PURE;
IG_FS_API char* IgFs_joinpath(const char* pathA, const char* pathB) IG_FS_PURE;
IG_FS_API char** IgFs_listdir(const char* path, IG_FS_NULLABLE int* file_count) IG_FS_OS;
IG_FS_API int IgFs_unlink(const char* path) IG_FS_OS;
IG_FS_API int IgFs_rmdir(const char* path, int remove_contents) IG_FS_OS;
IG_FS_API int IgFs_mkdir(const char* path) IG_FS_OS;
IG_FS_API int IgFs_ensure_parent_exists(const char* path) IG_FS_OS;
IG_FS_API int IgFs_touch(const char* path) IG_FS_OS;
IG_FS_API int IgFs_new_symlink(const char* path, const char* target) IG_FS_OS;
IG_FS_API int IgFs_rename(const char* old_path, const char* new_path) IG_FS_OS;
IG_FS_API char* IgFs_resolve(const char* path) IG_FS_OS;
IG_FS_API FILE* IgFs_open(const char* path, const char* mode) IG_FS_OS;
IG_FS_API char* IgFs_read_text(const char* path, IG_FS_NULLABLE int* file_size) IG_FS_OS;
IG_FS_API unsigned char* IgFs_read_bytes(const char* path, IG_FS_NULLABLE int* byte_count) IG_FS_OS;
IG_FS_API int IgFs_write_text(const char* path, const char* text, int text_size) IG_FS_OS;
IG_FS_API int IgFs_write_bytes(const char* path, const unsigned char* buff, int buff_size) IG_FS_OS;
IG_FS_API int IgFs_copyfile(const char* src_path, const char* dst_path) IG_FS_OS;
IG_FS_API char** IgFs_glob(const char* path, const char* pattern, int match_directories, int* match_count) IG_FS_OS;
IG_FS_API char** IgFs_rglob(const char* path, const char* pattern, int match_directories, int* match_count) IG_FS_OS;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* IGNIS__FILESYSTEM_H */

#ifdef IG_FILESYSTEM_IMPLEMENTATION

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif /* __clang__ */

#ifdef _WIN32
    #include <windows.h>
    #include <shellapi.h>
    #include <shlwapi.h>
    #include <ntdef.h>
    
    #define IG_FS_MAX_PATH MAX_PATH
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <pwd.h>
    #include <dirent.h>
    #include <errno.h>
    #include <limits.h>

    #define IG_FS_MAX_PATH PATH_MAX
#endif
#include <stdlib.h>

#define IG_FS_PRIVATE_DEF static

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32
IG_FS_PRIVATE_DEF char* IgFs__strcat2(const char* str1, const char* str2);
#endif /* _WIN32 */
IG_FS_PRIVATE_DEF int IgFs_strcat2_buf(char* buf, size_t buf_size, const char* str1, const char* str2);
IG_FS_PRIVATE_DEF char* IgFs__strdup(const char* str);
IG_FS_PRIVATE_DEF char* IgFs__strndup(const char* str, size_t n);
IG_FS_PRIVATE_DEF char* IgFs__strncpy(char* dest, const char* src, size_t n);
IG_FS_PRIVATE_DEF int IgFs__is_sep(char c);
IG_FS_PRIVATE_DEF const char* IgFs__last_component_ref(const char* path);
IG_FS_PRIVATE_DEF const char* IgFs__last_slash_ref(const char* path);
IG_FS_PRIVATE_DEF int IgFs__remove_directory_contents(const char* path);
IG_FS_PRIVATE_DEF int IgFs__joinpath_buf(char* buf, size_t buf_size, const char* pathA, const char* pathB);
IG_FS_PRIVATE_DEF int IgFs__parent_buf(char* buf, size_t buf_size, const char* path);

#ifdef __WIN32
IG_FS_PRIVATE_DEF char* IgFs__strcat2(const char* str1, const char* str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char* result = (char*)IG_FS_MALLOC((len1 + len2 + 1) * sizeof(char));

    if (result == NULL) {
        return NULL;
    }

    memcpy(result, str1, len1);
    memcpy(result + len1, str2, len2 + 1);

    return result;
}
#endif /* _WIN32 */

IG_FS_PRIVATE_DEF int IgFs_strcat2_buf(char* buf, size_t buf_size, const char* str1, const char* str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    size_t len = len1 + len2;

    if (len + 1 > buf_size) return 0;
    memcpy(buf, str1, len1);
    memcpy(buf + len1, str2, len2 + 1);

    return 1;
}

IG_FS_PRIVATE_DEF char* IgFs__strdup(const char* str) {
    size_t len = strlen(str);
    char* result = (char*)IG_FS_MALLOC((len + 1) * sizeof(char));

    if (result == NULL) {
        return NULL;
    }

    return memcpy(result, str, len + 1);
}

IG_FS_PRIVATE_DEF char* IgFs__strndup(const char* str, size_t n) {
    char* result = (char*)IG_FS_MALLOC((n + 1) * sizeof(char));
    result[n] = '\0';
    
    if (result == NULL) {
        return NULL;
    }

    return memcpy(result, str, n);
}

IG_FS_PRIVATE_DEF char* IgFs__strncpy(char* dest, const char* src, size_t n) {
    size_t i = 0;
    
    if (dest == NULL || src == NULL) {
        return NULL;
    }

    while (i < n && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }

    while (i < n) {
        dest[i] = '\0';
        i++;
    }

    return dest;
}

IG_FS_PRIVATE_DEF int IgFs__is_sep(char c) {
    return c == '\\' || c == '/';
}

IG_FS_PRIVATE_DEF const char* IgFs__last_component_ref(const char* path) {
    const char* last_sep = strrchr(path, '/');
    const char* last_win_sep = strrchr(path, '\\');
    if (last_win_sep > last_sep) {
        last_sep = last_win_sep;
    }
    return last_sep ? last_sep + 1 : path;
}

IG_FS_PRIVATE_DEF const char* IgFs__last_slash_ref(const char* path) {
    const char* last_sep = strrchr(path, '/');
    const char* last_win_sep = strrchr(path, '\\');
    if (last_win_sep > last_sep) {
        last_sep = last_win_sep;
    }
    return last_sep;
}

IG_FS_PRIVATE_DEF int IgFs__joinpath_buf(char* buf, size_t buf_size, const char* pathA, const char* pathB) {
    /* internal function so no safety */
    size_t pathA_len = strlen(pathA);
    size_t pathB_len = strlen(pathB);
    size_t total_len;

    pathA_len = strlen(pathA);
    
    /* trim tailing seperators */
    while (pathA_len > 0 && IgFs__is_sep(pathA[pathA_len - 1])) pathA_len--;
    if (pathA_len == 0) {
        if (buf_size >= pathB_len + 1) {
            IgFs__strncpy(buf, pathB, pathB_len);
            buf[pathB_len] = '\0';
            return 1;
        } else {
            return 0;
        }
    }
    
    pathB_len = strlen(pathB);
    while (pathB_len > 0 && IgFs__is_sep(pathB[0])) {
        pathB_len--;
        pathB++;
    }
    if (pathB_len == 0) {
        if (buf_size >= pathA_len + 1) {
            IgFs__strncpy(buf, pathA, pathA_len);
            buf[pathA_len] = '\0';
            return 1;
        } else {
            return 0;
        }
    }
    total_len = pathA_len + pathB_len + 2; /* +2 for '/' and '\0' */
    if (total_len > buf_size) return 0;
    
    IgFs__strncpy(buf, pathA, pathA_len);
    buf[pathA_len] = '/';
    IgFs__strncpy(buf + pathA_len + 1, pathB, pathB_len);
    buf[total_len-1] = '\0'; /* Null-terminate the joined path */

    return 1;
}

IG_FS_PRIVATE_DEF int IgFs__parent_buf(char* buf, size_t buf_size, const char* path) {
    const char* last_slash;
    size_t parent_len;

    last_slash = IgFs__last_slash_ref(path);

    parent_len = last_slash ? (size_t)(last_slash - path) : 1;

    if (parent_len > buf_size) return 0;

    if (last_slash) {
        IgFs__strncpy(buf, path, parent_len);
        buf[parent_len] = '\0';
    } else {
        if (IgFs__is_sep(path[0])) {
            buf[0] = path[0];
        } else {
            buf[0] = '.';
        }
        buf[1] = '\0';
    }

    return 1;
}

IG_FS_API char* IgFs_cwd(void) {
    char* cwd_buff;
    size_t size;

    #ifdef _WIN32
        size = GetCurrentDirectory(0, NULL);
        if (size == 0) {
            return NULL;
        }

        cwd_buff = (char*)IG_FS_MALLOC(size * sizeof(char));

        if (GetCurrentDirectory(size, cwd_buff) == 0) {
            return NULL;
        }
    #else
        size = 8;
        cwd_buff = (char*)IG_FS_MALLOC(size * sizeof(char));

        while (getcwd(cwd_buff, size) == NULL) {
            if (errno == ERANGE) {
                cwd_buff = (char*)IG_FS_REALLOC(cwd_buff, size, size*2 * sizeof(char));
                size *= 2;
            } else {
                return NULL;
            }
        }
    #endif

    return cwd_buff;
}

IG_FS_API char* IgFs_home(void) {
    char* home_dir = NULL;

    #ifdef _WIN32
        char* home_drive, *home_path;
        
        home_dir = getenv("USERPROFILE");
        if (home_dir && strlen(home_dir) > 0) {
            return IgFs__strdup(home_dir);
        }

        home_drive = getenv("HOMEDRIVE");
        home_path = getenv("HOMEPATH");
        if (home_drive && home_path) {
            return IgFs__strcat2(home_drive, home_path);
        }

    #else
        struct passwd* pw;

        home_dir = getenv("HOME");
        if (home_dir && strlen(home_dir) > 0) {
            return IgFs__strdup(home_dir);
        }

        pw = getpwuid(getuid());
        if (pw && pw->pw_dir) {
            return IgFs__strdup(pw->pw_dir);
        }
    #endif

    return NULL;
}

IG_FS_API char* IgFs_temp(void) {
    char* temp_dir = NULL;
    
    #ifdef _WIN32
        DWORD size = GetTempPath(0, NULL);
        
        if (size == 0) {
            return NULL;
        }

        temp_dir = (char*)IG_FS_MALLOC(size * sizeof(char));

        if (GetTempPath(size, temp_dir) == 0) {
            IG_FS_FREE(temp_dir);
            return NULL;
        }
        return temp_dir;
    #else
        size_t i;
        const char* env_vars[] = {"TMPDIR", "TEMP", "TMP"};
        
        for (i = 0; i < sizeof(env_vars) / sizeof(env_vars[0]); i++) {
            temp_dir = getenv(env_vars[i]);
            if (temp_dir && strlen(temp_dir) > 0) {
                return IgFs__strdup(temp_dir);
            }
        }

        return IgFs__strdup("/tmp");
    #endif
}

IG_FS_API int IgFs_exists(const char* path) {
    if (!path) return 0;
    if (!*path) return 0;
    
    #ifdef _WIN32
        return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
    #else /* _WIN32 */
        return access(path, F_OK) == 0;
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_is_dir(const char* path) {
    #ifdef _WIN32
        DWORD attr;
    #else
        struct stat statbuf;
    #endif
    
    if (!path) return 0;
    if (!*path) return 0;
    
    #ifdef _WIN32
        attr = GetFileAttributesA(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            return 0;
        }
        return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    #else /* _WIN32 */
        if (lstat(path, &statbuf) < 0) {
            return 0;
        }

        return (statbuf.st_mode & S_IFMT) == S_IFDIR;
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_is_file(const char* path) {
    #ifdef _WIN32
        DWORD attr;
    #else
        struct stat statbuf;
    #endif
    
    if (!path) return 0;
    if (!*path) return 0;
    
    #ifdef _WIN32
        attr = GetFileAttributesA(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            return 0;
        }
        return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    #else /* _WIN32 */
        if (lstat(path, &statbuf) < 0) {
            return 0;
        }

        return (statbuf.st_mode & S_IFMT) == S_IFREG;
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_is_symlink(const char* path) {
    #ifdef _WIN32
        DWORD attr;
    #else
        struct stat statbuf;
    #endif
    
    if (!path) return 0;
    if (!*path) return 0;
        
    #ifdef _WIN32
        attr = GetFileAttributesA(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            return 0;
        }
        return (attr & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;

    #else
        if (lstat(path, &statbuf) != 0) {
            return 0;
        }
        return S_ISLNK(statbuf.st_mode) ? 1 : 0;
    #endif
}

#ifdef _WIN32
IG_FS_PRIVATE_DEF int IgFs__get_symlink_target_win32(const char* path, char* target_buf, size_t buf_size) {
    HANDLE hFile;
    BYTE buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    DWORD bytesReturned;
    REPARSE_DATA_BUFFER* reparse;
    WCHAR *wTarget;
    DWORD wTargetLen;

    /* Open the symlink with reparse point flag */
    hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    /* Get reparse point data */
    if (!DeviceIoControl(
        hFile,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        buffer,
        sizeof(buffer),
        &bytesReturned,
        NULL
    )) {
        CloseHandle(hFile);
        return 0;
    }

    reparse = (REPARSE_DATA_BUFFER*)buffer;

    /* Check if it's a symlink (not a junction/mount point) */
    if (reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        CloseHandle(hFile);
        return 0;
    }

    /* Extract target path (UTF-16) */
    wTarget = reparse->SymbolicLinkReparseBuffer.PathBuffer +
              (reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR));
    wTargetLen = reparse->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

    /* Convert to UTF-8 */
    if (WideCharToMultiByte(
        CP_UTF8,
        0,
        wTarget,
        wTargetLen,
        target_buf,
        buf_size,
        NULL,
        NULL
    ) == 0) {
        CloseHandle(hFile);
        return 0;
    }

    CloseHandle(hFile);
    return 1;
}
#endif /* _WIN32 */


IG_FS_API int IgFs_is_symlink_target_eq(const char* path, const char* target) {
    char buf[IG_FS_MAX_PATH + 1];
    #ifndef _WIN32
        ssize_t len;
    #endif /* _WIN32 */
    if (!IgFs_exists(path)) return 0;
    if (!IgFs_is_symlink(path)) return 0;
    
    #ifdef _WIN32
        if (IgFs__get_symlink_target_win32(path, buf, sizeof(buf) - 1)) {
            return 0;
        }
        return strcmp(target, buf) == 0;
    #else /* _WIN32 */
        len = readlink(path, buf, sizeof(buf) - 1);
        if (len == -1) return 0;
    
        buf[len] = '\0';
        return strcmp(buf, target) == 0;
    #endif /* _WIN32 */
}

IG_FS_API char* IgFs_get_symlink_target(const char* path) {
    char buf[IG_FS_MAX_PATH + 1];
    #ifndef _WIN32
    ssize_t len;
    #endif /* _WIN32 */
    if (!IgFs_exists(path)) return NULL;
    if (!IgFs_is_symlink(path)) return NULL;
    
    #ifdef _WIN32
        if (!IgFs__get_symlink_target_win32(path, buf, sizeof(buf) - 1)) {
            return NULL;
        }
        return IgFs__strdup(buf);
    #else /* _WIN32 */
        len = readlink(path, buf, sizeof(buf) - 1);
        if (len == -1) return NULL;
    
        buf[len] = '\0';
        return IgFs__strdup(buf);
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_is_mount(const char* path) {
    #ifdef _WIN32
        char volumePath[IG_FS_MAX_PATH];
    #else
        struct stat pathStat, parentStat;
        char parentPath[IG_FS_MAX_PATH];
    #endif
    
    if (!path) return 0;
    if (!*path) return 0;
    
    #ifdef _WIN32
        if (!GetVolumePathName(path, volumePath, IG_FS_MAX_PATH)) {
            return 0;
        }
        return strcmp(path, volumePath) == 0 ? 1 : 0;

    #else
        if (lstat(path, &pathStat) != 0) {
            return 0;
        }

        if (!IgFs_strcat2_buf(parentPath, IG_FS_MAX_PATH, path, "/..")) return 0;

        if (stat(parentPath, &parentStat) != 0) {
            return 0;
        }

        return (pathStat.st_dev != parentStat.st_dev) ? 1 : 0;
    #endif
}

IG_FS_API int IgFs_is_block_device(const char* path) {
    #ifdef _WIN32
        HANDLE hFile;
        DWORD bytesReturned;
        STORAGE_PROPERTY_QUERY query;
        BYTE buffer[512];
        BOOL result;
        STORAGE_DEVICE_DESCRIPTOR* descriptor;
    #else
        struct stat pathStat;
    #endif

    if (!path) return 0;
    if (!*path) return 0;   
    
    #ifdef _WIN32
        hFile = CreateFile(
            path,                               /* File path */
            0,                                  /* No access to the file */
            FILE_SHARE_READ | FILE_SHARE_WRITE, /* Allow shared access */
            NULL,                               /* Default security attributes */
            OPEN_EXISTING,                      /* Open the existing file */
            FILE_ATTRIBUTE_NORMAL,              /* Normal attributes */
            NULL                                /* No template file */
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return 0;
        }

        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        result = DeviceIoControl(
            hFile,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            sizeof(query),
            buffer,
            sizeof(buffer),
            &bytesReturned,
            NULL
        );

        CloseHandle(hFile);

        if (!result) {
            return 0;
        }

        descriptor = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
        return (descriptor->BusType == BusTypeScsi || descriptor->BusType == BusTypeAta) ? 1 : 0;
    #else
        if (lstat(path, &pathStat) != 0) {
            return 0;
        }

        return S_ISBLK(pathStat.st_mode) ? 1 : 0;
    #endif
}

IG_FS_API int IgFs_is_char_device(const char* path) {
    #ifdef _WIN32
        HANDLE hFile;
        const char* knownDevices[] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", NULL};
        const char** device;
    #else
        struct stat pathStat;
    #endif
    
    if (!path) return 0;
    if (!*path) return 0;

    #ifdef _WIN32
        hFile = CreateFile(
            path,
            0,                                  /* No access to the file */
            FILE_SHARE_READ | FILE_SHARE_WRITE, /* Allow shared access */
            NULL,                               /* Default security attributes */
            OPEN_EXISTING,                      /* Open the existing file */
            FILE_ATTRIBUTE_NORMAL,              /* Normal attributes */
            NULL                                /* No template file */
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            for (device = knownDevices; *device; ++device) {
                if (_stricmp(path, *device) == 0) {
                    return 1;
                }
            }

            return 0;
        }

        CloseHandle(hFile);
        return 1;
    #else
        if (lstat(path, &pathStat) != 0) {
            return 0;
        }

        return S_ISCHR(pathStat.st_mode) ? 1 : 0;
    #endif
}

IG_FS_API int IgFs_is_socket(const char* path) {
    #ifdef _WIN32
        (void) path;
        return 0;
    #else
        struct stat pathStat;
        
        if (!path) return 0;
        if (!*path) return 0;
        
        if (lstat(path, &pathStat) != 0) {
            return 0;
        }

        return S_ISSOCK(pathStat.st_mode) ? 1 : 0;
    #endif
}

IG_FS_API int IgFs_is_fifo(const char* path) {
    #ifdef _WIN32
        if (!path) return 0;
        return strncmp(path, "\\\\.\\pipe\\", 9) == 0;
    #else
        struct stat pathStat;
        
        if (!path) return 0;
        if (!*path) return 0;
        
        if (lstat(path, &pathStat) != 0) {
            return 0;
        }

        return S_ISFIFO(pathStat.st_mode) ? 1 : 0;
    #endif
}

IG_FS_API int IgFs_is_absolute(const char* path) {
    return IgFs_is_absolute_win32(path) || IgFs_is_absolute_posix(path);
}

IG_FS_API int IgFs_is_absolute_posix(const char* path) {
    if (!path) return 0;
    
    return (path[0] == '/');
}

IG_FS_API int IgFs_is_absolute_win32(const char* path) {
    if (!path) return 0;
    /* at least 1 character */
    if (!*path) return 0;
    
    /* at least 2 characters */
    if (!*(path + 1)) return 0;
    if (path[0] == '\\' && path[1] == '\\') {
        /* UNC path (e.g., \\server\share) */
        return 1;
    }
    /* at least 3 characters */
    if (!*(path + 2)) return 0;
    if (path[1] == ':' && IgFs__is_sep(path[2])) {
        /* Drive letter path (e.g., C:\ or C:/) */
        return 1;
    }
    return 0;
}

IG_FS_API int IgFs_is_relative(const char* root, const char* path) {
    int chopped_path_sep;
    
    if(!root || !path) return 0; /*  NULL paths are invalid */
    if(!*root || !*path) return 0; /*  Empty paths are invalid */

    /* Compare the root and path character by character */
    while (*root && *path) {
        chopped_path_sep = IgFs__is_sep(*path);
        /* Skip consecutive separators in root and path */
        while (IgFs__is_sep(*root)) root++;
        while (IgFs__is_sep(*path)) path++;

        if (!*root && chopped_path_sep)
            reurn 1; /*  Path starts with a separator, so it's relative */

            /* Compare the current character */
        if (*root != *path) {
            reurn 0; /*  Mismatch */
        }

        /* Move to the next character */
        root++;
        path++;
    }

    /* If root is exhausted, path is relative to root */
    if (!*root) {
        /* Skip any trailing separators in root */
        while (IgFs__is_sep(*root)) root++;

        /* If root is fully exhausted, check if path is empty or continues with a separator */
        if (!*root) {
            if (!*path || IgFs__is_sep(*path)) {
                return 1;
            }
        }
    }

    return 0;
}

IG_FS_API char* IgFs_suffix(const char* path) {
    size_t path_size, last_sep_loc;
    const char* suffix;
    
    if (!path) return NULL;
    if (!*path) return "";
    
    suffix = strrchr(path, '.');
    if (!suffix) return ""; 
    
    /* some/random\file.txt */
    /*            ^    ^    */
    path_size = strlen(path);
    last_sep_loc = path_size - 1;
    while (last_sep_loc > 0 && !IgFs__is_sep(path[last_sep_loc]) && path[last_sep_loc] != '.') last_sep_loc--;

    if (last_sep_loc > (size_t)(suffix - path)) return "";
    if (last_sep_loc == 0) return "";
    
    return IgFs__strdup(suffix);
}

IG_FS_API char** IgFs_suffixes(const char* path, int* suffix_count) {
    char** suffixes;
    const char* final_component;
    const char* p;
    size_t dot_count, index, i;
    if (!path) return NULL;

    final_component = IgFs__last_component_ref(path);

    dot_count = 0;
    p = final_component;
    while (*p) {
        if (*p == '.') dot_count++;
        p++;
    }

    if (suffix_count) {
        *suffix_count = 0;
    }
    
    if (dot_count == 0 || (dot_count == 1 && final_component[0] == '.')) {
        return NULL;
    }

    suffixes = (char**)IG_FS_MALLOC((dot_count + 1) * sizeof(char*));
    if (!suffixes) return NULL;
    suffixes[dot_count] = NULL;
    
    p = final_component;
    index = 0;
    while (*p) {
        if (*p == '.') {
            if (p != final_component) {
                const char* next_dot = strchr(p + 1, '.');
                if (next_dot) {
                    suffixes[index] = IgFs__strndup(p, (size_t)(next_dot - p));
                } else {
                    suffixes[index] = IgFs__strdup(p);
                }
                if (!suffixes[index]) {
                    for (i = 0; i < index; i++) {
                        IG_FS_FREE(suffixes[i]);
                    }
                    IG_FS_FREE(suffixes);
                    return NULL;
                }
                index++;
            }
        }
        p++;
    }


    if (suffix_count) {
        *suffix_count = (int)index;
    }
    return suffixes;
}

IG_FS_API char* IgFs_with_suffix(const char* path, const char* suffix) {
    size_t path_len, suffix_len, new_path_len;
    const char* last_dot;
    const char* final_component;
    char* new_path;
    
    if(!path || !suffix) return NULL; /*  Invalid input */

    final_component = IgFs__last_component_ref(path);

    /* Find the last '.' in the final component */
    last_dot = strrchr(final_component, '.');

    /* Calculate the length of the new path */
    path_len = strlen(path);
    suffix_len = strlen(suffix);

    if (last_dot) {
        /* If there is a dot, replace the existing suffix */
        new_path_len = (size_t)(last_dot - path) + suffix_len + 1;
    } else {
        /* If there is no dot, append the new suffix */
        new_path_len = path_len + suffix_len + 1;
    }

    /* Allocate memory for the new path */
    new_path = (char*)IG_FS_MALLOC(new_path_len);
    if(!new_path) return NULL; /*  Memory allocation failed */

    /* Copy the path up to the last dot (or the entire path if no dot exists) */
    if (last_dot) {
        IgFs__strncpy(new_path, path, (size_t)(last_dot - path));
        ne_path[last_dot - path] = '\0'; /*  Null-terminate the copied part */
    } else {
        strcpy(new_path, path);
    }

    /* Append the new suffix */
    strcat(new_path, suffix);

    return new_path;
}

IG_FS_API char* IgFs_stem(const char* path) {
    const char* last_dot;
    const char* final_component;
    char* stem;
    size_t final_component_len, stem_len;

    if (!path) return NULL;

    final_component = IgFs__last_component_ref(path);

    /* Find the last '.' in the final component */
    last_dot = strrchr(final_component, '.');

    /* Calculate the length of the new path */
    final_component_len = strlen(final_component);
    stem_len = last_dot ? (size_t)(last_dot - path) : final_component_len;

    /* Allocate memory for the new path */
    stem = (char*)IG_FS_MALLOC(stem_len + 1);
    if(!stem) return NULL; /*  Memory allocation failed */

    /* Copy the path up to the last dot (or the entire path if no dot exists) */
    if (last_dot) {
        IgFs__strncpy(stem, final_component, (size_t)(last_dot - final_component));
        stm[last_dot - final_component] = '\0'; /*  Null-terminate the copied part */
    } else {
        strcpy(stem, final_component);
    }

    return stem;
}

IG_FS_API char* IgFs_parent(const char* path) {
    const char* last_slash;
    char* parent;
    size_t parent_len;

    if (!path) return NULL;

    /* Find the last '/' in the path */
    last_slash = IgFs__last_slash_ref(path);

    /* Calculate the length of the new path */
    parent_len = last_slash ? (size_t)(last_slash - path) : 1;

    /* Allocate memory for the new path */
    parent = (char*)IG_FS_MALLOC(parent_len + 1);
    if(!parent) return NULL; /*  Memory allocation failed */

    /* Copy the path up to the last slash (or the entire path if no slash exists) */
    if (last_slash) {
        IgFs__strncpy(parent, path, parent_len);
        paent[parent_len] = '\0'; /*  Null-terminate the copied part */
    } else {
        if (IgFs__is_sep(path[0])) {
            parent[0] = path[0];
        } else {
            parent[0] = '.';
        }
        parent[1] = '\0';
    }

    return parent;
}

IG_FS_API char* IgFs_name(const char* path) {
    const char* last_part;
    
    if (!path) return NULL;
    
    last_part = IgFs__last_component_ref(path);
    
    return IgFs__strdup(last_part);
}

IG_FS_API char* IgFs_joinpath(const char* pathA, const char* pathB) {
    size_t pathA_len;
    size_t pathB_len;
    size_t total_len;
    char* joined_path;

    if (!pathA || !pathB) return NULL;
    
    pathA_len = strlen(pathA);
    
    /* trim tailing seperators */
    while (pathA_len > 0 && IgFs__is_sep(pathA[pathA_len - 1])) pathA_len--;
    if (pathA_len == 0) return IgFs__strdup(pathB);
    
    pathB_len = strlen(pathB);
    while (pathB_len > 0 && IgFs__is_sep(pathB[0])) {
        pathB_len--;
        pathB++;
    }
    if (pathB_len == 0) return IgFs__strdup(pathA);
    total_len = pathA_len + pathB_len + 2; /* +2 for '/' and '\0' */
    joined_path = (char*)IG_FS_MALLOC(total_len);
    if (!joined_path) return NULL;
    
    IgFs__strncpy(joined_path, pathA, pathA_len);
    joined_path[pathA_len] = '/';
    IgFs__strncpy(joined_path + pathA_len + 1, pathB, pathB_len);
    joined_path[total_len-1] = '\0'; /* Null-terminate the joined path */

    return joined_path;
}

IG_FS_API char** IgFs_listdir(const char* inpath, int* file_count) {
    char** paths;
    size_t path_count;
    const char* name;
    size_t i;
    #ifdef _WIN32
        char searchPath[IG_FS_MAX_PATH+3];
        WIN32_FIND_DATA findFileData;
        HANDLE hFind;
    #else /* _WIN32 */
        DIR* dir;
        struct dirent* entry;
    #endif /* _WIN32 */
    
    if (!IgFs_exists(inpath)) {
        if (file_count) *file_count = 0;
        return NULL;
    }
    
    #ifdef _WIN32
        if (!IgFs_strcat2_buf(searchPath, IG_FS_MAX_PATH+3, inpath, "\\*")) {
            if (file_count) *file_count = 0;
            return NULL;
        }

        hFind = FindFirstFile(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            if (file_count) *file_count = 0;
            return NULL;
        }
        
        path_count = 0;
        do {
            name = findFileData.cFileName;
    
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
            
            path_count++;
    
        } while (FindNextFile(hFind, &findFileData) != 0);
    
        FindClose(hFind);
        
        paths = IG_FS_MALLOC(sizeof(*paths)*(path_count + 1));
        if (!paths) {
            if (file_count) *file_count = 0;
            return NULL;
        }
        paths[path_count] = NULL;
        
        hFind = FindFirstFile(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
            if (file_count) *file_count = 0;
            return NULL;
        }
    
        i = 0;
        do {
            name = findFileData.cFileName;
    
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

            paths[i++] = IgFs_joinpath(inpath, name);
        } while (FindNextFile(hFind, &findFileData) != 0);
    
        FindClose(hFind);
    #else /* _WIN32 */
        path_count = 0;
        dir = opendir(inpath);
        if (dir == NULL) {
            if (file_count) *file_count = 0;
            return NULL;
        }
    
        while ((entry = readdir(dir)) != NULL) {
            name = entry->d_name;
    
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
            path_count++;
        }
    
        closedir(dir);
        
        paths = IG_FS_MALLOC(sizeof(*paths)*(path_count + 1));
        if (!paths) {
            if (file_count) *file_count = 0;
            return NULL;
        }
        paths[path_count] = NULL;
        
        dir = opendir(inpath);
        if (dir == NULL) {
            IG_FS_FREE(paths);
            if (file_count) *file_count = 0;
            return NULL;
        }
    
        i = 0;
        while ((entry = readdir(dir)) != NULL) {
            name = entry->d_name;
    
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
            
            paths[i++] = IgFs_joinpath(inpath, name);
        }
    
        closedir(dir);
    #endif /* _WIN32 */
    
    if (file_count) *file_count = (int)path_count;
    
    return paths;
}

IG_FS_API int IgFs_unlink(const char* path) {
    if (!path) return 0;
    
    if (!IgFs_exists(path)) return 1;
    if (!IgFs_is_file(path)) return 0;
    
    #ifdef _WIN32
    if (!DeleteFileA(path)) return 0;
    #else /* _WIN32 */
    if (unlink(path) != 0) return 0;
    #endif /* _WIN32 */
    
    return 1;
}

#ifdef _WIN32
IG_FS_PRIVATE_DEF int IgFs__remove_directory_contents(const char* path) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind;
    char searchPath[IG_FS_MAX_PATH+3];
    char subpath_buf[IG_FS_MAX_PATH + 1];
    
    if (!IgFs_strcat2_buf(searchPath, IG_FS_MAX_PATH + 3, path, "\\*")) return 0;

    hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        const char* name = findFileData.cFileName;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        
        if (!IgFs__joinpath_buf(subpath_buf, IG_FS_MAX_PATH + 1, path, name)) continue;
        
        /* Recursive removal for directories, or delete files */
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!IgFs_rmdir(subpath_buf, 1)) {
                FindClose(hFind);
                return 0;
            }
        } else {
            if (!DeleteFile(subpath_buf)) {
                FindClose(hFind);
                return 0;
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return 1;
}
#else /* _WIN32 */
IG_FS_PRIVATE_DEF int IgFs__remove_directory_contents(const char* path) {
    DIR* dir;
    struct dirent* entry;
    struct stat pathStat;
    char subpath_buf[IG_FS_MAX_PATH + 1];
    
    dir = opendir(path);
    if (dir == NULL) return 0;

    while ((entry = readdir(dir)) != NULL) {
        const char* name = entry->d_name;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        if (!IgFs__joinpath_buf(subpath_buf, IG_FS_MAX_PATH + 1, path, name)) continue;

        if (stat(subpath_buf, &pathStat) != 0) continue;

        if (S_ISDIR(pathStat.st_mode)) {
            if (!IgFs_rmdir(subpath_buf, 1)) {
                closedir(dir);
                return 0;
            }
        } else {
            if (unlink(subpath_buf) != 0) {
                closedir(dir);
                return 0;
            }
        }
    }

    closedir(dir);
    return 1;
}
#endif /* _WIN32 */

IG_FS_API int IgFs_rmdir(const char* path, int remove_contents) {
    if (!IgFs_exists(path)) return 1;
    if (!IgFs_is_dir(path)) return 0;
    
    if (remove_contents) {
        if (!IgFs__remove_directory_contents(path)) return 0;
    }
    
    #ifdef _WIN32
        if (!RemoveDirectory(path)) return 0;
    #else
        if (rmdir(path) != 0) return 0;
    #endif
    
    return 1;
}

IG_FS_API int IgFs_mkdir(const char* path) {
    char parent_buf[IG_FS_MAX_PATH + 1];

    if (IgFs_exists(path)) return IgFs_is_dir(path);
    
    if (!IgFs__parent_buf(parent_buf, IG_FS_MAX_PATH + 1, path)) return 0;
    
    if (!IgFs_exists(parent_buf)) {
        if (!IgFs_mkdir(parent_buf)) return 0;
    }

    #ifdef _WIN32
        if (!CreateDirectory(path, NULL)) return 0;
    #else
        if (mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) return 0;
    #endif
    
    return 1;
}

IG_FS_API int IgFs_ensure_parent_exists(const char* path) {
    char parent_buf[IG_FS_MAX_PATH + 1];

    if (!IgFs__parent_buf(parent_buf, IG_FS_MAX_PATH + 1, path)) return 0;
    
    return IgFs_mkdir(parent_buf);
}

IG_FS_API int IgFs_touch(const char* path) {
    #ifdef _WIN32
        HANDLE hFile;
    #else /* _WIN32 */
        int fd;
    #endif /* _WIN32 */
    
    if (IgFs_exists(path)) return IgFs_is_file(path);
    if (!IgFs_ensure_parent_exists(path)) return 0;
    
    #ifdef _WIN32
        hFile = CreateFile(
            path,                  /* File name */
            GENERIC_WRITE,         /* Desired access */
            0,                     /* Share mode (no sharing) */
            NULL,                  /* Security attributes */
            CREATE_NEW,            /* Creation disposition (create a new file) */
            FILE_ATTRIBUTE_NORMAL, /* File attributes */
            NULL                   /* Template file */
        );

        if (hFile == INVALID_HANDLE_VALUE) return 0;
        CloseHandle(hFile);
        return 1;
    #else /* _WIN32 */
        fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

        if (fd == -1) return 0;

        close(fd);
        return 1;
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_new_symlink(const char* path, const char* target) {
    if (IgFs_exists(path)) {
        if (!IgFs_is_symlink(path)) {
            return 0;
        } else {
            return IgFs_is_symlink_target_eq(path, target);
        }
    }
    
    #ifdef _WIN32
        return CreateSymbolicLinkA(path, target, IgFs_is_dir(target) ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) != 0;
    #else /* _WIN32 */
        return symlink(target, path) == 0;
    #endif /* _WIN32 */
}

IG_FS_API int IgFs_rename(const char* old_path, const char* new_path) {
    if (!IgFs_ensure_parent_exists(new_path)) return 0;
    #ifdef _WIN32
        return MoveFileExA(old_path, new_path, MOVEFILE_REPLACE_EXISTING) != 0;
    #else /* _WIN32 */
        return rename(old_path, new_path) == 0;
    #endif /* _WIN32 */
}

#ifndef _WIN32
/* a slightly modified version of musl's realpath */
/* begin of https://github.com/kraj/musl/blob/eb4309b142bb7a8bdc839ef1faf18811b9ff31c8/src/misc/realpath.c */
    /* errors with -Weverything, not my code not my problem to remove the warnings */
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #pragma clang diagnostic ignored "-Wsign-compare"
    #pragma clang diagnostic ignored "-Wcomma"
    #endif /* __clang__ */
    
    static size_t IgFs__musl_slash_len(const char *s) {
    	const char *s0 = s;
    	while (*s == '/') s++;
    	return s-s0;
    }
    
    static int IgFs__musl_realpath(const char *filename, char *resolved) {
    	char stack[PATH_MAX+1];
    	char output[PATH_MAX];
    	size_t p, q, l, l0, cnt=0, nup=0;
        ssize_t k;
    	int check_dir=0, up;
        char* z;
    
    	if (!filename) {
    		errno = EINVAL;
    		return 0;
    	}
    	l = strnlen(filename, sizeof stack);
    	if (!l) {
    		errno = ENOENT;
    		return 0;
    	}
    	if (l >= PATH_MAX) goto toolong;
    	p = sizeof stack - l - 1;
    	q = 0;
    	memcpy(stack+p, filename, l+1);
    
    	/* Main loop. Each iteration pops the next part from stack of
    	 * remaining path components and consumes any slashes that follow.
    	 * If not a link, it's moved to output; if a link, contents are
    	 * pushed to the stack. */
    restart:
    	for (; ; p+=IgFs__musl_slash_len(stack+p)) {
    		/* If stack starts with /, the whole component is / or //
    		 * and the output state must be reset. */
    		if (stack[p] == '/') {
    			check_dir=0;
    			nup=0;
    			q=0;
    			output[q++] = '/';
    			p++;
    			/* Initial // is special. */
    			if (stack[p] == '/' && stack[p+1] != '/')
    				output[q++] = '/';
    			continue;
    		}
    
    		z = strchrnul(stack+p, '/');
    		l0 = l = z-(stack+p);
    
    		if (!l && !check_dir) break;
    
    		/* Skip any . component but preserve check_dir status. */
    		if (l==1 && stack[p]=='.') {
    			p += l;
    			continue;
    		}
    
    		/* Copy next component onto output at least temporarily, to
    		 * call readlink, but wait to advance output position until
    		 * determining it's not a link. */
    		if (q && output[q-1] != '/') {
    			if (!p) goto toolong;
    			stack[--p] = '/';
    			l++;
    		}
    		if (q+l >= PATH_MAX) goto toolong;
    		memcpy(output+q, stack+p, l);
    		output[q+l] = 0;
    		p += l;
    
    		up = 0;
    		if (l0==2 && stack[p-2]=='.' && stack[p-1]=='.') {
    			up = 1;
    			/* Any non-.. path components we could cancel start
    			 * after nup repetitions of the 3-byte string "../";
    			 * if there are none, accumulate .. components to
    			 * later apply to cwd, if needed. */
    			if (q <= 3*nup) {
    				nup++;
    				q += l;
    				continue;
    			}
    			/* When previous components are already known to be
    			 * directories, processing .. can skip readlink. */
    			if (!check_dir) goto skip_readlink;
    		}
    		k = readlink(output, stack, p);
    		if (k==p) goto toolong;
    		if (!k) {
    			/* errno = ENOENT; */
    			return 1;
    		}
    		if (k<0) {
                /* modified this to also check for ENOENT to allow the return of paths that doent exist */
    			if (errno != EINVAL && errno != ENOENT) return 0;
    skip_readlink:
    			check_dir = 0;
    			if (up) {
    				while(q && output[q-1]!='/') q--;
    				if (q>1 && (q>2 || output[0]!='/')) q--;
    				continue;
    			}
    			if (l0) q += l;
    			check_dir = stack[p];
    			continue;
    		}
    		if (++cnt == 16) {
    			errno = ELOOP;
    			return 0;
    		}
    
    		/* If link contents end in /, strip any slashes already on
    		 * stack to avoid /->// or //->/// or spurious toolong. */
    		if (stack[k-1]=='/') while (stack[p]=='/') p++;
    		p -= k;
    		memmove(stack+p, stack, k);
    
    		/* Skip the stack advancement in case we have a new
    		 * absolute base path. */
    		goto restart;
    	}
    
   	output[q] = 0;
    
    	if (output[0] != '/') {
    		if (!getcwd(stack, sizeof stack)) return 0;
    		l = strlen(stack);
    		/* Cancel any initial .. components. */
    		p = 0;
    		while (nup--) {
    			while(l>1 && stack[l-1]!='/') l--;
    			if (l>1) l--;
    			p += 2;
    			if (p<q) p++;
    		}
    		if (q-p && stack[l-1]!='/') stack[l++] = '/';
    		if (l + (q-p) + 1 >= PATH_MAX) goto toolong;
    		memmove(output + l, output + p, q - p + 1);
    		memcpy(output, stack, l);
    		q = l + q-p;
    	}
    
    	memcpy(resolved, output, q+1);
    	return 1;
    
    toolong:
    	errno = ENAMETOOLONG;
    	return 0;
    }
    
    /* errors with -Weverything, not my code not my problem to remove the warnings */
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif /* __clang__ */
/* end of https://github.com/kraj/musl/blob/eb4309b142bb7a8bdc839ef1faf18811b9ff31c8/src/misc/realpath.c */
#endif /* _WIN32 */

IG_FS_API char* IgFs_resolve(const char* path) {
    char* resolved_path = NULL;
    
    #ifdef _WIN32
        char* buffer = (char*)IG_FS_MALLOC(IG_FS_MAX_PATH);
        if (!buffer) return NULL;
        
        if (GetFullPathNameA(path, IG_FS_MAX_PATH, buffer, NULL)) {
            resolved_path = buffer;
        } else {
            IG_FS_FREE(buffer);
        }
    #else /* _WIN32 */
        char* buffer = (char*)IG_FS_MALLOC(IG_FS_MAX_PATH);
        if (!buffer) return NULL;
        
        if (IgFs__musl_realpath(path, buffer)) {
            resolved_path = buffer;
        } else {
            IG_FS_FREE(buffer);
        }
    #endif /* _WIN32 */
    
    return resolved_path;
}

IG_FS_API FILE* IgFs_open(const char* path, const char* mode) {
    FILE* file = NULL;
    
    if (!IgFs_exists(path)) {
        if (!IgFs_touch(path)) return NULL;
    } else {
        if (!IgFs_is_file(path)) return NULL;
    }
    
    file = fopen(path, mode);
    
    return file;
}

IG_FS_API char* IgFs_read_text(const char* path, int* file_size) {
    FILE* file = IgFs_open(path, "r");
    long size;
    char* buffer;
    
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    buffer = (char*)IG_FS_MALLOC((size_t)(size + 1));
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    fread(buffer, 1, (size_t)size, file);
    buffer[size] = '\0';
    
    fclose(file);
    
    if (file_size) *file_size = (int)size;
    
    return buffer;
}

IG_FS_API unsigned char* IgFs_read_bytes(const char* path, int* byte_count)  {
    FILE* file = IgFs_open(path, "rb");
    long size;
    unsigned char* buffer;
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    buffer = (unsigned char*)IG_FS_MALLOC((size_t)size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    fread(buffer, 1, (size_t)size, file);
    
    fclose(file);
    
    if (byte_count) *byte_count = (int)size;
    
    return buffer;
}

IG_FS_API int IgFs_write_text(const char* path, const char* text, int text_size) {
    FILE* file;
    if (!IgFs_exists(path)) return 0;
    if (!IgFs_is_file(path)) return 0;
    
    file = IgFs_open(path, "w");
    if (!file) return 0;
    
    fwrite(text, 1, (size_t)text_size, file);
    
    fclose(file);
    
    return 1;
}

IG_FS_API int IgFs_write_bytes(const char* path, const unsigned char* buff, int buff_size) {
    FILE* file;
    if (!IgFs_exists(path)) return 0;
    if (!IgFs_is_file(path)) return 0;
    
    file = IgFs_open(path, "wb");
    if (!file) return 0;
    
    fwrite(buff, 1, (size_t)buff_size, file);
    
    fclose(file);
    
    return 1;
}

IG_FS_API int IgFs_copyfile(const char* src_path, const char* dst_path) {
    #ifdef _WIN32
        return CopyFile(src_path, dst_path, FALSE) != 0;
    #else
        int src_fd = -1;
        int dst_fd = -1;
        size_t buf_size = 32*1024;
        char* buf = IG_FS_MALLOC(buf_size);
        char* buf2;
        ssize_t n, m;
        struct stat src_stat;
        if (!buf) goto failed;
        
        src_fd = open(src_path, O_RDONLY);
        if (src_fd < 0) goto failed;
    
        if (fstat(src_fd, &src_stat) < 0) goto failed;
    
        if (!IgFs_ensure_parent_exists(dst_path)) goto failed;
        dst_fd = open(dst_path, O_CREAT | O_TRUNC | O_WRONLY, src_stat.st_mode);
        if (dst_fd < 0) goto failed;
    
        for (;;) {
            n = read(src_fd, buf, buf_size);
            if (n == 0) break;
            if (n < 0) goto failed;
            buf2 = buf;
            while (n > 0) {
                m = write(dst_fd, buf2, (size_t)n);
                if (m < 0) goto failed;
                n    -= m;
                buf2 += m;
            }
        }
        IG_FS_FREE(buf);
        close(src_fd);
        close(dst_fd);
        return 1;
    failed:
        if (buf) IG_FS_FREE(buf);
        close(src_fd);
        close(dst_fd);
        return 0;
    #endif
}

/* a slightly stripped down version of fnmatch from musl C stdlib */
/* begin of https://github.com/kraj/musl/blob/eb4309b142bb7a8bdc839ef1faf18811b9ff31c8/src/regex/fnmatch.c */

    /* errors with -Weverything, not my code not my problem to remove the warnings */
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #pragma clang diagnostic ignored "-Wcomma"
    #endif /* __clang__ */

    #define IG_FS_FNM_END 0
    #define IG_FS_FNM_BRACKET -3
    #define IG_FS_FNM_QUESTION -4
    #define IG_FS_FNM_STAR -5
    #define	IG_FS_FNM_NOMATCH 1
    /*
        static wctype_t IgFs__wctype(const char *s) {
       	int i;
       	const char *p;
       	static const char names[] =
      		"alnum\0" "alpha\0" "blank\0"
      		"cntrl\0" "digit\0" "graph\0"
      		"lower\0" "print\0" "punct\0"
      		"space\0" "upper\0" "xdigi\0t";
       	for (i=1, p=names; *p; i++, p+=6)
      		if (*s == *p && !strcmp(s, p))
     			return i;
       	return 0;
    }
    */
    
    static int IgFs__str_next(const char *str, size_t n, size_t *step) {
       	if (!n) {
      		*step = 0;
      		return 0;
       	}
       	*step = 1;
       	return str[0];
    }
    
    static int IgFs__pat_next(const char *pat, size_t m, size_t *step) {
       	if (!m || !*pat) {
      		*step = 0;
      		return IG_FS_FNM_END;
       	}
       	*step = 1;
       	if (pat[0]=='\\' && pat[1]) {
      		*step = 2;
      		pat++;
      		goto escaped;
       	}
       	if (pat[0]=='[') {
      		size_t k = 1;
      		if (k<m) if (pat[k] == '^' || pat[k] == '!') k++;
      		if (k<m) if (pat[k] == ']') k++;
      		for (; k<m && pat[k] && pat[k]!=']'; k++) {
     			if (k+1<m && pat[k+1] && pat[k]=='[' && (pat[k+1]==':' || pat[k+1]=='.' || pat[k+1]=='=')) {
    				int z = pat[k+1];
    				k+=2;
    				if (k<m && pat[k]) k++;
    				while (k<m && pat[k] && (pat[k-1]!=z || pat[k]!=']')) k++;
    				if (k==m || !pat[k]) break;
     			}
      		}
      		if (k==m || !pat[k]) {
     			*step = 1;
     			return '[';
      		}
      		*step = k+1;
      		return IG_FS_FNM_BRACKET;
       	}
       	if (pat[0] == '*')
      		return IG_FS_FNM_STAR;
       	if (pat[0] == '?')
      		return IG_FS_FNM_QUESTION;
    escaped:
       	return pat[0];
    }
    
    static int IgFs__match_bracket(const char *p, int k, int kfold) {
       	wchar_t wc;
       	int inv = 0;
       	p++;
       	if (*p=='^' || *p=='!') {
      		inv = 1;
      		p++;
       	}
       	if (*p==']') {
      		if (k==']') return !inv;
      		p++;
       	} else if (*p=='-') {
      		if (k=='-') return !inv;
      		p++;
       	}
       	wc = p[-1];
       	for (; *p != ']'; p++) {
      		if (p[0]=='-' && p[1]!=']') {
     			wchar_t wc2;
     			int l = mbtowc(&wc2, p+1, 4);
     			if (l < 0) return 0;
     			if (wc <= wc2)
    				if ((unsigned)k-wc <= (unsigned)wc2-wc ||
    				(unsigned)kfold-wc <= (unsigned)wc2-wc)
       					return !inv;
     			p += l-1;
     			continue;
      		}
      		if (p[0]=='[' && (p[1]==':' || p[1]=='.' || p[1]=='=')) {
     			const char *p0 = p+2;
     			int z = p[1];
     			p+=3;
     			while (p[-1]!=z || p[0]!=']') p++;
     			if (z == ':' && p-1-p0 < 16) {
    				char buf[16];
    				memcpy(buf, p0, p-1-p0);
    				buf[p-1-p0] = 0;
        /* @TODO */
    				/* if (iswctype(k, IgFs__wctype(buf)) || iswctype(kfold, IgFs__wctype(buf))) */
       	/* 				return !inv; */
     			}
     			continue;
      		}
      		if ((unsigned char)*p < 128U) {
     			wc = (unsigned char)*p;
      		} else {
     			int l = mbtowc(&wc, p, 4);
     			if (l < 0) return 0;
     			p += l-1;
      		}
      		if (wc==k || wc==kfold) return !inv;
       	}
       	return inv;
    }
    
    static int IgFs__fnmatch(const char *pat, const char *str) {
       	const char *p, *ptail, *endpat;
       	const char *s, *stail, *endstr;
       	size_t m = -1, n = -1, pinc, sinc, tailcnt=0;
       	int c, k;
    
       	for (;;) {
      		switch ((c = IgFs__pat_next(pat, m, &pinc))) {
      		case IG_FS_FNM_STAR:
     			pat++;
     			m--;
     			break;
      		default:
     			k = IgFs__str_next(str, n, &sinc);
     			if (k <= 0)
    				return (c==IG_FS_FNM_END) ? 0 : IG_FS_FNM_NOMATCH;
     			str += sinc;
     			n -= sinc;
     			if (c == IG_FS_FNM_BRACKET) {
    				if (!IgFs__match_bracket(pat, k, k))
       					return IG_FS_FNM_NOMATCH;
     			} else if (c != IG_FS_FNM_QUESTION && k != c && k != c) {
    				return IG_FS_FNM_NOMATCH;
     			}
     			pat+=pinc;
     			m-=pinc;
     			continue;
      		}
      		break;
       	}
    
       	/* Compute real pat length if it was initially unknown/-1 */
       	m = strlen(pat);
       	endpat = pat + m;
    
       	/* Find the last * in pat and count chars needed after it */
       	for (p=ptail=pat; p<endpat; p+=pinc) {
      		switch (IgFs__pat_next(p, endpat-p, &pinc)) {
      		case IG_FS_FNM_STAR:
     			tailcnt=0;
     			ptail = p+1;
     			break;
      		default:
     			tailcnt++;
     			break;
      		}
       	}
    
       	/* Compute real str length if it was initially unknown/-1 */
       	n = strlen(str);
       	endstr = str + n;
       	if (n < tailcnt) return IG_FS_FNM_NOMATCH;
    
       	/* Find the final tailcnt chars of str, accounting for UTF-8.
      	 * On illegal sequences we may get it wrong, but in that case
      	 * we necessarily have a matching failure anyway. */
       	for (s=endstr; s>str && tailcnt; tailcnt--) {
      		if ((unsigned char)s[-1] < 128U || MB_CUR_MAX==1) s--;
      		else while ((unsigned char)*--s-0x80U<0x40 && s>str);
       	}
       	if (tailcnt) return IG_FS_FNM_NOMATCH;
       	stail = s;
    
       	/* Check that the pat and str tails match */
       	p = ptail;
       	for (;;) {
      		c = IgFs__pat_next(p, endpat-p, &pinc);
      		p += pinc;
      		if ((k = IgFs__str_next(s, endstr-s, &sinc)) <= 0) {
     			if (c != IG_FS_FNM_END) return IG_FS_FNM_NOMATCH;
     			break;
      		}
      		s += sinc;
      		if (c == IG_FS_FNM_BRACKET) {
     			if (!IgFs__match_bracket(p-pinc, k, k))
    				return IG_FS_FNM_NOMATCH;
      		} else if (c != IG_FS_FNM_QUESTION && k != c && k != c) {
     			return IG_FS_FNM_NOMATCH;
      		}
       	}
    
       	/* We're all done with the tails now, so throw them out */
       	endstr = stail;
       	endpat = ptail;
    
       	/* Match pattern components until there are none left */
       	while (pat<endpat) {
      		p = pat;
      		s = str;
      		for (;;) {
     			c = IgFs__pat_next(p, endpat-p, &pinc);
     			p += pinc;
     			/* Encountering * completes/commits a component */
     			if (c == IG_FS_FNM_STAR) {
    				pat = p;
    				str = s;
    				break;
     			}
     			k = IgFs__str_next(s, endstr-s, &sinc);
     			if (!k)
    				return IG_FS_FNM_NOMATCH;
     			if (c == IG_FS_FNM_BRACKET) {
    				if (!IgFs__match_bracket(p-pinc, k, k))
       					break;
     			} else if (c != IG_FS_FNM_QUESTION && k != c && k != c) {
    				break;
     			}
     			s += sinc;
      		}
      		if (c == IG_FS_FNM_STAR) continue;
      		/* If we failed, advance str, by 1 char if it's a valid
     		 * char, or past all invalid bytes otherwise. */
      		k = IgFs__str_next(str, endstr-str, &sinc);
      		if (k > 0) str += sinc;
      		else for (str++; IgFs__str_next(str, endstr-str, &sinc)<0; str++);
       	}
    
       	return 0;
    }
    
    #undef IG_FS_FNM_END
    #undef IG_FS_FNM_BRACKET
    #undef IG_FS_FNM_QUESTION
    #undef IG_FS_FNM_STAR
    #undef IG_FS_FNM_NOMATCH
    
    /* errors with -Weverything, not my code not my problem to remove the warnings */
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif /* __clang__ */
/* end o https://github.com/kraj/musl/blob/eb4309b142bb7a8bdc839ef1faf18811b9ff31c8/src/regex/fnmatch.c */

static int IgFs__rglob_impl(const char* base_path, const char* pattern, int recursive, int match_directories, char*** paths, int* path_count, int* path_capacity) {
    char fullpath[IG_FS_MAX_PATH+3];
    int new_capacity;
    const char* name;
    
    #if defined(_WIN32)
        WIN32_FIND_DATA find_data;
        HANDLE hFind;
        char search_path[IG_FS_MAX_PATH+3];
    
        if (!IgFs__joinpath_buf(search_path, IG_FS_MAX_PATH+3, base_path, "\\*")) return 0;
        
        hFind = FindFirstFile(search_path, &find_data);
        if (hFind == INVALID_HANDLE_VALUE) return 0;
    
        do {
            name = find_data.cFileName;
            
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
    
            if (!IgFs__joinpath_buf(fullpath, IG_FS_MAX_PATH+3, base_path, name)) continue;

            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recursive) {
                    if (!IgFs__rglob_impl(fullpath, pattern, recursive, match_directories, paths, path_count, path_capacity)) {
                        FindClose(hFind);
                        return 0;
                    }
                }
                if (!match_directories) continue;
            }

            if (IgFs__fnmatch(pattern, name) == 0) {
                if (*path_count >= *path_capacity) {
                    new_capacity = *path_capacity ? *path_capacity*3/2 : 16;
                    paths[0] = IG_FS_REALLOC(
                                (void*)*paths,
                                (unsigned int)*path_capacity*sizeof(paths[0][0]), 
                                (unsigned int)new_capacity*sizeof(paths[0][0]));
                    if (!*paths) {
                        FindClose(hFind);
                        return 0;
                    }
                    *path_capacity = new_capacity;
                }
                paths[0][(*path_count)++] = IgFs__strdup(fullpath);
            }
    
        } while (FindNextFile(hFind, &find_data) != 0);
    
        FindClose(hFind);
    #else /* _WIN32 */
        DIR* dir;
        struct dirent* entry;
        struct stat path_stat;
    
        dir = opendir(base_path);
        if (dir == NULL) return 0;
    
        while ((entry = readdir(dir)) != NULL) {
            name = entry->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
    
            if (!IgFs__joinpath_buf(fullpath, IG_FS_MAX_PATH+3, base_path, name)) continue;
    
            if (lstat(fullpath, &path_stat) != 0) continue;
    
            if (S_ISDIR(path_stat.st_mode)) {
                if (recursive) {
                    if (!IgFs__rglob_impl(fullpath, pattern, recursive, match_directories, paths, path_count, path_capacity)) {
                        closedir(dir);
                        return 0;
                    }
                }
                if (!match_directories) continue;
            }

            if (IgFs__fnmatch(pattern, name) == 0) {
                if (*path_count >= *path_capacity) {
                    new_capacity = *path_capacity ? *path_capacity*3/2 : 16;
                    paths[0] = IG_FS_REALLOC(
                                (void*)*paths,
                                (unsigned int)*path_capacity*sizeof(paths[0][0]), 
                                (unsigned int)new_capacity*sizeof(paths[0][0]));
                    if (!*paths) {
                        closedir(dir);
                        return 0;
                    }
                    *path_capacity = new_capacity;
                }
                paths[0][(*path_count)++] = IgFs__strdup(fullpath);
            }
        }
    
        closedir(dir);
    #endif /*_WIN32 */

    return 1;
}

IG_FS_API char** IgFs_glob(const char* path, const char* pattern, int match_directories, int* match_count) {
    char** paths_matched = NULL;
    int path_capacity = 0;
    
    if (!IgFs_is_dir(path)) return NULL;
    
    *match_count = 0;
    if (!IgFs__rglob_impl(path, pattern, 0, match_directories, &paths_matched, match_count, &path_capacity)) return NULL;
    if (*match_count == 0) return NULL; 
    
    if (*match_count >= path_capacity) {
        paths_matched = IG_FS_REALLOC((void*)*paths_matched,
                        (unsigned int)path_capacity*sizeof(paths_matched),
                        (unsigned int)path_capacity + sizeof(*paths_matched));
        if (!paths_matched) return 0;
    }
    paths_matched[*match_count] = NULL;
    return paths_matched;
}

IG_FS_API char** IgFs_rglob(const char* path, const char* pattern, int match_directories, int* match_count) {
    char** paths_matched = NULL;
    int path_capacity = 0;
    
    if (!IgFs_is_dir(path)) return NULL;
    
    *match_count = 0;
    if (!IgFs__rglob_impl(path, pattern, 1, match_directories, &paths_matched, match_count, &path_capacity)) return NULL;
    if (*match_count == 0) return NULL; 
    
    if (*match_count >= path_capacity) {
        paths_matched = IG_FS_REALLOC((void*)*paths_matched,
                        (unsigned int)path_capacity*sizeof(paths_matched),
                        (unsigned int)path_capacity + sizeof(*paths_matched));
        if (!paths_matched) return 0;
    }
    paths_matched[*match_count] = NULL;
    return paths_matched;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* errors with -Weverything */
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */

#endif /* IG_FILESYSTEM_IMPLEMENTATION */
