#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <windows.h>
#include <stdio.h>

typedef struct _JSON_WRITER {
    FILE*   fp;
    int     depth;
    BOOL    needs_comma;
} JSON_WRITER;

BOOL    jw_open(JSON_WRITER* jw, const char* path);
void    jw_close(JSON_WRITER* jw);

void    jw_begin_array(JSON_WRITER* jw);
void    jw_end_array(JSON_WRITER* jw);
void    jw_begin_object(JSON_WRITER* jw);
void    jw_end_object(JSON_WRITER* jw);

void    jw_key(JSON_WRITER* jw, const char* key);
void    jw_string(JSON_WRITER* jw, const char* val);
void    jw_string_w(JSON_WRITER* jw, const wchar_t* val);
void    jw_int(JSON_WRITER* jw, long long val);
void    jw_bool(JSON_WRITER* jw, BOOL val);
void    jw_null(JSON_WRITER* jw);

// Convenience: write "key": "value" pair
void    jw_kv_string(JSON_WRITER* jw, const char* key, const char* val);
void    jw_kv_int(JSON_WRITER* jw, const char* key, long long val);
void    jw_kv_bool(JSON_WRITER* jw, const char* key, BOOL val);

#endif
