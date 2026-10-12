#include "json_writer.h"
#include <stdlib.h>
#include <string.h>

BOOL jw_open(JSON_WRITER* jw, const char* path) {
    jw->fp = fopen(path, "wb");
    if (!jw->fp) return FALSE;
    jw->depth = 0;
    jw->needs_comma = FALSE;
    return TRUE;
}

void jw_close(JSON_WRITER* jw) {
    if (jw->fp) {
        fprintf(jw->fp, "\n");
        fclose(jw->fp);
        jw->fp = NULL;
    }
}

static void jw_indent(JSON_WRITER* jw) {
    for (int i = 0; i < jw->depth; i++)
        fprintf(jw->fp, "  ");
}

static void jw_comma(JSON_WRITER* jw) {
    if (jw->needs_comma)
        fprintf(jw->fp, ",");
    fprintf(jw->fp, "\n");
    jw_indent(jw);
    jw->needs_comma = TRUE;
}

static void jw_write_escaped(JSON_WRITER* jw, const char* s) {
    fputc('"', jw->fp);
    if (s) {
        for (; *s; s++) {
            switch (*s) {
                case '"':  fputs("\\\"", jw->fp); break;
                case '\\': fputs("\\\\", jw->fp); break;
                case '\n': fputs("\\n", jw->fp);  break;
                case '\r': fputs("\\r", jw->fp);  break;
                case '\t': fputs("\\t", jw->fp);  break;
                default:
                    if ((unsigned char)*s < 0x20)
                        fprintf(jw->fp, "\\u%04x", (unsigned char)*s);
                    else
                        fputc(*s, jw->fp);
            }
        }
    }
    fputc('"', jw->fp);
}

void jw_begin_array(JSON_WRITER* jw) {
    jw_comma(jw);
    fputc('[', jw->fp);
    jw->depth++;
    jw->needs_comma = FALSE;
}

void jw_end_array(JSON_WRITER* jw) {
    jw->depth--;
    fprintf(jw->fp, "\n");
    jw_indent(jw);
    fputc(']', jw->fp);
    jw->needs_comma = TRUE;
}

void jw_begin_object(JSON_WRITER* jw) {
    jw_comma(jw);
    fputc('{', jw->fp);
    jw->depth++;
    jw->needs_comma = FALSE;
}

void jw_end_object(JSON_WRITER* jw) {
    jw->depth--;
    fprintf(jw->fp, "\n");
    jw_indent(jw);
    fputc('}', jw->fp);
    jw->needs_comma = TRUE;
}

void jw_key(JSON_WRITER* jw, const char* key) {
    jw_comma(jw);
    jw_write_escaped(jw, key);
    fprintf(jw->fp, ": ");
    jw->needs_comma = FALSE;
}

void jw_string(JSON_WRITER* jw, const char* val) {
    if (jw->needs_comma) {
        fprintf(jw->fp, ",\n");
        jw_indent(jw);
    }
    jw_write_escaped(jw, val);
    jw->needs_comma = TRUE;
}

void jw_string_w(JSON_WRITER* jw, const wchar_t* val) {
    if (!val) { jw_null(jw); return; }
    int needed = WideCharToMultiByte(CP_UTF8, 0, val, -1, NULL, 0, NULL, NULL);
    char* buf = (char*)malloc(needed);
    if (buf) {
        WideCharToMultiByte(CP_UTF8, 0, val, -1, buf, needed, NULL, NULL);
        jw_string(jw, buf);
        free(buf);
    }
}

void jw_int(JSON_WRITER* jw, long long val) {
    if (jw->needs_comma) {
        fprintf(jw->fp, ",\n");
        jw_indent(jw);
    }
    fprintf(jw->fp, "%lld", val);
    jw->needs_comma = TRUE;
}

void jw_bool(JSON_WRITER* jw, BOOL val) {
    if (jw->needs_comma) {
        fprintf(jw->fp, ",\n");
        jw_indent(jw);
    }
    fprintf(jw->fp, val ? "true" : "false");
    jw->needs_comma = TRUE;
}

void jw_null(JSON_WRITER* jw) {
    if (jw->needs_comma) {
        fprintf(jw->fp, ",\n");
        jw_indent(jw);
    }
    fprintf(jw->fp, "null");
    jw->needs_comma = TRUE;
}

void jw_kv_string(JSON_WRITER* jw, const char* key, const char* val) {
    jw_key(jw, key);
    jw_write_escaped(jw, val);
    jw->needs_comma = TRUE;
}

void jw_kv_int(JSON_WRITER* jw, const char* key, long long val) {
    jw_key(jw, key);
    fprintf(jw->fp, "%lld", val);
    jw->needs_comma = TRUE;
}

void jw_kv_bool(JSON_WRITER* jw, const char* key, BOOL val) {
    jw_key(jw, key);
    fprintf(jw->fp, val ? "true" : "false");
    jw->needs_comma = TRUE;
}
