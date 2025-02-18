#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "uthash.h"

.void parseBinary (const char* fileName) {
    FILE *file = fopen(fileName, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error Opening Binary File");
        return;
    }
    unsigned char fourByteBuffer[4];
    unsigned char bigEndianBuffer[4];
    size_t bytesRead = fread(fourByteBuffer, 1, 4, file);
    for (int i = 0; i < 4; i++) {
        bigEndianBuffer[i] = fourByteBuffer[3 - i];
    }

} 