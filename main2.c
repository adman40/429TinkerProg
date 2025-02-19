#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "uthash.h"


int *globalRegisters[32];
int *programCounter = 4096;
// global array of function pointers45

void parseBinary (const char* fileName) {
    FILE *file = fopen(fileName, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error Opening Binary File");
        return;
    }
    unsigned char fourByteBuffer[4];
    unsigned char bigEndianBuffer[4];
    size_t bytesRead = fread(fourByteBuffer, 1, 4, file);
    for (int i = 0; i < 4; i++) {
        bigEndianBuffer[i] = fourByteBuffer[3 - i];
    }
    int *opcode, *r1, *r2, *r3, *literal;
    parseBigEndian(bigEndianBuffer, opcode, r1, r2, r3, literal);
    functionArray[opcode]
} 

// 5 opcode // 5 reg // 5 reg // 5reg // 12 literal

void parseBigEndian(unsigned char bigEndianBuffer[], int *opcode, int *r1, int *r2, int *r3, int *literal) {
    opcode = 31 & (bigEndianBuffer[0] >> 3);
    printf("OPCODE: %d\n", opcode);
    r1 = ((7 & bigEndianBuffer[0]) << 2) | ((bigEndianBuffer[1] >> 6) & 3);
    printf("R1: %d\n", r1);
    r2 = 31 & (bigEndianBuffer[1] >> 1);
    printf("R2: %d\n", r2);
    r3 = ((bigEndianBuffer[1] & 1) << 4) | ((bigEndianBuffer[2] >> 4) & 15);
    printf("R3: %d\n", r3);
    literal = (((bigEndianBuffer[2]) & 15) << 8 ) | (bigEndianBuffer[3]);
    printf("LITERAL: %d\n", literal);
    return;
}

void and(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] & *globalRegisters[r3];
    return;
}

void or(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] | *globalRegisters[r3];
    return;
}

void xor(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] ^ *globalRegisters[r3];
    return;
}

void not(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = ~*globalRegisters[r2];
    return;
}

void shftr(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] >> *globalRegisters[r3];
    return;
}

void shftri(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r1] >> literal;
    return;
}

void shftl(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] << *globalRegisters[r3];
    return;
}

void shftli(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r1] << literal;
    return;
}

void br(int r1, int r2, int r3, int literal) {
    *programCounter = *globalRegisters[r1];
    return;
}

void brr1(int r1, int r2, int r3, int literal) {
    *programCounter += *globalRegisters[r1];
    return;
}

void brrL(int r1, int r2, int r3, int literal) {
    *programCounter += literal;
    return;
}

void brnz(int r1, int r2, int r3, int literal) {
    if (*globalRegisters[r2] == 0) {
        *programCounter += 4;
    }
    else {
        *programCounter = *globalRegisters[r1];
    }
    return;
}

