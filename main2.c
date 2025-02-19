#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "uthash.h"


int64_t *globalRegisters[32] = {0};
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
    globalInstructionArray[*opcode](r1, r2, r3, literal);
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

void brr2(int r1, int r2, int r3, int literal) {
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

void call(int r1, int r2, int r3, int literal){
    // implement here
}

void returN(int r1, int r2, int r3, int literal){
    // implement here 
}

void brgt(int r1, int r2, int r3, int literal) {
    if (*globalRegisters[r2] <= *globalRegisters[r3]) {
        *programCounter += 4;
    }
    else {
        *programCounter = *globalRegisters[r1];
    }
    return;
}

void priv(int r1, int r2, int r3, int literal) {
    // not sure if 0x0 refers to decimal 0 or memory address 4096
    if (literal == 0) {
        printf("Halt Instruction Reached");
        return;
    }
    else if (literal == 1) {
        // implement this
    }
    else if (literal == 2) {
        // implement this
    }
    else if (literal == 3) {
        *globalRegisters[r1] = *globalRegisters[r2];
        return;
    }
    else if (literal = 4) {
        // implement this
    }
    else {
        printf("Illegal Literal Passed With Priv Opcode");
    }
}

void mov1(int r1, int r2, int r3, int literal) {
    // implement this
}

void mov2(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2]; 
    return;
}

void mov3(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] &= ~(((1ULL << 12) - 1) << 52);
    *globalRegisters[r1] |= (literal << 52);
    return;
}

void mov4(int r1, int r2, int r3, int literal) {
    // implement this
}

void addf(int r1, int r2, int r3, int literal) {
    double sum = (double)(*globalRegisters[r2]) + (double)(*globalRegisters[r3]);
    *globalRegisters[r1] = (int64_t)(sum);
    // not sure if this is how we should handle floating arithmetic
    return;
}

void subf(int r1, int r2, int r3, int literal) {
    double difference = (double)(*globalRegisters[r2]) - (double)(*globalRegisters[r3]);
    *globalRegisters[r1] = (int64_t)(difference);
    return;
    // not sure if this is how we should handle floating arithmetic
}

void mulf(int r1, int r2, int r3, int literal) {
    double product = (double)(*globalRegisters[r2]) * (double)(*globalRegisters[r3]);
    *globalRegisters[r1] = (int64_t)(product);
    return;
    // not sure if this is how we should handle floating arithmetic
}

void divf(int r1, int r2, int r3, int literal) {
    double quotient = (double)(*globalRegisters[r2]) - (double)(*globalRegisters[r3]);
    *globalRegisters[r1] = (int64_t)(quotient);
    return;
    // not sure if this is how we should handle floating arithmetic
}

void add(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] + *globalRegisters[r3];
    return;
}

void addi(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] += literal;
    return;
}

void sub(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = *globalRegisters[r2] - *globalRegisters[r3];
    return;
}

void subi(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] -= literal;
    return;
}

void mul(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = (int64_t)(*globalRegisters[r2] * *globalRegisters[r3]);
    return;
}

void div(int r1, int r2, int r3, int literal) {
    *globalRegisters[r1] = (int64_t)(*globalRegisters[r2] / *globalRegisters[r3]);
    return;
}

typedef void (*Instruction)(int r1, int r2, int r3, int literal);

Instruction globalInstructionArray[30] = {and, or, xor, not, shftr, shftri, 
                                        shftl, shftli, br, brr1, brr2, brnz, 
                                        call, returN, brgt, priv, mov1, mov2, 
                                        mov3, mov4, addf, subf, mulf, divf, add,
                                        addi, sub, subi, mul, div};

