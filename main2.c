#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "uthash.h"

#define MEM_SIZE (256 * 512) // 256 4 byte chunks (instructions) per 1 kibibyte * 256 kibibytes
                               // chunk 256 * 512 (top chunk) = program counter 4096
                               // chunk 255 * 512 (one chunk down) = program counter 4100 and so on

int64_t globalRegisters[32] = {0}; // array of signed 64-bit integers representing register values (should data type be int64?)
uint32_t instructionToPC[MEM_SIZE]; // array of 32 bit integers to hold each instruction index 0 = programCounter 4096, index n = (programCounter - 4096) / 4
int memAddressCounter = 0; // counts total number of instructions for first pass through file
int programCounter = 4096; // counter to keep track of current mem address
int isUserMode = 1; // tracks user mode
int isSupervisorMode = 0; // tracks supervisor mode

void and(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] & globalRegisters[r3];
    return;
}

void or(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] | globalRegisters[r3];
    return;
}

void xor(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] ^ globalRegisters[r3];
    return;
}

void not(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = ~globalRegisters[r2];
    return;
}

void shftr(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] >> globalRegisters[r3];
    return;
}

void shftri(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r1] >> literal;
    return;
}

void shftl(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] << globalRegisters[r3];
    return;
}

void shftli(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r1] << literal;
    return;
}

void br(int r1, int r2, int r3, int literal) {
    programCounter = globalRegisters[r1];
    return;
}

void brr1(int r1, int r2, int r3, int literal) {
    programCounter += globalRegisters[r1];
    return;
}

void brr2(int r1, int r2, int r3, int literal) {
    programCounter += literal;
    return;
}

void brnz(int r1, int r2, int r3, int literal) {
    if (globalRegisters[r2] == 0) {
        programCounter += 4;
    }
    else {
        programCounter = globalRegisters[r1];
    }
    return;
}

void call(int r1, int r2, int r3, int literal){
    if (globalRegisters[31] - 8 < 4096) {
        fprintf(stderr, "Stack Overflow Error");
        exit(-1);
    }
    instructionToPC[globalRegisters[31] - 2] = instructionToPC[(programCounter + 4 - 4096) / 4];
    programCounter = globalRegisters[r1];
    return;
}

void tinkerReturn(int r1, int r2, int r3, int literal){
    programCounter = instructionToPC[globalRegisters[31] - 2];
}

void brgt(int r1, int r2, int r3, int literal) {
    if (globalRegisters[r2] <= globalRegisters[r3]) {
        programCounter += 4;
    }
    else {
        programCounter = globalRegisters[r1];
    }
    return;
}

void priv(int r1, int r2, int r3, int literal) {
    char inputBuffer[64];
    uint64_t input;
    if (literal == 1) {
        isSupervisorMode = 1;
        isUserMode = 0;
    }
    else if (literal == 2) {
        isUserMode = 1;
        isSupervisorMode = 0;
    }
    else if (literal == 3) {
        if (globalRegisters[r2] == 0) {
            if (fgets(inputBuffer, sizeof(inputBuffer), stdin) == NULL) {
                fprintf(stderr, "ERROR READING FROM INPUT");
                exit(-1);
            } 
            if (sscanf(inputBuffer, "%lu", &input) != 1) {
                fprintf(stderr, "Invalid Input");
                exit(-1);
            }
            globalRegisters[r1] = input;
        }
        globalRegisters[r1] = globalRegisters[r2];
    }
    else if (literal == 4) {
        if (globalRegisters[r1] == 1) {
            printf("%lu", globalRegisters[r2]);
        }
    }
    else {
        printf("Illegal Literal Passed With Priv Opcode");
        exit(-1);
    }
    return;
}

void mov1(int r1, int r2, int r3, int literal) {
    //globalRegisters[r1] = instructionToPC[];
    return;
}

void mov2(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2]; 
    return;
}

void mov3(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] &= ~(((1ULL << 12) - 1) << 52);
    globalRegisters[r1] |= (literal << 52);
    return;
}

void mov4(int r1, int r2, int r3, int literal) {
    // implement this
    return;
}

void addf(int r1, int r2, int r3, int literal) {
    double sum = (double)(globalRegisters[r2]) + (double)(globalRegisters[r3]);
    globalRegisters[r1] = (int64_t)(sum);
    return;
}

void subf(int r1, int r2, int r3, int literal) {
    double difference = (double)(globalRegisters[r2]) - (double)(globalRegisters[r3]);
    globalRegisters[r1] = (int64_t)(difference);
    return;
}

void mulf(int r1, int r2, int r3, int literal) {
    double product = (double)(globalRegisters[r2]) * (double)(globalRegisters[r3]);
    globalRegisters[r1] = (int64_t)(product);
    return;
}

void divf(int r1, int r2, int r3, int literal) {
    double quotient = (double)(globalRegisters[r2]) - (double)(globalRegisters[r3]);
    globalRegisters[r1] = (int64_t)(quotient);
    return;
}

void add(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] + globalRegisters[r3];
    return;
}

void addi(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] += literal;
    return;
}

void sub(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = globalRegisters[r2] - globalRegisters[r3];
    return;
}

void subi(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] -= literal;
    return;
}

void mul(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = (int64_t)(globalRegisters[r2] * globalRegisters[r3]);
    return;
}

void div(int r1, int r2, int r3, int literal) {
    globalRegisters[r1] = (int64_t)(globalRegisters[r2] / globalRegisters[r3]);
    return;
}

typedef void (*Instruction)(int r1, int r2, int r3, int literal);
Instruction globalInstructionArray[30] = {and, or, xor, not, shftr, shftri, 
                                        shftl, shftli, br, brr1, brr2, brnz, 
                                        call, tinkerReturn, brgt, priv, mov1, mov2, 
                                        mov3, mov4, addf, subf, mulf, divf, add,
                                        addi, sub, subi, mul, div}; // array of function pointers to be called when parsing

// builds initial memory array from file
void buildFromFile(const char* fileName, uint32_t instructionToPC[]) {
    FILE *file = fopen(fileName, "rb");
    if (file == NULL) {
            fprintf(stderr, "Error Opening Binary File");
            return;
    }
    unsigned char fourByteBuffer[4] = {0};
    while (fread(fourByteBuffer, 1, 4, file)) {
        uint32_t bigEndianVal = (fourByteBuffer[3] << 24) |
                                (fourByteBuffer[2] << 16) | 
                                (fourByteBuffer[1] << 8) | 
                                (fourByteBuffer[0]);
        if (((bigEndianVal >> 27) == 15) && ((bigEndianVal << 27) == 0)) {
            instructionToPC[memAddressCounter] = bigEndianVal;
            memAddressCounter++;
            globalRegisters[31] = (int64_t)(MEM_SIZE - 1);
            return;
        }
        instructionToPC[memAddressCounter] = bigEndianVal;
        memAddressCounter++;
        if (memAddressCounter >= MEM_SIZE) {
            fprintf(stderr, "ERROR: BINARY FILE TOO LARGE");
            return;
        } 
    }
    globalRegisters[31] = (int64_t)(MEM_SIZE - 1); // initialize stack pointer to last (top) index
    fclose(file);
}

void parseBigEndian(uint32_t instruction, int *opcode, int *r1, int *r2, int *r3, int *literal) {
    *opcode = (0b1111100000000000000000000000000 & instruction) >> 27;
    printf("OPCODE: %d\n", *opcode);
    *r1 = (0b00000111110000000000000000000000 & instruction) >> 22;
    printf("R1: %d\n", *r1);
    *r2 = (0b00000000001111100000000000000000 & instruction) >> 17;
    printf("R2: %d\n", *r2);
    *r3 = (0b00000000000000011111000000000000 & instruction) >> 12; 
    printf("R3: %d\n", *r3);
    *literal = (0b00000000000000000000111111111111 & instruction); 
    printf("LITERAL: %d\n", *literal);
    return;
}

void parseFromStack(uint32_t instructionToPC[]) {
    int *opcode = malloc(sizeof(int));
    int *r1 = malloc(sizeof(int));
    int *r2 = malloc(sizeof(int));
    int *r3 = malloc(sizeof(int));
    int *literal = malloc(sizeof(int));
    int reachedHalt = 0;
    while (!reachedHalt) {
        int i = ((programCounter - 4096) / 4);
        parseBigEndian(instructionToPC[i], *opcode, *r1, *r2, *r3, *literal);
        if (opcode == 15 && literal == 0) {
            reachedHalt = 1; 
        }
        globalInstructionArray[*opcode](r1, r2, r3, literal); 
        programCounter += 4;
    }
    return;
}