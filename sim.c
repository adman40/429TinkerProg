#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MEM_SIZE (1024 * 512) // 256 4 byte chunks (instructions) per 1 kibibyte * 256 kibibytes
                               // chunk 256 * 512 (top chunk) = program counter 4096
                               // chunk 255 * 512 (one chunk down) = program counter 4100 and so on

uint64_t tinkerRegs[32] = {0}; // array of signed 64-bit integers representing register values (should data type be int64?)
uint8_t memArray[MEM_SIZE]; // array of 32 bit integers to hold each instruction index 0 = programCounter 4096, index n = (programCounter - 4096) / 4
int isUserMode = 1; // tracks user mode
int isSupervisorMode = 0; // tracks supervisor mode
uint64_t programCounter; // needs to be set by header
uint64_t initialPC;

int16_t extendLiteral(uint16_t literal) {
    return (int16_t)((literal & 0x0800) ? (literal | 0xF000) : literal);
}

void and(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] & tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void or(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] | tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void xor(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] ^ tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void not(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = ~tinkerRegs[r2];
    *programCounter += 4;
    return;
}

void shftr(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] >> tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void shftri(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r1] >> literal;
    *programCounter += 4;
    return;
}

void shftl(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] << tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void shftli(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r1] << literal;
    *programCounter += 4;
    return;
}

void br(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    *programCounter = tinkerRegs[r1];
    return;
}

void brr1(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
   *programCounter += tinkerRegs[r1];
    return;
}

void brr2(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    int16_t newLiteral = extendLiteral(literal);
    *programCounter += newLiteral;
    return;
}

void brnz(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    if (tinkerRegs[r2] != 0) {
        *programCounter = tinkerRegs[r1];
    }
    else {
        *programCounter += 4;
    }
    return;
}

void call(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter){
    if (tinkerRegs[31] - 8 < initialPC) {
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    *(uint64_t *)(&memArray[tinkerRegs[31] - 8]) = *programCounter + 4;
    *programCounter = tinkerRegs[r1];
    return;
}

void tinkerReturn(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter){
    if (tinkerRegs[31] - 8 < initialPC) {
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    *programCounter = *(uint64_t *)(&memArray[tinkerRegs[31] - 8]);
    return;
}

void brgt(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    if (tinkerRegs[r2] <= tinkerRegs[r3]) {
        *programCounter += 4;
    }
    else {
        *programCounter = tinkerRegs[r1];
    }
    return;
}

void priv(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    char inputBuffer[64];
    uint64_t input;
    if (literal == 0) {
        exit(0);
    }
    if (literal == 1) {
        isSupervisorMode = 1;
        isUserMode = 0;
        *programCounter += 4;
    }
    else if (literal == 2) {
        isUserMode = 1;
        isSupervisorMode = 0;
        *programCounter += 4;
    }
    else if (literal == 3) {
        if (tinkerRegs[r2] == 0) {
            if (fgets(inputBuffer, sizeof(inputBuffer), stdin) == NULL) {
                fprintf(stderr, "Simulation error");
                exit(-1);
            } 
            if (sscanf(inputBuffer, "%lu", &input) != 1) {
                fprintf(stderr, "Simulation error");
                exit(-1);
            }
            tinkerRegs[r1] = input;
        }
        *programCounter += 4;
    }
    else if (literal == 4) {
        if (tinkerRegs[r1] == 1) {
    printf("%lu", tinkerRegs[r2]);
} 
        *programCounter += 4;
    }
    else {
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    return;
}

void mov1(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    int16_t newLiteral = extendLiteral(literal);
    int64_t address = tinkerRegs[r2] + newLiteral;
    if (address < 0 || address + 8 > MEM_SIZE) { 
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    tinkerRegs[r1] = *(uint64_t *)(&memArray[address]); 
    *programCounter += 4;
    return;
}

void mov2(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2]; 
    *programCounter += 4;
    return;
}

void mov3(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = (tinkerRegs[r1] & ~0xFFFULL) | literal;
    *programCounter += 4;
    return;
}

void mov4(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    int16_t newLiteral = extendLiteral(literal);
    int64_t address = (int64_t)(tinkerRegs[r1] + newLiteral);
    if (address < 0 || address + 8 > MEM_SIZE) { 
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    *(uint64_t *)(&memArray[address]) = tinkerRegs[r2];
    *programCounter += 4;
    return;
}

void addf(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    double in1, in2, result;
    memcpy(&in1, &tinkerRegs[r2], sizeof(double));
    memcpy(&in2, &tinkerRegs[r3], sizeof(double));
    result = in1 + in2;
    uint64_t resultOut;
    memcpy(&resultOut, &result, sizeof(double)); 
    tinkerRegs[r1] = resultOut;
    *programCounter += 4;
    return;
}

void subf(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    double in1, in2, result;
    memcpy(&in1, &tinkerRegs[r2], sizeof(double));
    memcpy(&in2, &tinkerRegs[r3], sizeof(double));
    result = in1 - in2;
    uint64_t resultOut;
    memcpy(&resultOut, &result, sizeof(double)); 
    tinkerRegs[r1] = resultOut;
    *programCounter += 4;
    return;
}

void mulf(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    double in1, in2, result;
    memcpy(&in1, &tinkerRegs[r2], sizeof(double));
    memcpy(&in2, &tinkerRegs[r3], sizeof(double));
    result = in1 * in2;
    uint64_t resultOut;
    memcpy(&resultOut, &result, sizeof(double)); 
    tinkerRegs[r1] = resultOut;
    *programCounter += 4;
    return;
}

void divf(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    double in1, in2, result;
    memcpy(&in1, &tinkerRegs[r2], sizeof(double));
    memcpy(&in2, &tinkerRegs[r3], sizeof(double));
    if (in2 == 0.0) {
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    result = in1 / in2;
    uint64_t resultOut;
    memcpy(&resultOut, &result, sizeof(double)); 
    tinkerRegs[r1] = resultOut;
    *programCounter += 4;
    return;
}

void add(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] + tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void addi(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] += literal;
    *programCounter += 4;
    return;
}

void sub(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = tinkerRegs[r2] - tinkerRegs[r3];
    *programCounter += 4;
    return;
}

void subi(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] -= literal;
    *programCounter += 4;
    return;
}

void mul(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    tinkerRegs[r1] = (int64_t)(tinkerRegs[r2] * tinkerRegs[r3]);
    *programCounter += 4;
    return;
}

void tinkerDiv(int r1, int r2, int r3, uint16_t literal, uint64_t *programCounter) {
    if (tinkerRegs[r3] == 0) {
        fprintf(stderr, "Simulation error");
        exit(-1);
    }
    tinkerRegs[r1] = (int64_t)(tinkerRegs[r2] / tinkerRegs[r3]);
    *programCounter += 4;
    return;
}

struct tinkerHeader {
    uint32_t fileType;       // Expected to be 0
    uint32_t codeSegBegin;  // For this exercise: 0x2000
    uint32_t codeSegSize;
    uint32_t dataSegBegin;  // For this exercise: 0x10000
    uint32_t dataSegSize;
};

typedef void (*Instruction)(int r1, int r2, int r3, uint16_t literal, uint64_t *);
Instruction globalInstructionArray[30] = {and, or, xor, not, shftr, shftri, 
                                        shftl, shftli, br, brr1, brr2, brnz, 
                                        call, tinkerReturn, brgt, priv, mov1, mov2, 
                                        mov3, mov4, addf, subf, mulf, divf, add,
                                        addi, sub, subi, mul, tinkerDiv}; // array of function pointers to be called when parsing

// builds initial memory array from file
void buildFromFile(const char* fileName, uint8_t memArray[]) {
    FILE *file = fopen(fileName, "rb");
    if (file == NULL) {
            fprintf(stderr, "Invalid tinker filepath\n");
            exit(-1);
    }
    memset(memArray, 0, 512 * 1024);
    struct tinkerHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        fprintf(stderr, "Error reading file header\n");
        exit(-1);
    }
    if (header.fileType != 0) {
        fprintf(stderr, "Invalid file type in header\n");
        exit(-1);
    }
    if (header.codeSegBegin + header.codeSegSize > MEM_SIZE || header.dataSegBegin + header.dataSegSize > MEM_SIZE) {
        fprintf(stderr, "Simulation error: segment exceeds memory bounds\n");
        exit(-1);
    }
    initialPC = (uint64_t) header.codeSegBegin;
    programCounter = (uint64_t) header.codeSegBegin;
    for (long i = 0; i < header.codeSegSize; i+=4) {
        uint32_t instruction;
        size_t read = fread(&instruction, 1, 4, file);
        if (read != 4) {
            fprintf(stderr, "Simulation error");
            exit(-1);
        }
        *(uint32_t *)(&memArray[header.codeSegBegin + i]) = instruction; 
    }
    for (uint64_t i = 0; i < header.dataSegSize; i += 8) {
        uint64_t data;
        size_t read = fread(&data, 1, 8, file);
        if (read != 8) {
            fprintf(stderr, "Simulation error");
            exit(-1);
        }
        *(uint64_t *)(&memArray[header.dataSegBegin + i]) = data;
    }
    tinkerRegs[31] = MEM_SIZE;
    fclose(file);
}

void parseFromStack(uint8_t memArray[]) {
    int opcode, r1, r2, r3; 
    uint16_t literal;
    int reachedHalt = 0;
    uint32_t instruction;
    while (!reachedHalt) {
        if (programCounter > MEM_SIZE) {
            fprintf(stderr, "Simulation error");
            exit(-1);
        }
        instruction = *(uint32_t *)(&memArray[programCounter]);
        opcode = 0x1F & (instruction >> 27);
        r1 = 0x1F & (instruction >> 22);
        r2 = 0x1F & (instruction >> 17);
        r3 = 0x1F & (instruction >> 12); 
        literal = 0xFFF & instruction;  
        globalInstructionArray[opcode](r1, r2, r3, literal, &programCounter); 
    }
    return;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Invalid tinker filepath");
        return EXIT_FAILURE;
    }
    memset(memArray, 0, sizeof(memArray));
    buildFromFile(argv[1], memArray);
    parseFromStack(memArray);
    return EXIT_SUCCESS;
} 