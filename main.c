#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_HASH_BUCKETS 100

typedef struct HashNode {
    char key[50];
    char value[100];
    struct HashNode *next;
} HashNode;

typedef struct {
    HashNode *buckets[NUM_HASH_BUCKETS];
} HashMap;

unsigned int hashFunction(const char *key) {
    unsigned long hash = 5381;
    int c;
    while (c = *key++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % NUM_HASH_BUCKETS;
}

void initializeHashMap(HashMap *map) {
    for (int i = 0; i < NUM_HASH_BUCKETS; i++) {
        map->buckets[i] = NULL;
    } 
}

void hashMapInsert(HashMap *map, const char *key, const char *value) {
    unsigned int index = hashFunction(key);
    HashNode *node = map->buckets[index];

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            strcpy(node->value, value);
            return;
        }
        node = node->next;
    }

    node = (HashNode *)malloc(sizeof(HashNode));
    if (!node) {
        fprintf(stderr, "Node Mem Allocation Failed");
        return;
    }
    strcpy(node->key, key);
    strcpy(node->value, value);
    node->next = map->buckets[index];
    map->buckets[index] = node;

}

void hashMapDelete(HashMap *map, const char *key) {
    unsigned int index = hashFunction(key);
    HashNode *node = map->buckets[index];
    HashNode *prev = NULL;

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            if (prev == NULL) {
                map->buckets[index] = node->next;
            }
            else {
                prev->next = node->next;
            }
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

char *hashMapSearch(HashMap *map, const char *key) {
    unsigned int index = hashFunction(key);
    HashNode *node = map->buckets[index];

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            return node->value;  // Return found value
        }
        node = node->next;
    }
    return NULL;  // Not found
}

void hashMapFree(HashMap *map) {
    for (int i = 0; i < NUM_HASH_BUCKETS; i++) {
        HashNode *node = map->buckets[i];
        while (node != NULL) {
            HashNode *temp = node;
            node = node->next;
            free(temp); 
        }
        map->buckets[i] = NULL;
    }
}

size_t getFileSize(FILE *file) {
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size > 0 ? size : 1024;
}

typedef struct {
    char *mnemonic;
    char *operandTypes;
} InstructionFormat;

const InstructionFormat validFormats[] = {
    {"add", "RRR"},  {"addi", "RI"},  {"sub", "RRR"},  {"subi", "RI"},  {"mul", "RRR"},  {"div", "RRR"}, 
    {"and", "RRR"},  {"or", "RRR"},  {"xor", "RRR"},  {"not", "RR"},  {"shftr", "RRR"},  {"shftri", "RI"},  
    {"shftl", "RRR"},  {"shftli", "RI"},  {"br", "R"},  {"brr", "R"},  {"brr", "I"},  {"brnz", "RR"}, 
    {"call", "RRR"},  {"return", ""},  {"brgt", "RRR"},  {"priv", "RRRI"},  {"addf", "RRR"},  {"subf", "RRR"}, 
    {"mulf", "RRR"},  {"divf", "RRR"},  {"in", "RR"},  {"out", "RR"},  {"clr", "R"},  {"ld", "RI"},  {"push", "R"},  {"pop", "R"},
    {"halt", ""} 
};

const int numInstructions = sizeof(validFormats)/sizeof(validFormats[0]);

const char *getOperandFormat(const char *opcode) {
    for (int i = 0; i < numInstructions; i++) {
        if (strcmp(opcode, validFormats[i].mnemonic) == 0) {
            return validFormats[i].operandTypes;
        }
    }
    return NULL;
}

int isValidRegister(const char *operand) {
    if (operand[0] != 'r') return 0;
    char *endPtr;
    long regNum = strtol(operand + 1, &endPtr, 10);
    if (*endPtr != '\0') return 0;
    if (regNum < 0 || regNum > 31) return 0;
    return 1;
}

int isValidImmediate(const char *operand) {
    char *endPtr;
    long value = strtol(operand, &endPtr, 10);
    if (*endPtr != '\0') return 0;
    if (value < 0 || value > 65535) return 0;
    return 1;
}

char *parseFile(const char *fileName) {
    FILE *inputFile = fopen(fileName, "r");
    if (!inputFile) {
        perror("Error opening file");
        return NULL;
    }

    size_t bufferSize = (size_t)(getFileSize(inputFile) * 1.5);
    char *outputBuffer = (char*)malloc(bufferSize);
    if (!outputBuffer) {
        perror("Error allocating output buffer");
        fclose(inputFile);
        return NULL;
    }

    outputBuffer[0] = '\0';
    char line[256];
    int isData = 0, isCode = 0;
    size_t outputLength = 0;
    int memLabelCounter = 4096;
    HashMap labelMap;
    initializeHashMap(&labelMap);

    while (fgets(line, sizeof(line), inputFile)) {
        char *trimmed = line;
        
        // Skip blank lines
        while (*trimmed == ' ' || *trimmed == '\t') {
            trimmed++;
        }
        if (*trimmed == '\0' || *trimmed == '\n') {
            continue;
        }

        // Skip comments
        if (*trimmed == ';') {
            continue;
        }

        // .data and .code section
        if (*trimmed == '.') {
            if (strcmp(trimmed, ".data\n") == 0) {
                isData = 1;
                isCode = 0;
            } else if (strcmp(trimmed, ".code\n") == 0) {
                isData = 0;
                isCode = 1;
            } else {
                perror("Error: . must be followed by code or data");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            strncat(outputBuffer, trimmed, bufferSize - outputLength - 1);
            outputLength += strlen(trimmed);
            continue;
        }

        // Labels (e.g., :DATA1)
        if (*trimmed == ':') {
            char label[50];
            char memAddressString[20];

            if (sscanf(trimmed, ":%49s", label) != 1) {
                perror("Error: Invalid label format");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }

            if (!isCode && !isData) {
                perror("Error: Label must be inside .code or .data");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }

            if (!hashMapSearch(&labelMap, label)) {
                snprintf(memAddressString, sizeof(memAddressString), "%d", memLabelCounter);
                hashMapInsert(&labelMap, label, memAddressString);
                memLabelCounter += (isCode) ? 4 : 8;
            }

            snprintf(outputBuffer + outputLength, bufferSize - outputLength, ":%s %s\n", label, memAddressString);
            outputLength += strlen(label) + strlen(memAddressString) + 4;
            continue;
        }

        // Instruction Processing (Must be inside .code)
        if (!isCode) {
            perror("Error: Instructions must be inside .code section");
            free(outputBuffer);
            fclose(inputFile);
            return NULL;
        }

        // Extract opcode and operands
        char opcode[20] = {0};
        char operands[100] = {0};
        sscanf(trimmed, "%19s %99[^\n]", opcode, operands);

        if (strlen(opcode) == 0) {
            perror("Error: Missing opcode");
            free(outputBuffer);
            fclose(inputFile);
            return NULL;
        }

        // Validate Opcode
        const char *expectedOperands = getOperandFormat(opcode);
        if (!expectedOperands) {
            fprintf(stderr, "Error: Invalid instruction: %s\n", opcode);
            free(outputBuffer);
            fclose(inputFile);
            return NULL;
        }

        // Validate Operands
        int opIndex = 0;
        char *token = strtok(operands, ",");
        while (token) {
            while (*token == ' ') {
                token++;
            }
            if (expectedOperands[opIndex] == 'R' && !isValidRegister(token)) {
                fprintf(stderr, "Error: Expected a register but got %s\n", token);
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            if (expectedOperands[opIndex] == 'I' && !isValidImmediate(token)) {
                fprintf(stderr, "Error: Expected an immediate but got %s\n", token);
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            opIndex++;
            token = strtok(NULL, ",");
        }
        if (opIndex != strlen(expectedOperands)) {
            fprintf(stderr, "Error: Incorrect number of operands for %s\n", opcode);
            free(outputBuffer);
            fclose(inputFile);
            return NULL;
        }

        // Expand Macros
        char expanded[256] = "";
        if (strcmp(opcode, "clr") == 0) {
            snprintf(expanded, sizeof(expanded), "\txor %s, %s, %s\n", operands, operands, operands);
        } else if (strcmp(opcode, "push") == 0) {
            snprintf(expanded, sizeof(expanded), "\tmov (r31)(-8), %s\n\tsubi r31, 8\n", operands);
        } else if (strcmp(opcode, "pop") == 0) {
            snprintf(expanded, sizeof(expanded), "\tmov %s, (r31)(0)\n\taddi r31, 8\n", operands);
        } else if (strcmp(opcode, "in") == 0) {
            snprintf(expanded, sizeof(expanded), "\tpriv %s, %s, r0, 3\n", operands, operands);
        } else if (strcmp(opcode, "out") == 0) {
            snprintf(expanded, sizeof(expanded), "\tpriv %s, %s, r0, 0\n", operands, operands);
        } else if (strcmp(opcode, "halt") == 0) {
            snprintf(expanded, sizeof(expanded), "\tpriv r0, r0, r0, 0\n");
        } else {
            snprintf(expanded, sizeof(expanded), "%s", trimmed);
        }

        // Append to output buffer
        size_t lineLength = strlen(expanded) + 1;
        if (outputLength + lineLength >= bufferSize) {
            bufferSize *= 2;
            char *temp = realloc(outputBuffer, bufferSize);
            if (!temp) {
                perror("Error reallocating output buffer");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            outputBuffer = temp;
        }
        strcat(outputBuffer, expanded);
        outputLength += strlen(expanded);
    }

    fclose(inputFile);
    return outputBuffer;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *outputBuffer = parseFile(argv[1]);  // Pass file name
    if (!outputBuffer) {
        fprintf(stderr, "Error processing file.\n");
        return EXIT_FAILURE;
    }

    FILE *outputFile = fopen(argv[2], "w");
    if (!outputFile) {
        perror("Error opening output file");
        free(outputBuffer);
        return EXIT_FAILURE;
    }

    fprintf(outputFile, "%s", outputBuffer);
    fclose(outputFile);
    free(outputBuffer);

    printf("Assembly successfully written to %s\n", argv[2]);
    return EXIT_SUCCESS;
}



