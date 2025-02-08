#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define NUM_HASH_BUCKETS 100

typedef enum {
    NONE, 
    CODE, 
    DATA
} SectionType;

SectionType lastSection = NONE;

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
            return node->value;  
        }
        node = node->next;
    }
    return NULL;
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
    {"call", "R"},  {"return", ""},  {"brgt", "RRR"},  {"priv", "RRRI"},  {"addf", "RRR"},  {"subf", "RRR"}, 
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
    if (!operand || *operand == '\0') return 0;
    if (operand[0] == '-') return 0;
    if (operand[0] == ':') {
        if (strlen(operand) > 1) return 1;
        return 0;
    }
    char *endPtr;
    uint64_t value = strtoull(operand, &endPtr, 0);
    if (*endPtr != '\0') return 0;
    return 1;
}

void trimWhitespace(char *str) {
    if (!str) return;
    int len = strlen(str);
    int start = 0;
    while (str[start] && isspace((unsigned char)str[start])) {
        start++;
    }
    int end = len - 1;
    while (end >= start && isspace((unsigned char)str[end])) {
        end--;
    }
    int i, j = 0;
    for (i = start; i <= end; i++) {
        str[j++] = str[i];
    }
    str[j] = '\0';
}

void collectLabels(const char *fileName, HashMap *labelMap) {
    FILE *inputFile = fopen(fileName, "r");
    if (!inputFile) {
        fprintf(stderr, "Error opening file");
        return;
    }

    char line[256];
    int programCounter = 4096;
    int inCode = 0, inData = 0;

    while (fgets(line, sizeof(line), inputFile)) {
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') {
            trimmed++;
        }
        if (trimmed[0] == ';' || trimmed[0] == '\n' || trimmed[0] == '\0')
            continue;
        if (trimmed[0] == '.') {
            if (strncmp(trimmed, ".data", 5) == 0) {
                inData = 1;
                inCode = 0;
            } else if (strncmp(trimmed, ".code", 5) == 0) {
                inCode = 1;
                inData = 0;
            }
            continue;
        }
        if (trimmed[0] == ':') {
            char label[50];
            sscanf(trimmed, "%49s", label);
            trimWhitespace(label);
            if (hashMapSearch(labelMap, label) == NULL) {
                char addressStr[20];
                snprintf(addressStr, sizeof(addressStr), "%d", programCounter);
                hashMapInsert(labelMap, label, addressStr);
                printf("Collected label: '%s' -> address: '%s'\n", label, addressStr);
            } else {
                fprintf(stderr, "Error: Duplicate label %s\n", label);
            }
            continue;
        }
        if (inCode) {
            char opcode[20];
            if (sscanf(line, "\t%19s", opcode) != 1) {
                fprintf(stderr, "Error parsing instruction: %s\n", line);
                continue;
            }
            if (strcmp(opcode, "ld") == 0) {
                programCounter += 48;
            } else if (strcmp(opcode, "push") == 0 || strcmp(opcode, "pop") == 0) {
                programCounter += 8;
            } else {
                programCounter += 4;
            }
        }
        else if (inData) {
            programCounter += 8;
        }
    }

    fclose(inputFile);
}

void replaceMemoryAddresses(char *operands, HashMap *labelMap) {
    char newOperands[100] = {0};
    int firstToken = 1;
    char temp[100];
    strncpy(temp, operands, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';
    char *token = strtok(temp, ",");
    while (token != NULL) {
        while (*token && isspace((unsigned char)*token))
            token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }
        char processedToken[50] = {0};
        if (token[0] == ':') {
            char *lookup = hashMapSearch(labelMap, token);
            if (lookup != NULL) {
                strncpy(processedToken, lookup, sizeof(processedToken)-1);
            } else {
                strncpy(processedToken, token, sizeof(processedToken)-1);
            }
        } else {
            strncpy(processedToken, token, sizeof(processedToken)-1);
        }
        if (!firstToken)
            strncat(newOperands, ", ", sizeof(newOperands) - strlen(newOperands) - 1);
        strncat(newOperands, processedToken, sizeof(newOperands) - strlen(newOperands) - 1);
        firstToken = 0;
        token = strtok(NULL, ",");
    }
    strncpy(operands, newOperands, 100);
    operands[99] = '\0';
}

char *parseFile(const char *fileName) {
    FILE *inputFile = fopen(fileName, "r");
    if (!inputFile) {
        fprintf(stderr, "Error opening file");
        return NULL;
    }
    size_t bufferSize = (size_t)(getFileSize(inputFile) * 1.5);
    char *outputBuffer = (char*)malloc(bufferSize);
    if (!outputBuffer) {
        fprintf(stderr, "Error allocating output buffer");
        fclose(inputFile);
        return NULL;
    }
    outputBuffer[0] = '\0';
    char line[256];
    int isData = 0;
    int isCode = 0;
    int codeCounter = 0;
    size_t outputLength = 0;
    int memLabelCounter = 4096;
    HashMap labelMap;
    initializeHashMap(&labelMap);
    collectLabels(fileName, &labelMap);
    while (fgets(line, 255, inputFile)) {
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') { trimmed++; }
        if (trimmed[0] == ';' || trimmed[0] == '\0' || trimmed[0] == '\t' || trimmed[0] == '\n') {
            continue;
        }
        else if (trimmed[0] == '.') {
            if (strncmp(trimmed, ".data", 5) != 0 && strncmp(trimmed, ".code", 5) != 0) {
                fprintf(stderr, "Error . must be followed by code or data");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            SectionType currentSection;
            if (strncmp(trimmed, ".data", 5) == 0) {
                currentSection = DATA;
            }
            else if (strncmp(trimmed, ".code", 5) == 0) {
                currentSection = CODE;
            }
            if (currentSection == lastSection) {
                if (currentSection == DATA) {
                        isData = 1;
                        isCode = 0;
                } else {
                        isData = 0;
                        isCode = 1;
                }
                continue;
            }

            size_t lineLength = strlen(line);
            while (outputLength + lineLength >= bufferSize) {
                bufferSize *= 2;
                char *temp = realloc(outputBuffer, bufferSize);
                if (!temp) {
                    fprintf(stderr, "Error reallocating output buffer");
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                }
            outputBuffer = temp;
            }
            strcat(outputBuffer, line);
            outputLength += lineLength;
            if (strncmp(trimmed, ".data", 5) == 0) {
                isData = 1;
                isCode = 0;
            }
            else if (strncmp(trimmed, ".code", 5) == 0) {
                isData = 0;
                isCode = 1;
            }
            lastSection = currentSection;
        }
        else if (trimmed[0] == ':') {
            continue;
        }
        else {
            if (line[0] != '\t' && strncmp(line, "    ", 4) != 0) {
                fprintf(stderr, "Error instruction line should start with tab");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            if (!isCode && !isData) {
                fprintf(stderr, "Error, instructions/data must follow .code or .data");
                free(outputBuffer);
                fclose(inputFile);
                return NULL;
            }
            if (isData) {
                char *trimmedLine = line;
                while (*trimmedLine == ' ' || *trimmedLine == '\t') {
                    trimmedLine++;
                }

                char *endPtr;
                double num = strtod(trimmedLine, &endPtr);

                while (isspace((unsigned char)*endPtr)) {
                    endPtr++;
                }
                if (*endPtr != '\0' && trimmedLine[0] != ':') {
                    fprintf(stderr, "Error: Data section must contain only numbers.\n");
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                }

                size_t lineLength = strlen(line) + 1;
                while (outputLength + lineLength >= bufferSize) {
                    bufferSize *= 2;
                    char *temp = realloc(outputBuffer, bufferSize);
                    if (!temp) {
                        fprintf(stderr, "Error reallocating output buffer");
                        free(outputBuffer);
                        fclose(inputFile);
                        return NULL;
                    }
                    outputBuffer = temp;
                }
                strcat(outputBuffer, line);
                outputLength += lineLength;
            }
 
            else if (isCode) {
                char *trimmed = line + 1;
                while (*trimmed == ' ') {
                    trimmed++;
                }

                char opcode[20] = {0};
                char operands[100] = {0};
                int matched = sscanf(trimmed, "%19s %99[^\n]", opcode, operands);
                if (matched < 1) {
                    fprintf(stderr, "Error: Could not parse instruction line.\n");
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                } else if (matched == 1) {
                    operands[0] = '\0';
                }
                char originalOperands[100];
                strncpy(originalOperands, operands, sizeof(originalOperands));
                originalOperands[sizeof(originalOperands) - 1] = '\0';
                if (strcmp(opcode, "mov") == 0 || strcmp(opcode, "brr") == 0) {
                    size_t lineLength = strlen(line);
                    while (outputLength + lineLength >= bufferSize) {
                        bufferSize *= 2;
                        char *temp = realloc(outputBuffer, bufferSize);
                        if (!temp) {
                            fprintf(stderr, "Error reallocating output buffer");
                            free(outputBuffer);
                            fclose(inputFile);
                            return NULL;
                        }
                        outputBuffer = temp;
                    }
                    strcat(outputBuffer, line);
                    outputLength += lineLength;
                    continue; 
                }
                char expanded[4096] = {0}; 
                const char *expectedOperands = getOperandFormat(opcode);
                if (!expectedOperands) {
                    fprintf(stderr, "Error: Invalid instruction '%s'.\n", opcode);
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                }
                int opIndex = 0;
                char *token = strtok(operands, ",");
                while (token != NULL) {
                    while (*token == ' ') {
                        token++; 
                    }

                    char *end = token + strlen(token) - 1;
                    while (end > token && (*end == ' ' || *end == '\t')) {
                        *end = '\0'; 
                        end--;
                    }

                    if (expectedOperands[opIndex] == 'R') {
                        if (!isValidRegister(token)) {
                            fprintf(stderr, "Error: Expected a valid register (r0-r31), but got '%s'.\n", token);
                            free(outputBuffer);
                            fclose(inputFile);
                            return NULL;
                        }
                    } 
                    else if (expectedOperands[opIndex] == 'I') {
                        if (!isValidImmediate(token)) {
                            fprintf(stderr, "Error: Expected an immediate value (0-65535), but got '%s'.\n", token);
                            free(outputBuffer);
                            fclose(inputFile);
                            return NULL;
                        }
                    }

                    opIndex++;
                    token = strtok(NULL, ",");
                }

                if (opIndex != strlen(expectedOperands)) {
                    fprintf(stderr, "Error: Incorrect number of operands for instruction '%s'. Expected format: %s\n", opcode, expectedOperands);
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                }

                if (strcmp(opcode, "clr") == 0) {
                    snprintf(expanded, sizeof(expanded), "\txor %s, %s, %s\n", operands, operands, operands);
                }
                else if (strcmp(opcode, "push") == 0) { 
                    snprintf(expanded, sizeof(expanded), "\tmov (r31)(-8), %s\n\tsubi r31, 8\n", operands);
                }
                else if (strcmp(opcode, "pop") == 0) { 
                    snprintf(expanded, sizeof(expanded), "\tmov %s, (r31)(0)\n\taddi r31, 8\n", operands);
                }
                else if (strcmp(opcode, "in") == 0) { 
                    snprintf(expanded, sizeof(expanded), "\tpriv %s, r0, 3\n", originalOperands);
                }
                else if (strcmp(opcode, "out") == 0) { 
                    snprintf(expanded, sizeof(expanded), "\tpriv %s, r0, 4\n", originalOperands);
                }
                else if (strcmp(opcode, "halt") == 0) {
                    snprintf(expanded, sizeof(expanded), "\tpriv r0, r0, r0, 0\n");
                }
                else if (strcmp(opcode, "ld") == 0) {
                    char rd[10] = {0}, label[50] = {0};
                    char *commaPos = strchr(originalOperands, ',');
                    if (!commaPos) {
                        fprintf(stderr, "Error: ld instruction operands must be comma-separated (e.g., ld r1, :D0)\n");
                        free(outputBuffer);
                        fclose(inputFile);
                        return NULL;
                    }

                    size_t rdLength = commaPos - originalOperands;
                    strncpy(rd, originalOperands, rdLength);
                    rd[rdLength] = '\0'; 
                    char *labelStart = commaPos + 1;
                    while (*labelStart == ' ') labelStart++;
                    strncpy(label, labelStart, sizeof(label) - 1);
                    label[sizeof(label) - 1] = '\0';
                    if (!isValidRegister(rd)) {
                        fprintf(stderr, "Error: Invalid destination register '%s' in ld instruction\n", rd);
                        free(outputBuffer);
                        fclose(inputFile);
                        return NULL;
                    }

                    long long address;
                    trimWhitespace(label);
                    if (label[0] == ':') {
                        char *labelAddressPtr = hashMapSearch(&labelMap, label);
                        if (!labelAddressPtr) {
                            fprintf(stderr, "Error: Undefined label %s in ld instruction\n", label);
                            free(outputBuffer);
                            fclose(inputFile);
                            return NULL;
                        }
                        address = strtoll(labelAddressPtr, NULL, 0);
                    } 
                    else if (isValidImmediate(label)) {
                        address = strtoll(label, NULL, 10);
                    }
                    else {
                        fprintf(stderr, "Error: ld instruction must use a valid memory label or 64-bit immediate\n");
                        free(outputBuffer);
                        fclose(inputFile);
                        return NULL;
                    }

                    int bitSeq1 = (address >> 52) & 4095;
                    int bitSeq2 = (address >> 40) & 4095;
                    int bitSeq3 = (address >> 28) & 4095;
                    int bitSeq4 = (address >> 16) & 4095;
                    int bitSeq5 = (address >> 4) & 4095;
                    int bitSeq6 = address & 0xF;

                    int written = snprintf(expanded, sizeof(expanded),
                        "\txor %s, %s, %s\n"
                        "\taddi %s, %d\n"
                        "\tshftli %s, 12\n"
                        "\taddi %s, %d\n"
                        "\tshftli %s, 12\n"
                        "\taddi %s, %d\n"
                        "\tshftli %s, 12\n"
                        "\taddi %s, %d\n"
                        "\tshftli %s, 12\n"
                        "\taddi %s, %d\n"
                        "\tshftli %s, 4\n"
                        "\taddi %s, %d\n",
                        rd, rd, rd,
                        rd, bitSeq1, 
                        rd,
                        rd, bitSeq2, 
                        rd,
                        rd, bitSeq3, 
                        rd,
                        rd, bitSeq4, 
                        rd,
                        rd, bitSeq5, 
                        rd,
                        rd, bitSeq6
                    );
                }
                
                else {
                    replaceMemoryAddresses(originalOperands, &labelMap);
                    if (originalOperands[0] != '\0')
                        snprintf(expanded, sizeof(expanded), "\t%s %s\n", opcode, originalOperands);
                    else
                        snprintf(expanded, sizeof(expanded), "\t%s\n", opcode);    
                }

                size_t lineLength = strlen(expanded) + 1;
                while (outputLength + strlen(expanded) + 1 >= bufferSize) {
                    bufferSize *= 2;
                }
                char *temp = realloc(outputBuffer, bufferSize);
                if (!temp) {
                    fprintf(stderr, "Error reallocating output buffer");
                    free(outputBuffer);
                    fclose(inputFile);
                    return NULL;
                }
                outputBuffer = temp;
                strncat(outputBuffer, expanded, bufferSize - outputLength - 1);
                outputLength += strlen(expanded);
            }

        }
    }
    return outputBuffer;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *outputBuffer = parseFile(argv[1]);   
    if (!outputBuffer) {
        fprintf(stderr, "Error processing file.\n");
        return EXIT_FAILURE;
    }

    FILE *outputFile = fopen(argv[2], "wb");
    if (!outputFile) {
       fprintf(stderr, "Error opening output file");
        free(outputBuffer);
        return EXIT_FAILURE;
    }

    fprintf(outputFile, "%s", outputBuffer);
    fflush(outputFile);
    fclose(outputFile);
    free(outputBuffer);

    printf("Assembly successfully written to %s\n", argv[2]);
    return EXIT_SUCCESS;
}

