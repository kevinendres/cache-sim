#include "cachelab.h"
#include <stddef.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

typedef struct Cache_Line {
    int valid;
    int tag;
    int use_counter;
    struct timespec last_use;
} Cache_Line;

typedef struct Counters {
    int hit_count;
    int miss_count;
    int eviction_count;
} Counters;

enum policies {lru, lfu, low, hig} policy;
int lines_per_set, set_size;
int verbose_mode = 0;

/*****Prototypes****/
void parse_cl(int argv, char** argc, int* set_bits, int* block_bits, int* block_size, char* policy_arg, char* trace_source);
void set_policy(char* policy_arg);
void* initialize_cache();
void load(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id, Counters *counters);
void store(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id, Counters *counters);
void parse_addr(char *addr, int *set_id, int *tag_id, int set_bits, int block_bits);
int hit_check(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id);
int valid_check(Cache_Line cache_p[set_size][lines_per_set], int set_id);
int lru_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id);
int lfu_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id);
int low_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id);
int hig_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id);
void use_time(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id);

int main(int argc, char **argv)
{
    //inits
    char *policy_arg = NULL; 
    char *trace_source = NULL;
    int set_bits, block_bits, block_size;
    int addr, req, set_id, tag_id;
    char op;
    char str_addr[17];
    Counters counters;
    counters.hit_count = 0;
    counters.miss_count = 0;
    counters.eviction_count = 0;

    parse_cl(argc, argv, &set_bits, &block_bits, &block_size, policy_arg, trace_source);
    set_policy(policy_arg);

    //allocate cache
    Cache_Line (*cache_p)[lines_per_set] = initialize_cache();

    //open and parse trace file
    FILE *tracefile_p = fopen(trace_source, "r");
    while (fscanf(tracefile_p, " %c %x,%d", &op, &addr, &req) != EOF) {
        sprintf(str_addr, "%016x", addr);
        parse_addr(str_addr, &set_id, &tag_id, set_bits, block_bits);
        if (verbose_mode) {
            printf("\n%c %x,%d  %x|%x|0 ", op, addr, req, tag_id, set_id);
        }
        switch(op) {
            case 'I':
                break;
            case 'L':
                load(cache_p, set_id, tag_id, &counters);
                break;
            case 'S':
                store(cache_p, set_id, tag_id, &counters);
                break;
            case 'M':
                load(cache_p, set_id, tag_id, &counters);
                store(cache_p, set_id, tag_id, &counters);
                break;
            default:
                printf("bad operation");
        }
    }
    //don't forget to close the file
    fclose(tracefile_p);

    printSummary(counters.hit_count, counters.miss_count, counters.eviction_count);
    
    //don't forget to free
    free(cache_p);
    free(policy_arg);
    free(trace_source);

    return 0;
}

int eviction(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    int victim;
    switch (policy) {
        case 0: 
            //lru
            victim = lru_evict(cache_p, set_id);
            break;
        case 1:
            //lfu
            victim = lfu_evict(cache_p, set_id);
            break;
        case 2:
            //low
            victim = low_evict(cache_p, set_id);
            break;
        case 3:
            //hig
            victim = hig_evict(cache_p, set_id);
            break;
        default:
            abort();
    }
    return victim;
}

void* initialize_cache() {
    //allocate cache
    Cache_Line (*cache_p)[lines_per_set] = malloc(sizeof(Cache_Line[set_size][lines_per_set]));

    //initialize empty cache
    for (int i = 0; i < set_size; i++) {
        for (int j = 0; j < lines_per_set; j++) {
            cache_p[i][j].valid = 0;
            cache_p[i][j].tag = 0;
            cache_p[i][j].use_counter = 0;
        }
    }
    return cache_p;
}

void parse_cl(int argc, char** argv, int* set_bits, int* block_bits, int* block_size, char* policy_arg, char* trace_source) {
    //parse command line input
    int opt;
    while ((opt = getopt(argc, argv, "vs:E:b:p:t:")) != -1) {
        switch (opt) {
            case 'v': verbose_mode = 1; break;
            case 's': *set_bits = atoi(optarg); break;
            case 'E': lines_per_set = atoi(optarg); break;
            case 'b': *block_bits = atoi(optarg); break;
            case 'p': policy_arg = strdup(optarg); break;
            case 't': trace_source = strdup(optarg); break;
            default: printf("bad command line args"); abort();
        }
    }
    set_size = 1 << *set_bits;
    *block_size = 1 << *block_bits;
}

void set_policy(char* policy_arg) {

    //convert policy from str to enum
    if (!strcmp(policy_arg, "lru")) {
        policy = lru;
    } else if (!strcmp(policy_arg, "lfu")){
        policy = lfu;
    } else if (!strcmp(policy_arg, "low")) {
        policy = low;
    } else if (!strcmp(policy_arg, "hig")) {
        policy = hig;
    } else {
        printf("bad policy");
        abort();
    }
    
    //if direct mapped, keep eviction simple
    if (lines_per_set == 1) {
        policy = low;
    }
}

void load(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id, Counters *counters) {
    int line_index;
    int victim;
    //check if addr is in cache_p
    if ((line_index = hit_check(cache_p, set_id, tag_id)) != -1) {
    //if yes, hit_counter++ and use_counter++,
        counters->hit_count++;
        cache_p[set_id][line_index].use_counter++;
        if (verbose_mode) {
            printf("hit");
        }
        //lru usage
        if (policy == lru) {
            use_time(cache_p, set_id, line_index);
        }
        return;
    } else {
        //no hit so increase miss count
        counters->miss_count++;
        if (verbose_mode) {
            printf("miss ");
        }
        //look through the set to see if any lines are invalid
        if ((line_index = valid_check(cache_p, set_id)) != -1) {
            //if so, update that line to be valid and return
            cache_p[set_id][line_index].valid = 1;
            cache_p[set_id][line_index].tag = tag_id;
            cache_p[set_id][line_index].use_counter = 1;
            //lru
            if (policy == lru) {
                use_time(cache_p, set_id, line_index);
            }
            return;
        } else {
            //if all lines are valid, call eviction
            victim = eviction(cache_p, set_id);
            counters->eviction_count++;
            if (verbose_mode) {
                printf("eviction");
            }
            //replace victim
            cache_p[set_id][victim].valid = 1;
            cache_p[set_id][victim].tag = tag_id;
            cache_p[set_id][victim].use_counter = 1;
            //lru
            if (policy == lru) {
                use_time(cache_p, set_id, victim);
            }
            return;
        }
    }      
}

void store(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id, Counters *counters) {
    //since there's no actual writing of information so just call load
    load(cache_p, set_id, tag_id, counters);
}

int hit_check(Cache_Line cache_p[set_size][lines_per_set], int set_id, int tag_id) {
    //scan each line in the set to see if tags match, returns index
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].valid == 1 && cache_p[set_id][i].tag == tag_id) {    
            return i;
        }
    }
    return -1;
}

int valid_check(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    //scan each line in the set to see if there are any invalids
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].valid == 0) {
            return i;
        }
    }
    return -1;
}

int lru_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    //returns index of least recently used
    int lowest_time = 0;
    
    //cycle through comparing current lru_time with lowest lru_time
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].last_use.tv_sec < cache_p[set_id][lowest_time].last_use.tv_sec) {
            lowest_time = i;
        } else if (cache_p[set_id][i].last_use.tv_sec == cache_p[set_id][lowest_time].last_use.tv_sec) {
            if (cache_p[set_id][i].last_use.tv_nsec < cache_p[set_id][lowest_time].last_use.tv_nsec) {
                lowest_time = i;
            }
        }
    }
    return lowest_time;

}

int low_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    //returns index of line with lowest tag
    int lowest = 0;
    
    //cycle through comparing current tag with lowest tag
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].tag < cache_p[set_id][lowest].tag) {
            lowest = i;
        }
    }
    return lowest;
}

int lfu_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    //returns index of victim with lowest use_counter
    //cycle through to find least use cases
    int least = 0;
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].use_counter < cache_p[set_id][least].use_counter) {
            least = i;
            }
        printf("tag: %x, uses: %d ", cache_p[set_id][i].tag, cache_p[set_id][i].use_counter);
    }
    //check for ties
    int least_ties = 0;
    for (int i = 0; i < lines_per_set; i++) {
    if (cache_p[set_id][i].use_counter == cache_p[set_id][least].use_counter) {
                least_ties++;
            }
    }
    if (least_ties == 1) {
        return least;
    } else {
        //return lowest address
        for (int i = 0; i < lines_per_set; i++) {
            if (cache_p[set_id][i].use_counter == cache_p[set_id][least].use_counter && cache_p[set_id][i].tag < cache_p[set_id][least].tag) {
                least = i;
            }
        }
        return least;
    }
}

int hig_evict(Cache_Line cache_p[set_size][lines_per_set], int set_id) {
    //returns index of line with highest tag
    int highest = 0;

    //cycle through comparing current tag with highest tag
    for (int i = 0; i < lines_per_set; i++) {
        if (cache_p[set_id][i].tag > cache_p[set_id][highest].tag) {
            highest = i;
        }
    }
    return highest;
}

void use_time(Cache_Line cache_p[set_size][lines_per_set], int set_id, int index) {
    //records time of use into line struct
    struct timespec temp;
    clock_gettime(CLOCK_MONOTONIC, &temp);
    cache_p[set_id][index].last_use = temp;
}

void parse_addr(char *addr, int *set_id, int *tag_id, int set_bits, int block_bits) {
    int i = 0;
    int j = 0;
    char bin_addr[65];
    int tag_bits = 64 - set_bits - block_bits;
    char tag_bin[tag_bits + 1];
    char set_bin[set_bits + 1];
    char term[1] = "";

    //convert the 8byte hex address to 64bit binary 
    while (j < 64) {
        switch (addr[i]) { 
            case '0': 
                strcpy((bin_addr + j), "0000"); 
                j += 4;
                break; 
            case '1': 
                strcpy((bin_addr + j), "0001"); 
                j += 4;
                break; 
            case '2': 
                strcpy((bin_addr + j), "0010"); 
                j += 4;
                break; 
            case '3': 
                strcpy((bin_addr + j), "0011");
                j += 4;
                break; 
            case '4': 
                strcpy((bin_addr + j), "0100"); 
                j += 4;
                break; 
            case '5': 
                strcpy((bin_addr + j), "0101"); 
                j += 4;
                break; 
            case '6': 
                strcpy((bin_addr + j), "0110"); 
                j += 4;
                break; 
            case '7': 
                strcpy((bin_addr + j), "0111"); 
                j += 4;
                break; 
            case '8': 
                strcpy((bin_addr + j), "1000"); 
                j += 4;
                break; 
            case '9': 
                strcpy((bin_addr + j), "1001"); 
                j += 4;
                break; 
            case 'A': 
            case 'a': 
                strcpy((bin_addr + j), "1010"); 
                j += 4;
                break; 
            case 'B': 
            case 'b': 
                strcpy((bin_addr + j), "1011"); 
                j += 4;
                break; 
            case 'C': 
            case 'c': 
                strcpy((bin_addr + j), "1100"); 
                j += 4;
                break; 
            case 'D': 
            case 'd': 
                strcpy((bin_addr + j), "1101"); 
                j += 4;
                break; 
            case 'E': 
            case 'e': 
                strcpy((bin_addr + j), "1110"); 
                j += 4;
                break; 
            case 'F': 
            case 'f': 
                strcpy((bin_addr + j), "1111"); 
                j += 4;
                break;
            default: 
                return;
        }
        i++;
    }
    
    //separate out the tag and set bits
    memcpy(tag_bin, bin_addr, tag_bits);
    memcpy(tag_bin + tag_bits, term, 1);
    memcpy(set_bin, bin_addr + tag_bits, set_bits);

    //convert set bits to set_id
    int set_dec = 0;
    for (int shift = 0, i = set_bits - 1; i >= 0; i--, shift++) {
        set_dec += (set_bin[i] - 48) * (1 << shift);
    }
    *set_id = set_dec;

    //convert tag bits to tag_id
    int tag_dec = 0;
    for (int shift = 0, i = tag_bits - 1; i >= 0; i--, shift++) {
        tag_dec += (tag_bin[i] - 48) * (1 << shift);
    }
    *tag_id = tag_dec;
}