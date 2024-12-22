#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>

#ifndef DT_REG
#define DT_REG 8
#endif

#include <string.h>
#include <blake2.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#define uint128_t __uint128_t

#define HASH_TRUNC_BITS 32                          // Number of bits to truncate the hash to  
#define HASH_TRUNC_BYTES (HASH_TRUNC_BITS / 8)      // Number of bytes to truncate the hash to
#define MAX_CHAIN_LENGTH 0x400                      // Maximum length of a chain
#define NUM_CHAINS 0x100000                         // Number of chains in the table
#define BLAKE2B_OUTBYTES 32                         // Number of bytes in the BLAKE2b output         
#define TABLE_DIR "./path/to/directory/with/tables" // Directory with tables for attack in part2
#define NUM_THREADS 8                               // Optimal number of threads to use for table generation

#define TABLE_FILENAME "./path/to/table.table"      // File to save/load the table in part1

void evaluate_chain(uint32_t chain_start, uint32_t target_hash, int j, uint128_t seed); // Bascktrace chain, used for debugging (finding stray collisions between chain and target hash)

void print_hash_hex(const uint8_t *hash);                                                           // Print hash in hex format               
uint32_t truncate_hash(const uint8_t *hash);                                                        // Truncate hash to 32 bits             
uint128_t reduce(uint32_t hash, uint128_t seed);                                                    // Reduce function for generating chains, returns 128-bit value (seed || hash)
int compare(const void *a, const void *b);                                                          // Compare function for qsort
int compare_chain(const void *a, const void *b);                                                    // Compare function for bsearch
uint128_t generate_random_seed();                                                                   // Generate random 128-bit seed (seed have last 32 bits zeroed to be easily used in reduce function)
uint128_t generate_random_128bit();                                                                 // Generate random 128-bit value (simple as it is)
void print_table(uint32_t (*table)[2]);                                                             // Print the table to stdout
void save_table(const char *filename, uint32_t (*table)[2], size_t num_chains, uint128_t seed);     // Save the table to a file  
void load_table(const char *filename, uint32_t (*table)[2], size_t num_chains, uint128_t *seed);    // Load the table from a file 
void *generate_chunk(void* args);                                                                   // Generate a chunk of the table (used for multithreading)
void generate_table(uint32_t (*table)[2], uint128_t seed, bool verbose);                            // Generate the table (wrapper for multithreading)
bool search_preimage(uint32_t (*table)[2], uint32_t hash, uint128_t seed, uint128_t *preimage, bool verbose); // Search for a preimage 

void crack_on_multiple_tables(uint32_t number_of_tables);                                           // Crack the hash using multiple tables (wrapper for multithreading)
void* search_preimage_thread(void* args);                                                           // Search for preimage in a table (used for multithreading)
void generate_multiple_tables(size_t num_tables, size_t num_chains); // Generate multiple tables for part2


typedef struct {
    uint32_t (*table)[2];
    uint128_t seed;
    size_t start;
    size_t end;
    bool verbose;
    int id;
} ThreadArgs; // Arguments for the table generation thread

typedef struct {
    uint32_t (*tables)[NUM_CHAINS][2];
    uint128_t *seeds;
    size_t table_count;
    uint32_t target_hash;
    uint128_t *preimage;
    bool *found;
    pthread_mutex_t *mutex;
    size_t start;
    size_t end;
    int id;
} SearchThreadArgs; // Arguments for the preimage search thread

int main()
{
    printf("Hellman's time-memory tradeoff\n");
    printf("Parameters: K = %d, L = %d\n", NUM_CHAINS, MAX_CHAIN_LENGTH);
    printf("Using BLAKE2b with %d-byte output\n", BLAKE2B_OUTBYTES);
    
    // ***************** PART 2 *****************
    // size_t num_tables = 256;
    // size_t num_chains = NUM_CHAINS;
    // generate_multiple_tables(num_tables, num_chains);
    // crack_on_multiple_tables(256);


    // ***************** PART 1 *****************
    //generate table, or load it if it exists
    uint128_t seed;

    uint32_t (*table)[2] = malloc(sizeof(uint32_t) * NUM_CHAINS * 2);
    if (table == NULL)
    {
        perror("Failed to allocate memory for table");
        return 1;
    }

    if (access(TABLE_FILENAME, F_OK) != -1)
    {
        printf("Table exists, loading...\n");
        load_table(TABLE_FILENAME, table, NUM_CHAINS, &seed);
    } 
    else 
    {
        printf("Table does not exist, generating...\n");
        seed = generate_random_seed();
        srand(seed);
        generate_table(table, seed, false);
        save_table(TABLE_FILENAME, table, NUM_CHAINS, seed);
    }
    printf("Seed: %016llx%016llx\n", (unsigned long long)(seed >> 64), (unsigned long long)seed);


    // search for preimage in the table, use 10k random inputs

    uint32_t counter = 0;
    uint128_t preimage = 0;
    printf("Searching for preimage...\n");
    for (size_t i = 0; i < 10000; i++)
    {
        if (i % 1000 == 0)
            printf("Iteration %d\n", i);
        uint8_t hash[BLAKE2B_OUTBYTES];

        //this is for output of reduce function, should be commmented when using true random 256bit input
        // uint32_t msg = rand() & 0xFFFFFFFF;
        // union {
        //     uint128_t value;
        //     uint8_t bytes[sizeof(uint128_t)];
        // } input;
        // input.value = __builtin_bswap128(reduce(msg, seed));

        //generate 256 bit ramdom input
        union {
            uint128_t value[2];
            uint8_t bytes[sizeof(uint128_t) * 2];
        } input;
        input.value[0] = generate_random_128bit();
        input.value[1] = generate_random_128bit();

        blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t)*2, 0);
        uint32_t target_hash = truncate_hash(hash);
        if (search_preimage(table, target_hash, seed, &preimage, false))
        {
            counter++;
        }
    }
    printf("Success rate: %d/10000\n", counter);
    free(table);
    return 0;
}

void generate_multiple_tables(size_t num_tables, size_t num_chains) 
{
    const char *dir_name = "task2_tables"; //TODO: fix this
    for (size_t i = 0; i < num_tables; i++) {
        uint128_t seed = generate_random_seed(); // Generate a random seed for a table
        srand(seed);

        uint32_t (*table)[2] = malloc(sizeof(uint32_t) * num_chains * 2);
        if (table == NULL) {
            perror("Failed to allocate memory for table");
            exit(1);
        }

        generate_table(table, seed, false); // call the table generation function

        char file_path[128];
        snprintf(file_path, sizeof(file_path), "%s/%016llx%016llx_24x10.table", dir_name, (unsigned long long)(seed >> 64), (unsigned long long)seed); //idk how to name files 
        save_table(file_path, table, num_chains, seed);
        printf("Table saved to %s\n", file_path);
        free(table);
    }
}

void* search_preimage_thread(void* args) 
{
    SearchThreadArgs* threadArgs = (SearchThreadArgs*)args; //cast void* to SearchThreadArgs*
    uint32_t (*tables)[NUM_CHAINS][2] = threadArgs->tables; //get tables to search through
    uint128_t *seeds = threadArgs->seeds;                   //get seeds for each table
    uint32_t target_hash = threadArgs->target_hash;         //get target hash
    uint128_t *preimage = threadArgs->preimage;             //get preimage pointer
    bool *found = threadArgs->found;                        //get found flag, need to halt other threads if preimage is found
    pthread_mutex_t *mutex = threadArgs->mutex;             //get mutex for locking
    size_t start = threadArgs->start;                       //get start index for tables
    size_t end = threadArgs->end;                           //get end index for tables         
    //get args

    // int id  = threadArgs->id;
    // printf("[%d] Thread: %zu-%zu\n", id, start, end);

    for (size_t j = start; j < end; j++) {
        //iterate through MY tables
        pthread_mutex_lock(mutex);
        if (*found) {
            //someone already found the preimage, no need to search anymore
            // printf("[%d] Found by another thread\n", id);
            pthread_mutex_unlock(mutex);
            break;
        }
        pthread_mutex_unlock(mutex);

        //just call search function, hell yeah
        if (search_preimage(tables[j], target_hash, seeds[j], preimage, false)) {
            //just confirm that we found the actual preimage
            uint8_t hash[BLAKE2B_OUTBYTES];
            union {
                uint128_t value;
                uint8_t bytes[sizeof(uint128_t)];
            } input;
            input.value = __builtin_bswap128(*preimage);

            blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
            uint32_t x = truncate_hash(hash);

            if (x == target_hash) {
                //set flag found and halt
                // printf("[%d] Preimage found by thread in table %lu:\n", id, j);
                pthread_mutex_lock(mutex);
                *found = true;
                pthread_mutex_unlock(mutex);
                break;
            }
            *preimage = 0;
        }
    }

    return NULL;
}

void crack_on_multiple_tables(uint32_t number_of_tables)
{
    DIR *dir;
    struct dirent *ent;
    //get that dir here
    if ((dir = opendir(TABLE_DIR)) == NULL) 
    { 
        perror("Failed to open directory");
        return;
    }

    //allocate memory for tables and seeds
    uint32_t (*tables)[NUM_CHAINS][2] = malloc(sizeof(uint32_t) * NUM_CHAINS * 2 * number_of_tables);
    uint128_t seeds[number_of_tables];
    size_t table_count = 0;

    //load tables from directory
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            char file_path[256*2];
            snprintf(file_path, sizeof(file_path), "%s/%s", TABLE_DIR, ent->d_name);
            load_table(file_path, tables[table_count], NUM_CHAINS, &seeds[table_count]);
            table_count++;
            if (table_count >= number_of_tables) break;
        }
    }
    closedir(dir);

    if (table_count == 0) {
        printf("No tables found in the directory.\n");
        free(tables);
        return;
    }

    printf("Loaded %zu tables.\n", table_count);

    uint32_t counter = 0;
    uint128_t preimage = 0;


    printf("Searching for preimages...\n");
    for (size_t i = 0; i < 10000; i++) {
        if (i % 10 == 0)
            printf("Iteration %zu\n", i);

        // uint32_t msg = rand() & 0xFFFFFFFF;
        uint8_t hash[BLAKE2B_OUTBYTES];
        //this is for output of reduce function, should be commmented when using true random 256bit input
        // union {
        //     uint128_t value;
        //     uint8_t bytes[sizeof(uint128_t)];
        // } input;
        // input.value = __builtin_bswap128(reduce(msg, seeds[0]));
        union {
            uint128_t value[2];
            uint8_t bytes[sizeof(uint128_t) * 2];
        } input;
        input.value[0] = generate_random_128bit();
        input.value[1] = generate_random_128bit();



        blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
        uint32_t target_hash = truncate_hash(hash);
        if  (i % 1000 == 0) 
        {
            printf("[%lu] Input value: ", i);\
            for (int k = 0; k < (int)sizeof(uint128_t)*2; k++)
            {
                printf("%02x", input.bytes[k]);
            }
            printf("\nHash: ");
            printf("%08x\n", target_hash);
        }

        //threading routine
        bool found = false;
        pthread_t threads[NUM_THREADS];
        SearchThreadArgs threadArgs[NUM_THREADS];
        pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

        size_t tables_per_thread = table_count / NUM_THREADS;
        for (size_t t = 0; t < NUM_THREADS; t++) {
            threadArgs[t].tables = tables;
            threadArgs[t].seeds = seeds;
            threadArgs[t].table_count = table_count;
            threadArgs[t].target_hash = target_hash;
            threadArgs[t].preimage = &preimage;
            threadArgs[t].found = &found;
            threadArgs[t].mutex = &mutex;
            threadArgs[t].start = t * tables_per_thread;
            threadArgs[t].end = (t == NUM_THREADS - 1) ? table_count : (t + 1) * tables_per_thread;
            threadArgs[t].id = t;

            pthread_create(&threads[t], NULL, search_preimage_thread, &threadArgs[t]);
        }

        for (size_t t = 0; t < NUM_THREADS; t++) {
            pthread_join(threads[t], NULL);
        }

        if (found) {
            counter++;
        }
    }

    printf("Success rate: %d/10000\n", counter);
    free(tables);
}

void evaluate_chain(uint32_t chain_start, uint32_t target_hash, int j, uint128_t seed)
{
    //generate and print full chain, and also generate and print path form target hash to point where it was same as chain end 
    uint32_t x = chain_start;
    uint32_t y = target_hash;
    uint8_t hash[BLAKE2B_OUTBYTES];
    union {
        uint128_t value;
        uint8_t bytes[sizeof(uint128_t)];
    } input;

    printf("Chain: ");
    for (int k = 0; k < MAX_CHAIN_LENGTH; k++)
    {
        printf("%08x -> ", x);
        uint128_t reduced_x = reduce(x, seed);
        input.value = __builtin_bswap128(reduced_x);
        blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
        x = truncate_hash(hash);
    }

    printf("Path: ");

    for (int k = 0; k < j; k++)
    {
        printf("%08x -> ", y);
        uint128_t reduced_y = reduce(y, seed);
        input.value = __builtin_bswap128(reduced_y);
        blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
        y = truncate_hash(hash);
    }
    printf("%08x\n", y);
}

void *generate_chunk(void* args)
{
    //just generate a chunk of the table, defined by start and end, mini version of generate_table
    ThreadArgs* threadArgs = (ThreadArgs*)args;
    uint32_t (*table)[2] = threadArgs->table;
    uint128_t seed = threadArgs->seed;
    size_t start = threadArgs->start;
    size_t end = threadArgs->end;
    bool verbose = threadArgs->verbose;
    int thread_id = threadArgs->id;

    // printf("Thread #%d: Generating with parameters: start = %zu, end = %zu\n", thread_id, start, end);

    if (verbose)
        printf("Thread #%d Generating table with seed %016llx%016llx...\n", thread_id, (unsigned long long)(seed >> 64), (unsigned long long)seed);

    for (size_t i = start; i < end; i++)
    {
        
        // if ((i - start+1) % spaces == 0)
        // {
        //     printf("Thread #%d: Generated %zu chains\n", thread_id, i-start);
        // }

        uint32_t x = rand() & 0xFFFFFFFF;
        table[i][0] = x;

        if (verbose)
            printf("Generating chain with start: %08x\n", x);

        for (size_t j = 1; j < MAX_CHAIN_LENGTH; j++)
        { 
            uint8_t hash[BLAKE2B_OUTBYTES];
            union {
                uint128_t value;
                uint8_t bytes[sizeof(uint128_t)];
            } input;

            if (verbose)
                printf("Start round x -> %08x\n", x);

            uint128_t reduced_x = reduce(x, seed);
            if (verbose) 
                printf("reduced -> %016llx%016llx\n", (unsigned long long)(reduced_x >> 64), (unsigned long long)reduced_x);
            

            input.value = __builtin_bswap128(reduced_x);

            if (verbose) 
            {
                printf("input -> ");
                for (int k = 0; k < (int)sizeof(uint128_t); k++)
                {
                    printf("%02x", input.bytes[k]);
                }
                printf("\nhash -> ");
            }

            blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);

            if (verbose)
                print_hash_hex(hash);

            x = truncate_hash(hash);

            if (verbose)
                printf("Final round x -> %08x\n", x);
        }
        table[i][1] = x;

        if (verbose)
            printf("\n");
    }
    return NULL; //some wierd void* shit :)
}

void generate_table(uint32_t (*table)[2], uint128_t seed, bool verbose)
{
    //threading wrapper
    size_t num_threads = NUM_THREADS;
    pthread_t threads[num_threads];
    ThreadArgs threadArgs[num_threads];

    size_t chains_per_thread = NUM_CHAINS / num_threads;

    for (size_t i = 0; i < num_threads; i++) {
        threadArgs[i].table = table;
        threadArgs[i].seed = seed;
        threadArgs[i].start = i * chains_per_thread;
        threadArgs[i].end = (i == num_threads - 1) ? NUM_CHAINS : (i + 1) * chains_per_thread;
        threadArgs[i].verbose = verbose;
        threadArgs[i].id = i;

        pthread_create(&threads[i], NULL, generate_chunk, &threadArgs[i]);
    }

    for (size_t i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    //sort table
    qsort(table, NUM_CHAINS, sizeof(uint32_t) * 2, compare);
}

bool search_preimage(uint32_t (*table)[2], uint32_t target_hash, uint128_t seed, uint128_t *preimage, bool verbose)
{
    if (verbose)
        printf("Searching for %08x preimage...\n", target_hash);
    
    uint32_t y = target_hash;
    for (int j = 0; j < MAX_CHAIN_LENGTH; j++)
    {
        //binary search for chain
        uint32_t *found = bsearch(&y, table, NUM_CHAINS, sizeof(uint32_t) * 2, compare_chain);
        if (found != NULL)
        {
            size_t i = (found - (uint32_t *)table) / 2;
            if (verbose)
            {
                printf("Found chain %zu with value at %d\nCalculating preimage...\n", i, MAX_CHAIN_LENGTH - j);
                printf("Current y(j): %08x(%d)\n", y, j);
                printf("Chain: [%08x] -> [%08x]\n", table[i][0], table[i][1]);
            }
            //evaluate_chain(table[i][0], target_hash, j, seed);

            uint32_t x = table[i][0];
            uint8_t hash[BLAKE2B_OUTBYTES];
            uint128_t reduced_x = 0; 
            union {
                uint128_t value;
                uint8_t bytes[sizeof(uint128_t)];
            } input;

            //calculate chain from start to L - j - 1
            for (size_t k = 0; k < (long unsigned int)(MAX_CHAIN_LENGTH - j - 1); k++)
            {
                reduced_x = reduce(x, seed);
                input.value = __builtin_bswap128(reduced_x);

                if (verbose) 
                {
                    printf("[%ld] x: %08x, reduced input:", k, x);
                    for (int m = 0; m < (int)sizeof(uint128_t); m++)
                    {
                        printf("%02x", input.bytes[m]);
                    }
                }

                blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
                x = truncate_hash(hash);

                if (verbose)
                    printf(" Current hash: %08x -> target hash %08x\n", x, target_hash);

                //check if we found the actual preimage
                if (x == target_hash)
                {
                    if (verbose)
                        printf("Target hash and current hash are equal, so preimage is current input\n");
                        //printf("k = %ld, max = %d\n", k, MAX_CHAIN_LENGTH - j);
                    //write preimage to preimage pointer and return
                    *preimage = reduced_x;
                    return true;
                }
            }
        }
        //yeah, well continue the chain

        uint8_t hash[BLAKE2B_OUTBYTES];
        union {
            uint128_t value;
            uint8_t bytes[sizeof(uint128_t)];
        } input;
        uint128_t reduced_y = reduce(y, seed);
        input.value = __builtin_bswap128(reduced_y);

        if (verbose) 
        {
            printf("y: %08x, input: ", y);
            for (int k = 0; k < (int)sizeof(uint128_t); k++)
            {
                printf("%02x", input.bytes[k]);
            }
        }

        blake2b(hash, input.bytes, NULL, BLAKE2B_OUTBYTES, sizeof(uint128_t), 0);
        y = truncate_hash(hash);
        // }

        // if (verbose)
        //     printf("y = %08x\n", y);
    }
    return false;
}

uint128_t reduce(uint32_t hash, uint128_t seed)
{
    //concat hash to last bits of seed (free bits, they are 0), and return it
    return hash | seed;
}

uint32_t truncate_hash(const uint8_t *hash) 
{
    //truncate hash to 32 bits
    uint32_t truncated;
    memcpy(&truncated, 
    hash + BLAKE2B_OUTBYTES - HASH_TRUNC_BYTES, 
    HASH_TRUNC_BYTES);
    return __builtin_bswap32(truncated);
}

uint128_t generate_random_seed()
{
    //unix priviledges are cool
    uint128_t seed;
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0)
    {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    if (read(urandom, &seed, sizeof(seed)) != sizeof(seed))
    {
        perror("Failed to read from /dev/urandom");
        close(urandom);
        exit(EXIT_FAILURE);
    }
    close(urandom);
    seed = (seed >> HASH_TRUNC_BITS) << HASH_TRUNC_BITS;
    return seed;
}

uint128_t generate_random_128bit()
{
    //same as above, but without shifts
    uint128_t value;
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0)
    {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    if (read(urandom, &value, sizeof(value)) != sizeof(value))
    {
        perror("Failed to read from /dev/urandom");
        close(urandom);
        exit(EXIT_FAILURE);
    }
    close(urandom);
    return value;
}

void save_table(const char *filename, uint32_t (*table)[2], size_t num_chains, uint128_t seed)
{
    //save table to file
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Failed to open file for writing");
        exit(EXIT_FAILURE);
    }
    fwrite(&seed, sizeof(seed), 1, file);
    fwrite(table, sizeof(uint32_t), num_chains * 2, file);
    fclose(file);
}

void load_table(const char *filename, uint32_t (*table)[2], size_t num_chains, uint128_t *seed)
{
    //load table from file
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Failed to open file for reading");
        exit(EXIT_FAILURE);
    }
    fread(seed, sizeof(*seed), 1, file);
    fread(table, sizeof(uint32_t), num_chains * 2, file);
    fclose(file);
}

int compare_chain(const void *a, const void *b)
{
    //needed for bsearch, compare chain with target hash
    uint32_t key = *(const uint32_t *)a;
    uint32_t (*row)[2] = (uint32_t (*)[2])b;
    return (key > row[0][1]) - (key < row[0][1]);
}

int compare(const void *a, const void *b)
{
    //compare function for qsort, by second element
    uint32_t (*rowA)[2] = (uint32_t (*)[2])a;
    uint32_t (*rowB)[2] = (uint32_t (*)[2])b;
    return (rowA[0][1] > rowB[0][1]) - (rowA[0][1] < rowB[0][1]);
}

void print_hash_hex(const uint8_t *hash)
{
    //dummy for hash printing before truncation to uint32_t
    for (int i = 0; i < BLAKE2B_OUTBYTES; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void print_table(uint32_t (*table)[2])
{
    //God help me debug this thing
    for (size_t i = 0; i < NUM_CHAINS; i++)
    {
        printf("%08x %08x\n", table[i][0], table[i][1]);
    }
}
