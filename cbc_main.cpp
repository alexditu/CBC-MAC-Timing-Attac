#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SAMPLE_NO   100
#define TRUE        1
#define FALSE       0

unsigned long long PS_getTimeStamp() {
    volatile unsigned int h = 0;
    volatile unsigned int l = 0;
    unsigned long long h_64, l_64;

    __asm__ __volatile__(
                         "RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r" (h), "=r" (l)
                         :
                         : "%rax", "%rbx", "%rcx", "%rdx");

    h_64 = (ps_u64) h;
    l_64 = (ps_u64) l;

    return (l_64 | (h_64 << 32));
}

unsigned long long compute_average(unsigned long long *arr) {
    unsigned long long avg = 0;

    for (int i = 0; i < SAMPLE_NO; i++) {
        avg += arr[i];
    }

    return avg / SAMPLE_NO;
}

// void show_goodtag(const char *message) {
//     char *key = "Cozonace si oua";
//     char *goodtag;

//     /* Get correct tag */
//     //goodtag = aes_cbc_mac(key, message);
    
//     for (int i = 0; i < 16; i++) {
//         printf("%x", (unsigned char)goodtag[i]);
//     }
//     printf("\n");
// }

/* will run on the server with the oracle */
int verify(const char *message, const char *tag) {
    char *key = "Cozonace si oua";
    char * goodtag;

    /* Get correct tag */
    goodtag = aes_cbc_mac(key, message);

    for (int i = 0; i < 16; i++) {
        // slow_foo()
        if (tag[i] != goodtag[i])
            return FALSE; 
    }

    return TRUE;
}

int main() {
    char *message = "Hristos a inviat!";
    unsigned char candidate_hash[16];

    // show_goodtag(message);

    memset(candidate_hash, 0, 16);

    /*
     * iterate through the first 15 bytes of the hash
     * and try all possibilities for them
     */
    for (int i = 0; i < 15; i++) {
        unsigned long long max_delta = 0;
        unsigned char current_byte = 0;
        unsigned long long start_ts, end_ts;

        for (int j = 0; j < 256; j++) {
            unsigned long long delta[SAMPLE_NO], avg_delta;
            candidate_hash[i] = j;

            for (int k = 0; k < SAMPLE_NO; k++) {
                start_ts = PS_getTimeStamp();
                verify(message, candidate_hash);
                end_ts = PS_getTimeStamp();
                delta[k] = end_ts - start_ts;
            }

            avg_delta = compute_average(delta);

            if (avg_delta > max_delta) {
                current_byte = j;
                max_delta = avg_delta;
            }
        }

        candidate_hash[i] = current_byte;
    }

    /* try all possibilities for last byte */
    for (int i = 0; i < 256; i++) {
        candidate_hash[15] = i;

        if (verify(message, candidate_hash) == TRUE) {
            printf ("Found hash")
        }
    }

}