#include <stdio.h>
#include <stdint.h>
/* #include <stdlib.h> */
/* #include <dirent.h> */
/* #include <dlfcn.h> */
#include <sys/time.h>
/* #include <sys/stat.h> */
/* #include <sys/types.h> */
#include <xmmintrin.h>


void *aligned_alloc(size_t alignment, size_t size);
void *memset(void *s, int c, size_t n);



#define PAGE_SIZE 4096
#define PRERUN_NUM_ITERATIONS 1000

// PLACEHOLDER_* strings are replaced by the python framework.
#define TARGET_USEC PLACEHOLDER_TARGET_USEC
#define NUM_REPS PLACEHOLDER_NUM_REPS
#define FREQ_PATH "PLACEHOLDER_FREQ_PATH"

typedef int64_t num_t;

void one_time_init(void) {
    _mm_setcsr( _mm_getcsr() | (1<<15) | (1<<6)); // disable denormal floats
}

// it's probably better for caches if we make sure that the benchmarking code
// is not duplicated
__attribute__((noinline))
double measure_usec(void *scratch_mem, size_t scratch_mem_size, num_t num_iterations) {
    struct timeval start, end;
    double benchtime_usec;

    memset(scratch_mem, 42, scratch_mem_size);

    {
    gettimeofday(&start, NULL);
    register num_t num_iterations_reg asm("r15") = num_iterations;
    register void * mem_rbp asm("rbp") = scratch_mem + 1 * PAGE_SIZE;
    register void * mem_rsi asm("rsi") = scratch_mem + 2 * PAGE_SIZE;
    register void * mem_rdi asm("rdi") = scratch_mem + 3 * PAGE_SIZE;
    register void * mem_r14 asm("r14") = scratch_mem + 4 * PAGE_SIZE;
    asm volatile (
        "   .intel_syntax noprefix\n"

        // init registers
        "   VZEROALL\n"
        "   MOV r13d, 42\n"
        "   VCVTSI2SS xmm0, xmm0, r13d\n"        // set the lower-most float to the value
        "   VPERMILPS xmm0, xmm0, 0\n"           // set the lower half of the floats to the lower-most
        "   VINSERTF128 ymm0, ymm0, xmm0, 1\n"   // set the upper half of the floats to the lower half
        "   VMOVAPS ymm1, ymm0\n"
        "   VMOVAPS ymm2, ymm0\n"
        "   VMOVAPS ymm3, ymm0\n"
        "   VMOVAPS ymm4, ymm0\n"
        "   VMOVAPS ymm5, ymm0\n"
        "   VMOVAPS ymm6, ymm0\n"
        "   VMOVAPS ymm7, ymm0\n"
        "   VMOVAPS ymm8, ymm0\n"
        "   VMOVAPS ymm9, ymm0\n"
        "   VMOVAPS ymm10, ymm0\n"
        "   VMOVAPS ymm11, ymm0\n"
        "   VMOVAPS ymm12, ymm0\n"
        "   VMOVAPS ymm13, ymm0\n"
        "   VMOVAPS ymm14, ymm0\n"
        "   VMOVAPS ymm15, ymm0\n"

        "   MOV rax, 42\n"
        "   MOV rbx, 42\n"
        "   MOV rdx, 42\n"
        "   MOV r8, 42\n"
        "   MOV r9, 42\n"
        "   MOV r10, 42\n"
        "   MOV r11, 42\n"
        "   MOV r12, 42\n"
        "   MOV r13, 42\n"

        "   MOV rcx, 3\n"  // shift amount

        "   CMP rbx, rbx\n" // flag registers

        // "   MOV r15, [num_iterations]\n" // already initialized otherwise

        "   .p2align 4,,15\n"
        "TestbenchLabel:\n"
        // benchmarked instructions begin
PLACEHOLDER_BENCH_CODE
        // benchmarked instructions end
        "   SUB r15, 1\n"
        "   JNZ TestbenchLabel\n"
        "   .att_syntax\n"
        : "=r" (num_iterations_reg) // declare this as an output since it is an input that we want to clobber
        : "r" (num_iterations_reg),
          "r" (mem_rbp), "r" (mem_rsi), "r" (mem_rdi), "r" (mem_r14) // inputs for memory operands
        : "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13",
          "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
          "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "cc", "memory"
           // clobber everything, except for the inputs
    );
    gettimeofday(&end, NULL);
    }

    benchtime_usec = ((double)end.tv_sec - (double)start.tv_sec) * 1000000 +
            ((double)end.tv_usec - (double)start.tv_usec);
    return benchtime_usec;
}

int main(void) {
    one_time_init();

    // allocate and initialize scratch memory
    size_t mem_size = PAGE_SIZE + 8 * PAGE_SIZE;
    char * scratch_mem = (char*) aligned_alloc(PAGE_SIZE, mem_size);

    fprintf(stdout, "[\n");
    for (int curr_it = 0; curr_it < NUM_REPS; ++curr_it) {
        // pre-run: run the code for a fixed, small number of iterations, to
        // estimate how long it runs
        double prerun_usec = measure_usec(scratch_mem, mem_size, PRERUN_NUM_ITERATIONS);

        // compute how often we need to execute the code to roughly reach the
        // target execution time
        num_t num_iterations = (PRERUN_NUM_ITERATIONS * TARGET_USEC) / prerun_usec;

        // do a warmup run with N iterations
        measure_usec(scratch_mem, mem_size, num_iterations);

        // measure the clock frequency
        num_t parse_freq_early;
        {
            FILE* f = fopen(FREQ_PATH, "r");
            fscanf(f, "%lld", &parse_freq_early);
            fclose(f);
        }
        double freq_early_kHz = (double)parse_freq_early;

        // do another warmup run with N iterations
        measure_usec(scratch_mem, mem_size, num_iterations);

        // measure the time for 2*N interations
        double measurement_twice_usec = measure_usec(scratch_mem, mem_size, 2* num_iterations);

        // measure the time for N interations
        double measurement_once_usec = measure_usec(scratch_mem, mem_size, num_iterations);

        // measure the clock frequency again, to check for inconsistencies
        num_t parse_freq_late;
        {
            FILE* f = fopen(FREQ_PATH, "r");
            fscanf(f, "%lld", &parse_freq_late);
            fclose(f);
        }
        double freq_late_kHz = (double)parse_freq_late;

        // use the difference
        double measured_time_usec = measurement_twice_usec - measurement_once_usec;

        // take the average of the frequencies; the calling python script should
        // check whether the frequencies are substantially different and reject the
        // run in that case.
        double freq_kHz = (freq_early_kHz + freq_late_kHz) / 2;

        // calculate total cycles: (measured_time_usec * 10^-6 seconds) * (freq_kHz * 10^3 * 1/seconds)
        double total_cycles = (measured_time_usec * freq_kHz) / 1000.0;
        double cycles_per_iteration = total_cycles / num_iterations;

        // dump output
        fprintf(stdout, "  {\n");
        fprintf(stdout, "    \"measured_time_usec\": %.2f,\n", measured_time_usec);
        fprintf(stdout, "    \"cycles_per_iteration\": %.10f,\n", cycles_per_iteration);
        fprintf(stdout, "    \"total_cycles\": %.10f,\n", total_cycles);
        fprintf(stdout, "    \"num_iterations\": %lld,\n", num_iterations);
        fprintf(stdout, "    \"freq_early_kHz\": %f,\n", freq_early_kHz);
        fprintf(stdout, "    \"freq_late_kHz\": %f,\n", freq_late_kHz);
        fprintf(stdout, "    \"avg_freq_kHz\": %f\n", freq_kHz);
        fprintf(stdout, "  }");
        if (curr_it == NUM_REPS - 1) {
            fprintf(stdout, "\n");
        } else {
            fprintf(stdout, ",\n");
        }
    }
    fprintf(stdout, "]\n");
}

