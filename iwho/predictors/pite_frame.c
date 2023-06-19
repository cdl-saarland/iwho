#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <xmmintrin.h>

void *aligned_alloc(size_t alignment, size_t size);
void *memset(void *s, int c, size_t n);

#ifndef USE_PERF_COUNTERS
// default: do not use model specific performance counters
// Adjust by compiling with `-DUSE_PERF_COUNTERS 1`
#define USE_PERF_COUNTERS 0
#endif

#define PAGE_SIZE 4096
#define PRERUN_NUM_ITERATIONS 100000

#ifndef INIT_ADDITIONAL_MEM_REGS
#define INIT_ADDITIONAL_MEM_REGS 0
#endif

// PLACEHOLDER_* strings are replaced by the python framework.
#define TARGET_USEC PLACEHOLDER_TARGET_USEC
#define NUM_REPS PLACEHOLDER_NUM_REPS
#define FREQ_PATH "/sys/devices/system/cpu/cpuPLACEHOLDER_PINNED_CORE/cpufreq/scaling_cur_freq"
#define PINNED_CORE PLACEHOLDER_PINNED_CORE

#ifndef COUNTER_ID
#define COUNTER_ID 0x0c1
#endif

#ifndef UNIT_MASK
#define UNIT_MASK 0x00
#endif

#define CTR_ID_HIGH_NIBBLE ((((uint64_t)(COUNTER_ID)) >> 8) & 0xF)
#define CTR_ID_LOW_BYTE (((uint64_t)(COUNTER_ID)) & 0xFF)
#define UNIT_MASK_BYTE (((uint64_t)(UNIT_MASK)) & 0xFF)

typedef int64_t num_t;

static uint64_t __attribute__((used)) saved_counters[2] = {0};


void write_msr(unsigned int msr, uint64_t value) {
    // use the wrmsr command to change a machine-specific register, since the
    // instruction for that can only be executed in kernel mode.
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "wrmsr -p%d %#x %#llx", PINNED_CORE, msr, value);
    if (system(cmd)) {
        fprintf(stderr, "\"%s\" failed.", cmd);
        exit(1);
    }
}

#define MSR_PM_CONTROL 0xC0010200
#define MSR_PM_COUNTER 0xC0010201

void configure_perf_counters(void) {
    // this is specific to AMD family 17h (i.e., Zen, Zen+, Zen2) processors

    write_msr(MSR_PM_CONTROL, 0); // clear the perf counter config
    write_msr(MSR_PM_COUNTER, 0); // clear the perf counter

    // write the PerfEvtSel0 MSR register
    uint64_t control_word = 0;
    control_word &= ~(0xffull << 24); // clear bits 31:24, the CNT_MASK, so that all events are counted
    control_word |= (1ull << 22);     // set bit 22, the EN bit, to enable the counter
    control_word &= ~(1ull << 20);    // clear bit 20, the INT bit, to disable overflow interrupts
    control_word &= ~(1ull << 18);    // clear bit 18, the EDGE bit, to disable edge detection
    control_word &= ~(1ull << 17);    // clear bit 17, the OS bit, to ignore events in os mode
    control_word |= (1ull << 16);     // set bit 16, the USR bit, to count events in user mode

    control_word |= (UNIT_MASK_BYTE << 8);  // set bits 15:8, the UNIT_MASK, to indicate the subcounter
    control_word |= (CTR_ID_HIGH_NIBBLE << 32);      // set the highest nibble of the EVENT_SELECT bits (35:32) to 0x0 for the "uop" counter
    control_word |= (CTR_ID_LOW_BYTE);      // set the low byte of the EVENT_SELECT bits (7:0) to 0xc1 for the "uop" counter

    write_msr(MSR_PM_CONTROL, control_word);
}

void one_time_init(void) {
    _mm_setcsr( _mm_getcsr() | (1<<15) | (1<<6)); // disable denormal floats
#if USE_PERF_COUNTERS
    configure_perf_counters();
#endif
}

// it's probably better for caches if we make sure that the benchmarking code
// is not duplicated
__attribute__((noinline))
double measure_usec(num_t *res_perf_counter, void *scratch_mem, size_t scratch_mem_size, num_t num_iterations) {
    struct timespec start, end;

    memset(scratch_mem, 42, scratch_mem_size);

    {
    saved_counters[0] = 0;
    saved_counters[1] = 0;
    clock_gettime(CLOCK_MONOTONIC,  &start);

    register num_t num_iterations_reg asm("r15") = num_iterations;
    register void * mem_rbp asm("rbp") = scratch_mem + 1 * PAGE_SIZE;
#if INIT_ADDITIONAL_MEM_REGS
    register void * mem_rsi asm("rsi") = scratch_mem + 2 * PAGE_SIZE;
    register void * mem_rdi asm("rdi") = scratch_mem + 3 * PAGE_SIZE;
    register void * mem_r14 asm("r14") = scratch_mem + 4 * PAGE_SIZE;
#endif
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

#if USE_PERF_COUNTERS
        // read performance counter
        "   XOR rcx, rcx\n" // use the first programmable counter
        "   LFENCE\n"
        "   RDPMC\n" // reads into EDX:EAX
        "   LFENCE\n"
        "   SHL RDX, 32\n"
        "   OR RAX, RDX\n"
        "   MOV qword ptr [rip+saved_counters+0], RAX\n"
#endif

        "   MOV rax, 42\n"
        "   MOV rbx, 42\n"
        "   MOV rdx, 42\n"
        "   MOV r8, 42\n"
        "   MOV r9, 42\n"
        "   MOV r10, 42\n"
        "   MOV r11, 42\n"
        "   MOV r12, 42\n"
        "   MOV r13, 42\n"

#if (! INIT_ADDITIONAL_MEM_REGS)
        // additional ones that might make problems with memory instructions
        "   MOV r14, 42\n" // (kernel)nanobench's preferred memory operand
        "   MOV rsi, 42\n"
        "   MOV rdi, 42\n"
#endif

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

#if USE_PERF_COUNTERS
        // read performance counter
        "   XOR rcx, rcx\n"
        "   LFENCE\n"
        "   RDPMC\n"
        "   LFENCE\n"
        "   SHL RDX, 32\n"
        "   OR RAX, RDX\n"
        "   MOV qword ptr [rip+saved_counters+8], RAX\n"
#endif

        "   .att_syntax\n"
        : "=r" (num_iterations_reg) // declare this as an output since it is an input that we want to clobber
        : "r" (num_iterations_reg), //[saved_counters_addr] "o" (saved_counters),
          "r" (mem_rbp) // inputs for memory operands
#if INIT_ADDITIONAL_MEM_REGS
          , "r" (mem_rsi), "r" (mem_rdi), "r" (mem_r14)
#endif
        : "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13",
#if (! INIT_ADDITIONAL_MEM_REGS)
          "r14", "rsi", "rdi",
#endif
          "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
          "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "cc", "memory"
           // clobber everything, except for the inputs
    );
    clock_gettime(CLOCK_MONOTONIC,  &end);
    }

    *res_perf_counter = saved_counters[1] - saved_counters[0];

    double benchtime_usec = ((double)end.tv_sec - (double)start.tv_sec) * 1000000 +
            (((double)end.tv_nsec - (double)start.tv_nsec) / 1000);
    return benchtime_usec;
}

int main(void) {
    one_time_init();

    // allocate and initialize scratch memory
    size_t mem_size = PAGE_SIZE + 8 * PAGE_SIZE;
    char * scratch_mem = (char*) aligned_alloc(PAGE_SIZE, mem_size);

    num_t perf_counter_return = 0;

    fprintf(stdout, "[\n");
    for (int curr_it = 0; curr_it < NUM_REPS; ++curr_it) {
        // pre-run: run the code for a fixed, small number of iterations, to
        // estimate how long it runs (but do it twice, for warm-up purposes)
        measure_usec(&perf_counter_return, scratch_mem, mem_size, PRERUN_NUM_ITERATIONS);
        double prerun_usec = measure_usec(&perf_counter_return, scratch_mem, mem_size, PRERUN_NUM_ITERATIONS);

        // compute how often we need to execute the code to roughly reach the
        // target execution time
        num_t num_iterations = (PRERUN_NUM_ITERATIONS * TARGET_USEC) / prerun_usec;

        fprintf(stderr, "determined number of iterations: %lld", num_iterations);
        fprintf(stderr, " with prerun time: %.10f usec\n", prerun_usec);

        // do a warmup run with N iterations
        measure_usec(&perf_counter_return, scratch_mem, mem_size, num_iterations);

        // measure the clock frequency
        num_t parse_freq_early;
        {
            FILE* f = fopen(FREQ_PATH, "r");
            fscanf(f, "%lld", &parse_freq_early);
            fclose(f);
        }
        double freq_early_kHz = (double)parse_freq_early;

        // do another warmup run with N iterations
        measure_usec(&perf_counter_return, scratch_mem, mem_size, num_iterations);

        // measure the time for 2*N interations
        double measurement_twice_usec = measure_usec(&perf_counter_return, scratch_mem, mem_size, 2* num_iterations);
        num_t perf_counter_twice = perf_counter_return;

        // measure the time for N interations
        double measurement_once_usec = measure_usec(&perf_counter_return, scratch_mem, mem_size, num_iterations);
        num_t perf_counter_once = perf_counter_return;

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

        num_t total_perf_counter = perf_counter_twice - perf_counter_once;
        double perf_counter_per_iteration = (double)total_perf_counter / (double)num_iterations;

        // dump output
        fprintf(stdout, "  {\n");
        fprintf(stdout, "    \"measured_time_usec\": %.2f,\n", measured_time_usec);
        fprintf(stdout, "    \"cycles_per_iteration\": %.10f,\n", cycles_per_iteration);
        fprintf(stdout, "    \"total_cycles\": %.10f,\n", total_cycles);
        fprintf(stdout, "    \"perf_counter_per_iteration\": %.10f,\n", perf_counter_per_iteration);
        fprintf(stdout, "    \"total_perf_counter\": %lld,\n", total_perf_counter);
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
    return 0;
}

