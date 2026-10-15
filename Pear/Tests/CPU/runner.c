/* SPDX-License-Identifier: GPL-3.0-or-later
 * Pear single-case capture driver; per-case capture/table approach adapted from
 * Madeira by Will Faust (48f976429c189f8396e23d251d8a82f43c705922).
 * No CRT, resumable execution, network, writable code or exception suppression.
 */
#include <windows.h>
#include <stdint.h>
#include <cpuid.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
extern void pear_case(void);
extern unsigned char pear_registers[648];
#include "case.h"
static char output[8192];
static unsigned used;
static int io_failed;
static void text(const char *s) {
    while (*s) {
        if (used == sizeof(output)) { io_failed=1; return; }
        output[used++]=*s++;
    }
}
static void hex(uint64_t n) {
    text("\"0x");
    for (int i=15;i>=0;--i) { char c[2]={"0123456789abcdef"[(n>>(i*4))&15],0}; text(c); }
    text("\"");
}
static void flush(void) {
    DWORD written=0;
    if (io_failed || !WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,used,&written,0) || written!=used) io_failed=1;
    used=0;
}
static void finish(LONG status) {
    NtTerminateProcess((HANDLE)(intptr_t)-1,io_failed?92:status);
    for (;;) {}
}
void pear_first_dispatch(void) {
    unsigned a,b,c,d; uint64_t xcr0=0;
    __cpuid(1,a,b,c,d);
    if (c & (1u<<27)) {
        unsigned lo,hi;
        __asm__ volatile("xgetbv" : "=a"(lo),"=d"(hi) : "c"(0));
        xcr0=((uint64_t)hi<<32)|lo;
    }
    int avx=(c&(1u<<28)) && (c&(1u<<27)) && ((xcr0&6)==6);
    text("{\"event\":\"begin\",\"id\":\"" PEAR_CASE_ID "\",\"manifest\":\"" PEAR_MANIFEST "\",\"cpuid_ecx\":"); hex(c);
    text(",\"cpuid_edx\":"); hex(d); text(",\"xcr0\":"); hex(xcr0); text(",\"avx\":"); text(avx?"true":"false"); text("}\n"); flush();
    if (PEAR_REQUIRES_AVX && !avx) { text("{\"event\":\"unavailable\",\"reason\":\"AVX_OSXSAVE_XCR0\"}\n"); flush(); finish(77); }
    if (!map_data()) { text("{\"event\":\"failed\",\"reason\":\"fixed_data_mapping\"}\n"); flush(); finish(91); }
    pear_case();
    unsigned failures=0;
    text("{\"event\":\"result\",\"id\":\"" PEAR_CASE_ID "\",\"values\":[");
    for (unsigned i=0;i<PEAR_EXPECTATIONS;++i) {
        uint64_t actual=*(uint64_t *)(pear_registers+expectations[i].offset);
        if ((actual&expectations[i].mask)!=(expectations[i].value&expectations[i].mask)) ++failures;
        if (i) text(","); hex(actual);
    }
    text("],\"rflags\":"); hex(*(uint64_t *)(pear_registers+640));
    text(",\"matched\":"); text(failures?"false":"true"); text("}\n"); flush();
    finish(failures?90:42);
}
