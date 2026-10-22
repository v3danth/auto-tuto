/*
 * Benign marker library for the Auto-Color detection harness.
 *
 * What: on load, appends a single line to a log file, then does nothing.
 * Why:  gives the preload-in-maps sweep (DETECTION.md §3) a non-standard .so to
 *       find mapped into a process -- WITHOUT any of the implant's behavior.
 * Where/how: built by emulate.build_marker_preload_so() and LD_PRELOAD'd into a
 *       throwaway `sleep` process in the lab VM; the sweep then asserts it shows
 *       up in /proc/<pid>/maps.
 *
 * It has no hooks, no network, no persistence, no file hiding. It is a stand-in
 * for "a library got preloaded", not for Auto-Color's libcext.so.2.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

__attribute__((constructor))
static void marker_on_load(void) {
    const char *log = getenv("MARKER_LOG");
    if (!log) log = "/tmp/marker_preload.log";

    FILE *f = fopen(log, "a");
    if (!f) return;
    fprintf(f, "marker_preload loaded into pid %d at %ld\n",
            getpid(), (long)time(NULL));
    fclose(f);
}
