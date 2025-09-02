// SPDX-License-Identifier: GPL-3.0-or-later

/*
 *	Copyright 2023, 2024, 2025 Ian Pilcher <arequipeno@gmail.com>
 *
 *	ACME Cert Getter - https://github.com/ipilcher/acg
 */


#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <linux/openat2.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <unistd.h>

#include <selinux/label.h>
#include <selinux/selinux.h>
#include <systemd/sd-journal.h>


#define CFM_INFO(...)   cfm_log(LOG_INFO, __VA_ARGS__)
#define CFM_ERROR(...)  cfm_log(LOG_ERR, __VA_ARGS__)
#define CFM_FATAL(...)  cfm_log(LOG_CRIT, __VA_ARGS__)
#define CFM_ABORT(...)  cfm_log(LOG_ALERT, __VA_ARGS__)


static const char *restrict cfm_cfg;
static struct selabel_handle *cfm_hndl;
static _Bool cfm_journal;
static _Bool cfm_debug;


__attribute__((format(printf, 3, 0)))
static void cfm_vlog(const unsigned int priority, const _Bool enable_exit,
                     const char *restrict const format, va_list ap)
{
    /* RFC5424 defines these as 0 (LOG_EMERG) - 7 (LOG_DEBUG) */
    static const char *restrict const prios[] = {
        [LOG_EMERG]     = "EMERGENCY",
        [LOG_ALERT]     = "ALERT",
        [LOG_CRIT]      = "CRITICAL",
        [LOG_ERR]       = "ERROR",
        [LOG_WARNING]   = "WARNING",
        [LOG_NOTICE]    = "NOTICE",
        [LOG_INFO]      = "INFO",
        [LOG_DEBUG]     = "DEBUG"
    };

    assert(priority <= LOG_DEBUG);

    if (priority == LOG_DEBUG && !cfm_debug)
        return;

    if (cfm_journal) {
        sd_journal_printv(priority, format, ap);
    }
    else {
        /* stderr must be line-buffered */
        fprintf(stderr, "%s: ", prios[priority]);
        vfprintf(stderr, format, ap);
        fputc('\n', stderr);
    }

    if (enable_exit && priority == LOG_CRIT)
        exit(EXIT_FAILURE);

    if (priority <= LOG_ALERT)
        abort();
}

__attribute__((format(printf, 2, 3)))
static void cfm_log(const unsigned int priority,
                    const char *restrict const format, ...)
{
    va_list ap;

    va_start(ap, format);
    cfm_vlog(priority, 1, format, ap);
    va_end(ap);
}


static int cfm_open(const char *restrict const path, const int flags,
                    const mode_t mode, const unsigned int lnum)
{
    struct open_how how;
    char *pcopy, *dpath, *rpath;
    int fd;
    struct stat st;

    /*
     * We want to check that the path is canonical, but the file may not exist,
     * so we check the directory (everything but the last element).
     */

    /* dirname() may modify its argument, so make a copy */
    if ((pcopy = strdup(path)) == NULL)
        CFM_FATAL("%s:%u: strdup: %s: %m", cfm_cfg, lnum, path);

    dpath = dirname(pcopy);

    if ((rpath = realpath(dpath, NULL)) == NULL)
        CFM_FATAL("%s:%u: realpath: %s: %m", cfm_cfg, lnum, dpath);

    if (strcmp(dpath, rpath) != 0)
        CFM_FATAL("%s:%u: %s: Non-canonical path", cfm_cfg, lnum, dpath);

    free(pcopy);
    free(rpath);

    memset(&how, 0, sizeof how);
    how.flags = flags;
    how.mode = mode;
    how.resolve = RESOLVE_NO_SYMLINKS;

    fd = syscall(SYS_openat2, 0, path, &how, sizeof how);

    if (fd >= 0) {

        if (fstat(fd, &st) < 0)
            CFM_FATAL("%s:%u: fstat: %s: %m", cfm_cfg, lnum, path);

        if (!S_ISREG(st.st_mode))
            CFM_FATAL("%s:%u: %s: Not a regular file", cfm_cfg, lnum, path);
    }

    return fd;
}

static void cfm_chkcfg(const int fd)
{
    struct stat st;

    if (fstat(fd, &st) < 0)
        CFM_FATAL("fstat: %s: %m", cfm_cfg);

    if (!S_ISREG(st.st_mode))
        CFM_FATAL("%s: Not a regular file", cfm_cfg);

    if (st.st_uid != 0)
        CFM_FATAL("%s: Not owned by root user", cfm_cfg);

    if (st.st_mode & (S_IWGRP | S_IXGRP))
        CFM_FATAL("%s: Group has write or execute permission", cfm_cfg);

    if (st.st_mode & (S_IWOTH | S_IXOTH))
        CFM_FATAL("%s: Others have write or execute permission", cfm_cfg);

    if (st.st_mode & (S_ISUID | S_ISGID | S_ISVTX))
        CFM_FATAL("%s: Set-user-ID, set-group-ID, or stick bit set", cfm_cfg);
}



static void cfm_setcon(const char *restrict const context, const int dstfd,
                       const char *restrict const dest, const unsigned int lnum)
{
    char *ctx;

    if (strcmp(context, "-") == 0) {
        /* Use the default context from the policy */
        if (selabel_lookup(cfm_hndl, &ctx, dest, S_IFREG) < 0)
            CFM_FATAL("%s:%u: selabel_lookup: %s: %m", cfm_cfg, lnum, dest);
        if (fsetfilecon(dstfd, ctx) < 0)
            CFM_FATAL("%s:%u: fsetfilecon: %s: %m\n", cfm_cfg, lnum, dest);
        freecon(ctx);
    }
    else if (strchr(context, ':') == NULL) {
        /* Supplied "context" is only type, so create full context */
        if (asprintf(&ctx, "system_u:object_r:%s:s0", context) < 0) {
            CFM_ABORT("%s:%u: asprintf: system_u:object_r:%s:s0: %m",
                      cfm_cfg, lnum, context);
        }
        if (fsetfilecon(dstfd, ctx) < 0)
            CFM_FATAL("%s:%u: fsetfilecon: %s: %m", cfm_cfg, lnum, dest);
        free(ctx);
    }
    else {
        /* Supplied context is complete */
        if (fsetfilecon(dstfd, context) < 0)
            CFM_FATAL("%s:%u: fsetfilecon: %s: %m", cfm_cfg, lnum, dest);
    }
}

static void cfm_do_line(const char *restrict const line,
			const unsigned int lnum)
{
    char *restrict source, *restrict dest, *restrict user,
         *restrict group, *restrict context;
    unsigned int mode;
    int matched, nchar, srcfd, dstfd;
    struct passwd *pw;
    struct group *gr;
    struct stat st;
    ssize_t sent;
    const char *restrict errmsg;

    if (*line == '\n' || *line == '#' || *line == 0)
        return;

    /*
     * Context is optional, so it may not be matched by sscanf (in which case
     * the second %n conversion won't be matched either).
     */
    context = NULL;  /* Make free(context) a NOOP if not matched */
    matched = sscanf(line, "%ms %ms %ms %ms %o%n %ms%n",
                     &source, &dest, &user, &group, &mode, &nchar,
                     &context, &nchar);
    if (matched < 5)
        CFM_FATAL("%s:%u: Missing field(s)", cfm_cfg, lnum);

    if (line[nchar] != '\n' && line[nchar] != 0)
            CFM_FATAL("%s:%u: Extra characters", cfm_cfg, lnum);

    if ((pw = getpwnam(user)) == NULL) {
        CFM_FATAL("%s:%u: getpwnam: %s: %s", cfm_cfg, lnum, user,
                  (errno != 0) ? strerror(errno) : "No such user");
    }

    if ((gr = getgrnam(group)) == NULL) {
        CFM_FATAL("%s:%u: getgrnam: %s: %s", cfm_cfg, lnum, group,
                  (errno != 0) ? strerror(errno) : "No such group");
    }

    if ((srcfd = cfm_open(source, O_RDONLY, 0, lnum)) < 0) {
        if (errno != ENOENT)
            CFM_FATAL("%s:%u: openat2: %s: %m", cfm_cfg, lnum, source);
        CFM_INFO("%s:%u: %s: %m; skipping", cfm_cfg, lnum, source);
        goto done;
    }

    if (fstat(srcfd, &st) < 0)
        CFM_FATAL("%s:%u: fstat: %s: %m", cfm_cfg, lnum, source);

    if ((dstfd = cfm_open(dest, O_WRONLY | O_CREAT | O_TRUNC, mode, lnum)) < 0)
        CFM_FATAL("%s:%u: openat2 %s: %m", cfm_cfg, lnum, dest);

    if (fchown(dstfd, pw->pw_uid, gr->gr_gid) < 0)
        CFM_FATAL("%s:%u: fchown %s: %m", cfm_cfg, lnum, dest);

    if (fchmod(dstfd, mode) < 0)
        CFM_FATAL("%s:%u: fchmod %s: %m", cfm_cfg, lnum, dest);

    if (matched == 6)
        cfm_setcon(context, dstfd, dest, lnum);

    if ((sent = sendfile(dstfd, srcfd, NULL, st.st_size)) != st.st_size) {
        errmsg = (sent < 0) ? strerror(errno) : "Incorrect copy size";
        CFM_FATAL("%s:%u: sendfile: %s → %s: %s",
                  cfm_cfg, lnum, source, dest, errmsg);
    }

    if (close(srcfd) < 0)
        CFM_ERROR("%s:%u: close: %s: %m", cfm_cfg, lnum, source);

    if (close(dstfd) < 0)
        CFM_ERROR("%s:%u: close: %s: %m", cfm_cfg, lnum, source);

    CFM_INFO("%s:%u: %s → %s: Success", cfm_cfg, lnum, source, dest);

    done:
        free(source);
        free(dest);
        free(user);
        free(group);
        free(context);
}

static _Bool cfm_opt_eq(const char *restrict const s,
                        const char *restrict const sopt,
                        const char *restrict const lopt)
{
    return strcmp(s, sopt) == 0 || strcmp(s, lopt) == 0;
}

__attribute__((noreturn, format(printf, 2, 3)))
static void cfm_usage(const char *restrict const cmd,
                      const char *restrict const format, ...)
{
    va_list ap;

    va_start(ap, format);
    cfm_vlog(LOG_CRIT, 0, format, ap);
    va_end(ap);

    CFM_INFO(" ");  /* Avoid warning about empty format string */
    CFM_INFO("Usage: %s [-j|--journal|-s|--stderr] CONFIG_FILE", cmd);
    CFM_INFO("    -j | --journal    Log to journald");
    CFM_INFO("    -s | --stderr     Log to stderr");
    CFM_INFO(" ");
    CFM_INFO("By default, messages are logged to stderr if it is connected to");
    CFM_INFO("a terminal; otherwise they are logged to the journal.  Use the");
    CFM_INFO("'-j' ('--journal') or '-s' ('--stderr') options to override the");
    CFM_INFO("default behavior.");

    exit(EXIT_FAILURE);
}

int main(const int argc, char **const argv)
{
    FILE *cfg;
    char *buf = NULL;
    size_t bsize;
    int i;
    _Bool log_mode_set = 0;

    setlinebuf(stderr);
    cfm_journal = !isatty(STDERR_FILENO);

    if (argc < 2 || argc > 4)
        cfm_usage(argv[0], "Invalid number of arguments");

    for (i = 1; i < argc - 1; ++i) {

        if (cfm_opt_eq(argv[i], "-j", "--journal")) {
            if (log_mode_set)
                cfm_usage(argv[0], "Duplicate/conflicting option: %s", argv[i]);
            log_mode_set = 1;
            cfm_journal = 1;
        }
        else if (cfm_opt_eq(argv[i], "-s", "--stderr")) {
            if (log_mode_set)
                cfm_usage(argv[0], "Duplicate/conflicting option: %s", argv[i]);
            log_mode_set = 1;
            cfm_journal = 0;
        }
        else {
            cfm_usage(argv[0], "Invalid option: %s", argv[i]);
        }
    }

    cfm_cfg = argv[i];

    if ((cfm_hndl = selabel_open(SELABEL_CTX_FILE, NULL, 0)) == NULL)
        CFM_FATAL("selabel_open: SELABEL_CTX_FILE: %m");

    if ((cfg = fopen(cfm_cfg, "r")) == NULL)
        CFM_FATAL("fopen: %s: %m", cfm_cfg);

    cfm_chkcfg(fileno(cfg));

    for (i = 1; getline(&buf, &bsize, cfg) >= 0; ++i)
        cfm_do_line(buf, i);

    free(buf);

    if (fclose(cfg) != 0)
        CFM_ERROR("fclose: %s: %m", cfm_cfg);

    selabel_close(cfm_hndl);

    return EXIT_SUCCESS;
}


/* kate: indent-width 4; replace-tabs on; */
