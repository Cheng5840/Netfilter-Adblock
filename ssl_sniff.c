#include <assert.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h> 

#include "ssl_sniff.skel.h"


#define BUF_MAX_LEN 256
struct data_t {
    unsigned int pid;
    int len;
    char buf[BUF_MAX_LEN];
};

regex_t preg;
int fd;

void handle_sniff(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct data_t *d = data;
    uint32_t result = 0;
    if (d->buf[0] == 'G' && d->buf[1] == 'E' && d->buf[2] == 'T') {
        int r = regexec(&preg, d->buf, 0, NULL, 0);
        if (!r)
            result = 1;
    }
    lseek(fd, d->pid | result << 31, 0);
}

const char regexp[] = "[/_.?\\-]ad[bcfgklnpqstwxyz/_.=?\\-]";

int main(int argc, char *argv[])
{
    if (argc == 1 || !(argc & 1)) {
        printf("wrong argument count\n");
        printf("Usage: %s <libpath1> <func1> <libpath2> <func2>\n", argv[0]);
        exit(0);
    }

    int ret = regcomp(&preg, regexp, REG_NOSUB | REG_ICASE);
    assert(ret == 0);


    struct ssl_sniff_bpf *skel;
    struct perf_buffer *pb = NULL;
    skel = ssl_sniff_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    for (int i = 1; i < argc; i += 2) {
        printf("Attaching %s in %s\n", argv[i + 1], argv[i]);
        const char *rawpath = argv[i];         // 參數帶進來的 so
        const char *func    = argv[i + 1];     // 對應函式名
        char so[PATH_MAX];

        /* 1 路徑統一成 loader 用的 inode */
        if (!realpath(rawpath, so)) {
            perror(rawpath);
            continue;
        }

        /* 2 如果想用 offset（可避免符號解析問題） */
        size_t offset = 0;
        if (!strcmp(func, "SSL_write"))
            offset = 0x36b20;                  // readelf 算出
        /* PR_Write 也可以事先用 readelf 算 offset 放這裡 */

        /* 3 清乾淨 opts，只留必要欄位 */
        struct bpf_uprobe_opts opts = {
            .sz       = sizeof(opts),
            .retprobe = false,
        };

        if (offset)
            ;                                  // 用 offset attach
        else
            opts.func_name = func;             // 用符號名 attach

        /* ref_ctr_offset 留 0 就對了（沒有 USDT semaphore 就別設） */

        struct bpf_link *link =
            bpf_program__attach_uprobe_opts(skel->progs.probe_SSL_write,
                                            -1, so, offset, &opts);
        if (!link)
            fprintf(stderr, "Error attaching %s in %s: %s (errno=%d)\n",
                    func, so, strerror(errno), errno);
    }


    pb = perf_buffer__new(bpf_map__fd(skel->maps.tls_event), 8, &handle_sniff,
                          NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 0;
    }

    printf("Opening adbdev...\n");
    fd = open("/dev/adbdev", O_WRONLY);
    if (fd < 0) {
        printf(
            "Failed to open adbdev.\nIt could be due to another program"
            "using it or the kernel module not being loaded.\n");
        exit(1);
    }

    printf("All ok. Sniffing plaintext now\n");
    while (1) {
        int err = perf_buffer__poll(pb, 1);
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
    return 0;
}