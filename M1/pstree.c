#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define PROC_PATH "/proc"
#define COMM_LEN 256
#define PATH_BUF_LEN 512
#define FILE_BUF_LEN 1024


struct process_node {
    pid_t id;
    char comm[COMM_LEN];
    struct process_node *next;
    struct process_node *child;
};

static int show_pids = 0;
static int numeric_sort = 0;
static int vertion = 0;

static void parse_args(int argc, char *argv[]) {
    const struct option table[] = {
        { "show-pids",  no_argument, NULL, 'p'},
        { "numeric-sort", no_argument, NULL, 'n'},
        { "version", no_argument, NULL, 'V'},
        {0, 0                , NULL,  0 },
    };

    int o = 0;
    while ((o = getopt_long(argc, argv, "-pnV", table, NULL)) != -1) {
        switch(o) {
            case 'p':
                show_pids = 1;
                break;
                numeric_sort = 1;
                break;
            case 'V':
                vertion = 1;
                break;
            case 1:
                assert(0);
        }
    }
}

int is_a_digit_path(const char *path) {
    assert(path != NULL);
    int path_len = strlen(path);

    for (int i = 0; i < path_len; ++i) {
        if (isdigit(path[i]) == 0) {
            return 0;
        }
    }

    return 1;
}

void read_stat(const char* pid_str) {
    char path_buf[PATH_BUF_LEN] = {};
    snprintf(path_buf, PATH_BUF_LEN, "%s/%s/stat", PROC_PATH, pid_str);

    FILE *fd = fopen(path_buf, "r");
    assert(fd != NULL);
    
    // char *regex = "[0-9]+ (\\(.+\\)) \\w{1} ([0-9]+)";
    
    fclose(fd);
}


int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    DIR *proc_dir = opendir(PROC_PATH);
    if (NULL == proc_dir) {
        printf("proc_dir is null, erron:%d\n", errno);
        return -1;
    }

    errno = 0;
    struct dirent *dir_ent = NULL;
    char path_buf[PATH_BUF_LEN] = {};
    while ((dir_ent = readdir(proc_dir)) != NULL) {
        if (is_a_digit_path(dir_ent->d_name) == 0) {
            continue;
        }

        if (DT_DIR != dir_ent->d_type) {
            continue;
        }

        read_stat(dir_ent->d_name);
        
        snprintf(path_buf, PATH_BUF_LEN, "%s/%s/task", PROC_PATH, dir_ent->d_name);
        struct dirent * task_dir_ent = NULL;
        DIR *task_dir = opendir(path_buf);
        while ((task_dir_ent = readdir(task_dir)) != NULL) {
            if (is_a_digit_path(task_dir_ent->d_name) == 0) {
                continue;
            }
            // printf("task_dir_ent->d_name:%s\n", task_dir_ent->d_name);
        }

    }
    assert(errno == 0);

    
}
