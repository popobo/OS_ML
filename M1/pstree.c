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
#include <regex.h>

#define PROC_PATH "/proc"
#define SHORT_LEN 64
#define COMM_LEN 256
#define PATH_BUF_LEN 512
#define FILE_BUF_LEN 1024

typedef struct process_node {
    int pid;
    int ppid;
    char comm[COMM_LEN];
    struct process_node *next;
    struct process_node *child; 
} process_node;

static process_node *head = NULL;
static process_node *current = NULL;

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

void append_node(int pid, int ppid, const char* comm) {
    process_node *node = (process_node *)malloc(sizeof(process_node));
    assert(node != NULL);
    node->pid = pid;
    node->ppid = ppid;
    strcpy(node->comm, comm);
    node->next = NULL;
    node->child = NULL;

    if (head == NULL) {
        head = node;
        current = head;
        return;
    }

    current->next = node;
    current = current->next;
}

void print_node() {
    if (NULL == head) {
        return;
    }

    process_node *temp = head;
    while (temp != NULL) {
        printf("pid:%d, ppid:%d, comm:%s\n", temp->pid, temp->ppid, temp->comm);
        temp = temp->next;
    }
}

void free_nodes() {
    if (NULL == head) {
        return;
    }

    process_node *temp = head;
    process_node *temp_next = temp->next;
    while (temp != NULL && temp_next != NULL) {
        free(temp);
        temp = temp_next;
        temp_next = temp->next;
    }

    if (temp != NULL) {
        free(temp);
    }
}

void read_stat(const char* pid_str) {
    char path_buf[PATH_BUF_LEN] = {};
    snprintf(path_buf, PATH_BUF_LEN, "%s/%s/stat", PROC_PATH, pid_str);

    FILE *fd = fopen(path_buf, "r");
    assert(fd != NULL);
    char stat_buf[FILE_BUF_LEN];
    fread(stat_buf, sizeof(char), FILE_BUF_LEN, fd);
    stat_buf[FILE_BUF_LEN - 1] = '\0';
    
    char *regex = "[0-9]+ (\\(.+\\)) \\w{1} ([0-9]+)";
    regex_t rt;
    int ret = regcomp(&rt, regex, REG_EXTENDED);
    assert(ret == 0);
    
    const int max_group = 3;
    regmatch_t group_array[max_group];
    ret = regexec(&rt, stat_buf, max_group, group_array, 0);
    assert(ret == 0);

    char comm_buf[COMM_LEN];
    int group_len = group_array[1].rm_eo - group_array[1].rm_so;
    assert(group_len < COMM_LEN);
    memcpy(comm_buf, stat_buf + group_array[1].rm_so, group_len);
    comm_buf[group_len] = '\0';

    char ppid_buf[SHORT_LEN];
    group_len = group_array[2].rm_eo - group_array[2].rm_so;
    assert(group_len < SHORT_LEN);
    memcpy(ppid_buf, stat_buf + group_array[2].rm_so, group_len);
    ppid_buf[group_len] = '\0';

    append_node(atoi(pid_str), atoi(ppid_buf), comm_buf);

    regfree(&rt);
    fclose(fd);
}

void read_task(const char* pid_str) {
    char path_buf[PATH_BUF_LEN] = {};

    snprintf(path_buf, PATH_BUF_LEN, "%s/%s/task", PROC_PATH, pid_str);
    struct dirent * task_dir_ent = NULL;
    DIR *task_dir = opendir(path_buf);
    while ((task_dir_ent = readdir(task_dir)) != NULL) {
        if (is_a_digit_path(task_dir_ent->d_name) == 0) {
            continue;
        }
        // printf("task_dir_ent->d_name:%s\n", task_dir_ent->d_name);
    }
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

    while ((dir_ent = readdir(proc_dir)) != NULL) {
        if (is_a_digit_path(dir_ent->d_name) == 0) {
            continue;
        }

        if (DT_DIR != dir_ent->d_type) {
            continue;
        }

        read_stat(dir_ent->d_name);
        
        read_task(dir_ent->d_name);
    }

    print_node();
    free_nodes();

    assert(errno == 0);
}
