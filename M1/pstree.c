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
#define NODE_STR "-+-"

typedef struct process_node {
    int pid;
    int ppid;
    int is_thread;
    char comm[COMM_LEN];
    struct process_node *next;
    struct process_node *parent;
    struct process_node *child;
    struct process_node *next_child;
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

void append_node(int pid, int ppid, int thread_parent, const char* comm) {
    process_node *node = (process_node *)malloc(sizeof(process_node));
    assert(node != NULL);
    node->pid = pid;
    
    node->ppid = thread_parent != 0 ? thread_parent : ppid;
    node->is_thread = thread_parent != 0;

    strcpy(node->comm, comm);
    node->next = NULL;
    node->child = NULL;
    node->next_child = NULL;
    node->parent = NULL;

    if (head == NULL) {
        head = node;
        current = head;
        return;
    }

    current->next = node;
    current = current->next;
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

void read_stat(const char* prefix, const char* pid_str, const char *thread_parent) {
    char path_buf[PATH_BUF_LEN] = {};
    snprintf(path_buf, PATH_BUF_LEN, "%s/%s/stat", prefix, pid_str);

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

    append_node(atoi(pid_str), atoi(ppid_buf), thread_parent != NULL ? atoi(thread_parent): 0, comm_buf);

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

        read_stat(path_buf, task_dir_ent->d_name, pid_str);
    }
}

void generate_nodes_tree() {
    if (head == NULL) {
        return;
    }

    process_node *target = head;
    
    while(target != NULL) {
        process_node *target_current_child = NULL;
        process_node *psb_child = head;
        // printf("pid:%d, ppid:%d, comm:%s\n", target->pid, target->ppid, target->comm);
        while (psb_child != NULL) {
            if (psb_child->ppid != target->pid) {
                psb_child = psb_child->next;
                continue;
            }

            // printf("psb_child->pid:%d, psb_child->ppid:%d, psb_child->comm:%s\n", psb_child->pid, psb_child->ppid, psb_child->comm);

            if (target->child == NULL) {
                psb_child->parent = target;
                target->child = psb_child;
                target_current_child = target->child;
            } else {
                target_current_child->next_child = psb_child;
                target_current_child = target_current_child->next_child;
            }

            psb_child = psb_child->next;
        }

        target = target->next;
    }
}

void traverse(process_node * node, int deepth) {
    if (NULL == node) {
        return;
    }

    for (int i = 0; i < deepth; ++i) {
        printf("  ");
    }

    printf("%s(%d)\n", node->comm, node->pid);
    process_node *child = node->child;
    while(child != NULL) {
        traverse(child, deepth + 1);
        child = child->next_child;
    }
}

void print_nodes() {
    if (NULL == head) {
        return;
    }

    // find systemmd
    const int systemmd_pid = 1;
    process_node *temp = head;
    process_node *systemmd = NULL;
    while (temp != NULL) {
        if (temp->pid == systemmd_pid) {
            systemmd = temp;
            break;
        }

        temp = temp->next;
    }

    traverse(systemmd, 0);
    // temp = head;
    // while (temp != NULL)
    // {
    //     printf("%s(%d)\n", temp->comm, temp->pid);
    //     temp = temp->next;
    // }
}

void filter_nodes() {
    if (NULL == head) {
        return;
    }

    process_node *target  = head;
    while (target != NULL) {
        process_node *temp = target;
        process_node *temp_next = temp->next;
        while (temp != NULL && temp_next != NULL) {
            if (temp_next == target) {
                temp = temp_next;
                temp_next = temp->next;
                continue;
            }
            
            if (temp_next->pid == target->pid) {
                temp->next = temp_next->next;
                free(temp_next);
                temp_next = temp->next;
            } else {
                temp = temp_next;
                temp_next = temp->next;
            }
        }

        target = target->next;
    }

    // filter pid=2,ppid=2
    const int filter_id = 2;
    process_node *temp = head;
    while (temp != NULL) {
        if (temp->pid != 2 && temp->ppid != 2) {
            break;
        }
        
        free(temp);
        head = head->next;
        temp = head;
    }

    process_node *temp_next = temp->next;
    while (temp != NULL && temp_next != NULL) {
        if (filter_id != temp_next->pid && filter_id != temp_next->ppid) {
            temp = temp_next;
            temp_next = temp->next;
            continue;
        }

        temp->next = temp_next->next;
        free(temp_next);
        temp_next = temp->next;
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

        read_stat(PROC_PATH, dir_ent->d_name, NULL);
        
        read_task(dir_ent->d_name);
    }

    filter_nodes();
    generate_nodes_tree();
    print_nodes();
    free_nodes();

    assert(errno == 0);
}
