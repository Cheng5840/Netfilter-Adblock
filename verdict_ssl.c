#include "verdict_ssl.h"
#include <linux/mutex.h>
#include <linux/slab.h>

struct list_head order_head, verdict_head;
static DEFINE_MUTEX(insert_mutex);

void init_verdict(void)
{
    INIT_LIST_HEAD(&order_head);
    INIT_LIST_HEAD(&verdict_head);
}


struct queue_st *insert_order(ktime_t timestamp)
{
    struct list_head *pos;
    struct queue_st *entry;
    struct queue_st *new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new) return NULL;
    new->timestamp = timestamp;

    mutex_lock(&insert_mutex);
    /* 找到第一個 timestamp > new 的節點 */
    list_for_each(pos, &order_head) {
        entry = list_entry(pos, struct queue_st, head);
        if (entry->timestamp > timestamp)
            break;
    }

    list_add_tail(&new->head, pos);
    mutex_unlock(&insert_mutex);
    return new;
}


/*
    Verdict result is store at LSB of pid
    0 for pass
    1 for block
*/
void insert_verdict(pid_t pid)
{
    struct queue_st *verdict;
    verdict = kmalloc(sizeof(struct queue_st), GFP_KERNEL);
    verdict->pid = pid;
    list_add_tail(&verdict->head, &verdict_head);
}

int poll_verdict(ktime_t timestamp, pid_t pid)
{
    struct queue_st *verdict, *first;
    int ret = -1;

    if (list_empty(&order_head) || list_empty(&verdict_head))
        return -1;
    first = list_first_entry(&order_head, struct queue_st, head);
    if (!first || first->timestamp != timestamp)
        return -1;

    list_for_each_entry (verdict, &verdict_head, head) {
        pid_t cpid = verdict->pid & ((1U << 31) - 1);
        int result = (u32) verdict->pid >> 31;
        if (cpid == pid) {
            ret = result;
            break;
        }
    }
    list_del(&verdict->head);
    list_del(&first->head);
    kfree(verdict);
    kfree(first);
    return ret;
}