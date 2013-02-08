/* FS-Cache writeback (client) registration
 *
 * Copyright (C) 2012
 * Written by Hongyi Jia (jiayisuse@gmail.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "internal.h"

static LIST_HEAD(fscache_wbi_list);
static DECLARE_RWSEM(fscache_wbi_list_sem);
atomic_t fscache_wb_interval = ATOMIC_INIT(2000);	/* ms */

struct proc_dir_entry *writeback_proc_entry = NULL;

static struct fscache_wbi default_fscache_wbi = {
	.server	= &fscache_fsdef_index,
	.task	= NULL,
};

/*
 * fscache pagevec for write-back
 */
static DEFINE_SEMAPHORE(fscache_pagevec_sem);

static struct fscache_pagevec {
	unsigned int n;
	struct fscache_wbpage **fsc_pages;
} fscache_wbpages = {
	.n = INIT_WB_PAGES_PER_ROUND,
};

static int fscache_pagevec_init(unsigned n)
{
	fscache_wbpages.fsc_pages = kcalloc(n, sizeof(struct fscache_wbpage *),
					    GFP_KERNEL);
	fscache_wbpages.n = fscache_wbpages.fsc_pages ? n : 0;
	return fscache_wbpages.fsc_pages ? 0 : -ENOMEM;
}

static void fscache_pagevec_realloc(unsigned int n)
{
	struct fscache_wbpage **fsc_pages;

	down(&fscache_pagevec_sem);
	if (fscache_wbpages.n != n) {
		if (n > MAX_WB_PAGES_PER_ROUND)
			n = MAX_WB_PAGES_PER_ROUND;

		fsc_pages = kcalloc(n, sizeof(struct page *),
				    GFP_KERNEL);

		/*
		 * if memory allocation failed, just keep current pagevec
		 */
		if (fsc_pages) {
			kfree(fscache_wbpages.fsc_pages);
			fscache_wbpages.fsc_pages = fsc_pages;
			fscache_wbpages.n = n;
		}
	}
	up(&fscache_pagevec_sem);
}

void fscache_pagevec_get(struct fscache_wbpage ***fsc_pages, unsigned int *n)
{
	down(&fscache_pagevec_sem);
	/* if nomem, give it another try */
	if (!fscache_wbpages.fsc_pages)
		fscache_pagevec_init(INIT_WB_PAGES_PER_ROUND);
	*fsc_pages = fscache_wbpages.fsc_pages;
	*n = fscache_wbpages.n;
	up(&fscache_pagevec_sem);
}

static void fscache_pagevec_clean(void)
{
	down(&fscache_pagevec_sem);
	fscache_wbpages.n = 0;
	kfree(fscache_wbpages.fsc_pages);
	fscache_wbpages.fsc_pages = NULL;
	up(&fscache_pagevec_sem);
}

/*
 * write-back /proc
 */
static int fscache_writeback_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u %u", atomic_read(&fscache_wb_interval),
			       fscache_wbpages.n);
	return 0;
}

static int fscache_writeback_open(struct inode *inode, struct file *file)
{
	return single_open(file, fscache_writeback_show, NULL);
}

static ssize_t fscache_writeback_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	char str[12];
	long int wb_interval, wb_pages;

	if (count > sizeof(str) - 1)
		return 0;

	memset(str, 0, sizeof(str));
	if (copy_from_user(str, buffer, count))
		return -EFAULT;

	sscanf(str, "%ld %ld", &wb_interval, &wb_pages);
	if (wb_interval > 0)
		atomic_set(&fscache_wb_interval, wb_interval);
	if (wb_pages > 0)
		fscache_pagevec_realloc(wb_pages);

	return count;
}

static const struct file_operations fscache_writeback_fops = {
	.owner		= THIS_MODULE,
	.open		= fscache_writeback_open,
	.read		= seq_read,
	.write		= fscache_writeback_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static inline int fscache_init_writeback_proc(void)
{
	if (writeback_proc_entry)
		return 0;

	writeback_proc_entry = proc_create("fs/fscache/writeback",
					   S_IFREG | 0666, NULL,
					   &fscache_writeback_fops);
	return writeback_proc_entry == NULL ? -1 : 0;
}

/*
 * search server cookie from current cookie
 */
static struct fscache_cookie *fscache_get_server(struct fscache_cookie *cookie)
{
	struct fscache_cookie *server, *primary;

	if (cookie == &fscache_fsdef_index ||
			cookie == NULL ||
			cookie->parent == NULL)
		return NULL;

	server = cookie;
	primary = cookie->parent;
	while (primary->parent->parent != &fscache_fsdef_index) {
		server = primary;
		primary = primary->parent;
	}

	return server;
}

static inline bool wbi_has_dirty_io(struct fscache_wbi *wbi)
{
	return atomic_read(&wbi->dirty_pages) > 0;
}

static unsigned long wbi_longest_inactive(void)
{
	return msecs_to_jiffies(atomic_read(&fscache_wb_interval));
}

static void fscache_do_writeback(struct work_struct *work)
{
	struct fscache_cookie *cookie =
		container_of(work, struct fscache_cookie, work);
	struct fscache_wbi *wbi = cookie->wbi;

	BUG_ON(!wbi);

	while (atomic_read(&cookie->dirty_pages) > 0)
		wbi->do_writeback(cookie->netfs_data, cookie->wbc);
}

static int fscache_wbi_writeback(struct fscache_wbi *wbi, bool sync)
{
	struct fscache_cookie *cookie;

	down_read(&wbi->cookie_sem);
	list_for_each_entry(cookie, &wbi->cookie_list, wbi_list) {
		if (cookie->wbc == NULL)
			continue;
		if (sync)
			fscache_do_writeback(&cookie->work);
		else
			queue_work(wbi->wq, &cookie->work);
	}
	up_read(&wbi->cookie_sem);

	return 0;
}

static int fscache_writeback_worker(void *data)
{
	struct fscache_wbi *wbi = data;
	int ret;

	wbi->last_active = jiffies;
	while (!kthread_freezable_should_stop(NULL)) {
		spin_lock(&wbi->lock);
		del_timer(&wbi->wb_timer);
		spin_unlock(&wbi->lock);

		ret = fscache_wbi_writeback(wbi, false);

		if (!ret) {
			spin_lock(&wbi->lock);
			wbi->last_active = jiffies;
			spin_unlock(&wbi->lock);
		}

		if (wbi_has_dirty_io(wbi) || kthread_should_stop())
			continue;

		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

static int fscache_wbi_forker(void *data)
{
	struct fscache_wbi *wbi;
	bool have_dirty_io;
	while (!kthread_should_stop()) {
		struct task_struct *task;
		enum {
			NO_ACTION,
			NEW_THREAD,
			STOP_THREAD,
		} action = NO_ACTION;

		down_read(&fscache_wbi_list_sem);
		list_for_each_entry(wbi, &fscache_wbi_list, link) {
			have_dirty_io = wbi_has_dirty_io(wbi);
			if (!wbi->task && have_dirty_io) {
				action = NEW_THREAD;
				break;
			}

			spin_lock(&wbi->lock);
			if (wbi->task && !have_dirty_io &&
			    time_after(jiffies, wbi->last_active +
				       10 * wbi_longest_inactive())) {
				action = STOP_THREAD;
				task = wbi->task;
				wbi->task = NULL;
				spin_unlock(&wbi->lock);
				break;
			}
			spin_unlock(&wbi->lock);
		}
		up_read(&fscache_wbi_list_sem);

		switch (action) {
		case NEW_THREAD:
			task = kthread_create(fscache_writeback_worker, wbi,
					"fscache_flush-%s",
					wbi->server->def->name);
			if (IS_ERR(task)) {
				fscache_wbi_writeback(wbi, false);
			} else {
				spin_lock_bh(&wbi->lock);
				wbi->task = task;
				spin_unlock_bh(&wbi->lock);
				wake_up_process(task);
			}
			break;

		case STOP_THREAD:
			__set_current_state(TASK_RUNNING);
			kthread_stop(task);
			break;

		case NO_ACTION:
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(5 * wbi_longest_inactive());
			break;
		}
	}
	return 0;
}

static void wbi_wakeup(unsigned long data)
{
	struct fscache_wbi *wbi = (struct fscache_wbi *)data;
	struct task_struct *task;

	spin_lock_bh(&wbi->lock);
	task = wbi->task ? wbi->task : default_fscache_wbi.task;
	spin_unlock_bh(&wbi->lock);

	wake_up_process(task);
}

int __fscache_wbi_init(struct fscache_wbi *wbi,
		       do_writeback_t do_writeback,
		       dev_t s_dev)
{
	unsigned writeback_max_active = 4;
	unsigned cpu_nr;
	char dev[16];

	spin_lock_init(&wbi->lock);
	init_rwsem(&wbi->cookie_sem);
	INIT_LIST_HEAD(&wbi->link);
	INIT_LIST_HEAD(&wbi->cookie_list);
	atomic_set(&wbi->dirty_pages, 0);
	wbi->last_active = 0;
	setup_timer(&wbi->wb_timer, wbi_wakeup, (unsigned long)wbi);
	wbi->task = NULL;
	wbi->server = NULL;
	wbi->do_writeback = do_writeback;

	cpu_nr = num_possible_cpus();
	writeback_max_active =
		clamp_val(cpu_nr, writeback_max_active, WQ_UNBOUND_MAX_ACTIVE);
	snprintf(dev, 16, "%u:%u flusher", MAJOR(s_dev), MINOR(s_dev));
	wbi->wq = alloc_workqueue(dev, WQ_UNBOUND, writeback_max_active);

	if (!wbi->wq) {
		del_timer(&wbi->wb_timer);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(__fscache_wbi_init);

int __fscache_wbi_register(struct fscache_wbi *wbi,
			   struct fscache_cookie *server)
{
	struct fscache_wbi *ptr;
	int ret;

	if (wbi->server)
		return 0;

	down_write(&fscache_wbi_list_sem);

	if (list_empty(&fscache_wbi_list)) {
		ret = fscache_pagevec_init(INIT_WB_PAGES_PER_ROUND);
		if (ret)
			goto pagevec_error;

		ret = fscache_init_writeback_proc();
		if (ret)
			goto proc_error;

		default_fscache_wbi.task = kthread_run(fscache_wbi_forker,
							&default_fscache_wbi,
							"fscache forker");
		if (IS_ERR(default_fscache_wbi.task)) {
			ret = PTR_ERR(default_fscache_wbi.task);
			goto task_error;
		}

		goto register_wbi;
	}

	ret = -EEXIST;
	list_for_each_entry(ptr, &fscache_wbi_list, link) {
		if (ptr->server == server)
			goto already_registered;
	}

register_wbi:
	wbi->server = server;
	list_add(&wbi->link, &fscache_wbi_list);
	ret = 0;

	printk(KERN_NOTICE "FS-Cache: wbi '%p' registered for caching\n", wbi);

already_registered:
	up_write(&fscache_wbi_list_sem);
	return ret;

task_error:
	remove_proc_entry("fs/fscache/writeback", NULL);
proc_error:
	fscache_pagevec_clean();
pagevec_error:
	up_write(&fscache_wbi_list_sem);
	return ret;
}
EXPORT_SYMBOL(__fscache_wbi_register);

void __fscache_wbi_unregister(struct fscache_wbi *wbi)
{
	struct fscache_wbi *ptr;
	struct task_struct *task;

	down_write(&fscache_wbi_list_sem);
	list_for_each_entry(ptr, &fscache_wbi_list, link) {
		if (ptr == wbi) {
			task = NULL;
			spin_lock_bh(&wbi->lock);
			del_timer_sync(&wbi->wb_timer);
			if (wbi->task) {
				task = wbi->task;
				wbi->task = NULL;
			}
			list_del(&wbi->link);
			spin_unlock_bh(&wbi->lock);

			if (task)
				kthread_stop(task);

			fscache_wbi_writeback(wbi, true);

			if (list_empty(&fscache_wbi_list) &&
					default_fscache_wbi.task) {
				kthread_stop(default_fscache_wbi.task);
				default_fscache_wbi.task = NULL;
			}
			up_write(&fscache_wbi_list_sem);
			return;
		}
	}
	up_write(&fscache_wbi_list_sem);
}
EXPORT_SYMBOL(__fscache_wbi_unregister);

void __fscache_wbi_cookie_add(struct fscache_cookie *cookie)
{
	struct fscache_wbi *wbi;
	struct fscache_cookie *server = fscache_get_server(cookie);

	down_read(&fscache_wbi_list_sem);
	list_for_each_entry(wbi, &fscache_wbi_list, link) {
		if (wbi->server == server) {
			down_write(&wbi->cookie_sem);
			list_add(&cookie->wbi_list, &wbi->cookie_list);
			up_write(&wbi->cookie_sem);

			cookie->wbi = wbi;
			INIT_WORK(&cookie->work, fscache_do_writeback);

			up_read(&fscache_wbi_list_sem);
			return;
		}
	}
	up_read(&fscache_wbi_list_sem);
}
EXPORT_SYMBOL(__fscache_wbi_cookie_add);

void __fscache_wbi_cookie_del(struct fscache_cookie *cookie)
{
	struct fscache_wbi *wbi, *tmp;
	struct fscache_cookie *server = fscache_get_server(cookie);

	if (server == NULL)
		return;

	down_read(&fscache_wbi_list_sem);
	list_for_each_entry_safe(wbi, tmp, &fscache_wbi_list, link) {
		if (wbi->server == server) {
			down_write(&wbi->cookie_sem);
			list_del(&cookie->wbi_list);
			up_write(&wbi->cookie_sem);
			if (cookie->wbc) {
				cookie->wbc->sync_mode = WB_SYNC_ALL;
				flush_work_sync(&cookie->work);
			}
			cookie->wbi = NULL;
			up_read(&fscache_wbi_list_sem);
			return;
		}
	}
	up_read(&fscache_wbi_list_sem);
}
EXPORT_SYMBOL(__fscache_wbi_cookie_del);

void fscache_writeback_cleanup(void)
{
	if (default_fscache_wbi.task) {
		kthread_stop(default_fscache_wbi.task);
		default_fscache_wbi.task = NULL;
		fscache_pagevec_clean();
	}
}
