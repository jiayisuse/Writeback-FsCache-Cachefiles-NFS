/* Cache page management and data I/O routines
 *
 * Copyright (C) 2004-2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL PAGE
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>
#include <linux/slab.h>
#include <linux/freezer.h>
#include "internal.h"

extern atomic_t fscache_wb_interval;

/*
 * check to see if a page is being written to the cache
 */
bool __fscache_check_page_write(struct fscache_cookie *cookie, struct page *page)
{
	void *val;

	rcu_read_lock();
	val = radix_tree_lookup(&cookie->stores, page->index);
	rcu_read_unlock();

	return val != NULL;
}
EXPORT_SYMBOL(__fscache_check_page_write);

/*
 * wait for a page to finish being written to the cache
 */
void __fscache_wait_on_page_write(struct fscache_cookie *cookie, struct page *page)
{
	wait_queue_head_t *wq = bit_waitqueue(&cookie->flags, 0);

	wait_event(*wq, !__fscache_check_page_write(cookie, page));
}
EXPORT_SYMBOL(__fscache_wait_on_page_write);

/*
 * helper function that is sleeping on bit locks
 */
static int fscache_wait_bit_killable(void *word)
{
	if (fatal_signal_pending(current))
		return -ERESTARTSYS;
	freezable_schedule();
	return 0;
}

/*
 * decide whether a page can be released, possibly by cancelling a store to it
 * - we're allowed to sleep if __GFP_WAIT is flagged
 */
bool __fscache_maybe_release_page(struct fscache_cookie *cookie,
				  struct page *page,
				  gfp_t gfp)
{
	struct page *xpage;
	void *val;

	_enter("%p,%p,%x", cookie, page, gfp);

	rcu_read_lock();
	val = radix_tree_lookup(&cookie->stores, page->index);
	if (!val) {
		rcu_read_unlock();
		fscache_stat(&fscache_n_store_vmscan_not_storing);
		__fscache_uncache_page(cookie, page);
		return true;
	}

	/* see if the page is actually undergoing storage - if so we can't get
	 * rid of it till the cache has finished with it */
	if (radix_tree_tag_get(&cookie->stores, page->index,
			       FSCACHE_COOKIE_STORING_TAG)) {
		rcu_read_unlock();
		goto page_busy;
	}

	/* the page is pending storage, so we attempt to cancel the store and
	 * discard the store request so that the page can be reclaimed */
	spin_lock(&cookie->stores_lock);
	rcu_read_unlock();

	if (radix_tree_tag_get(&cookie->stores, page->index,
			       FSCACHE_COOKIE_STORING_TAG)) {
		/* the page started to undergo storage whilst we were looking,
		 * so now we can only wait or return */
		spin_unlock(&cookie->stores_lock);
		goto page_busy;
	}

	xpage = radix_tree_delete(&cookie->stores, page->index);
	spin_unlock(&cookie->stores_lock);

	if (xpage) {
		fscache_stat(&fscache_n_store_vmscan_cancelled);
		fscache_stat(&fscache_n_store_radix_deletes);
		ASSERTCMP(xpage, ==, page);
	} else {
		fscache_stat(&fscache_n_store_vmscan_gone);
	}

	wake_up_bit(&cookie->flags, 0);
	if (xpage)
		page_cache_release(xpage);
	__fscache_uncache_page(cookie, page);
	return true;

page_busy:
	/* we might want to wait here, but that could deadlock the allocator as
	 * the work threads writing to the cache may all end up sleeping
	 * on memory allocation */
	fscache_stat(&fscache_n_store_vmscan_busy);
	return false;
}
EXPORT_SYMBOL(__fscache_maybe_release_page);

static struct fscache_wbpage *
fscache_alloc_fscpage(struct fscache_cookie *cookie, struct page *page)
{
	uint64_t i_size;
	unsigned int offset = page->index << PAGE_SHIFT;
	struct fscache_wbpage *fsc_page = kmalloc(sizeof(struct fscache_wbpage),
						  GFP_KERNEL);
	if (!fsc_page)
		return NULL;

	cookie->def->get_attr(cookie->netfs_data, &i_size);
	fsc_page->index = page->index;
	fsc_page->mapping = page->mapping;
	fsc_page->data = (void *)page_private(page);
	fsc_page->start = 0;
	if (i_size - offset < PAGE_SIZE)
		fsc_page->size = i_size - offset;
	else
		fsc_page->size = PAGE_SIZE;

	return fsc_page;
}

static void fscache_process_dirty_write_end(struct fscache_cookie *cookie,
					    struct page *page)
{
	int err;
	struct fscache_wbpage *wb_page;
	int timeout = atomic_read(&fscache_wb_interval);

	wb_page = fscache_alloc_fscpage(cookie, page);
	if (!wb_page)
		goto nomem;

	err = radix_tree_preload(GFP_KERNEL);
	if (err)
		goto free_out;

	spin_lock_bh(&cookie->dirty_lock);
	err = radix_tree_insert(&cookie->dirty_tree, page->index,
				(void *)wb_page);
	if (err) {
		if (err == -EEXIST)
			_debug("already exists %d", err);
		else
			_debug("insert failed %d", err);
		spin_unlock_bh(&cookie->dirty_lock);
		radix_tree_preload_end();
		goto free_out;
	}
	radix_tree_tag_set(&cookie->dirty_tree, page->index,
			   FSCACHE_COOKIE_DIRTY_TAG);
	atomic_inc(&cookie->dirty_pages);
	atomic_inc(&cookie->wbi->dirty_pages);
	spin_unlock_bh(&cookie->dirty_lock);
	radix_tree_preload_end();

	spin_lock_bh(&cookie->wbi->lock);
	if (!timer_pending(&cookie->wbi->wb_timer))
		mod_timer(&cookie->wbi->wb_timer,
			  jiffies + msecs_to_jiffies(5 * timeout));
	spin_unlock_bh(&cookie->wbi->lock);

	clear_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
nomem:
	return;
free_out:
	kfree(wb_page);
	return;
}

/*
 * note that a page has finished being written to the cache
 */
static void fscache_end_page_write(struct fscache_object *object,
				   struct page *page,
				   int dirty)
{
	struct fscache_cookie *cookie;
	struct page *xpage = NULL;

	spin_lock(&object->lock);
	cookie = object->cookie;
	if (cookie) {
		/* process dirty pages to prepare for the following
		 * write-back */
		if (dirty)
			fscache_process_dirty_write_end(cookie, page);

		/* delete the page from the tree if it is now no longer
		 * pending */
		spin_lock(&cookie->stores_lock);
		radix_tree_tag_clear(&cookie->stores, page->index,
				     FSCACHE_COOKIE_STORING_TAG);
		if (!radix_tree_tag_get(&cookie->stores, page->index,
					FSCACHE_COOKIE_PENDING_TAG)) {
			fscache_stat(&fscache_n_store_radix_deletes);
			xpage = radix_tree_delete(&cookie->stores, page->index);
		}
		spin_unlock(&cookie->stores_lock);
		wake_up_bit(&cookie->flags, 0);
	}
	spin_unlock(&object->lock);
	if (xpage)
		page_cache_release(xpage);
}

/*
 * actually apply the changed attributes to a cache object
 */
static void fscache_attr_changed_op(struct fscache_operation *op)
{
	struct fscache_object *object = op->object;
	int ret;

	_enter("{OBJ%x OP%x}", object->debug_id, op->debug_id);

	fscache_stat(&fscache_n_attr_changed_calls);

	if (fscache_object_is_active(object)) {
		fscache_stat(&fscache_n_cop_attr_changed);
		ret = object->cache->ops->attr_changed(object);
		fscache_stat_d(&fscache_n_cop_attr_changed);
		if (ret < 0)
			fscache_abort_object(object);
	}

	_leave("");
}

/*
 * notification that the attributes on an object have changed
 */
int __fscache_attr_changed(struct fscache_cookie *cookie)
{
	struct fscache_operation *op;
	struct fscache_object *object;

	_enter("%p", cookie);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);

	fscache_stat(&fscache_n_attr_changed);

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op) {
		fscache_stat(&fscache_n_attr_changed_nomem);
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	fscache_operation_init(op, fscache_attr_changed_op, NULL);
	op->flags = FSCACHE_OP_ASYNC | (1 << FSCACHE_OP_EXCLUSIVE);

	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_submit_exclusive_op(object, op) < 0)
		goto nobufs;
	spin_unlock(&cookie->lock);
	fscache_stat(&fscache_n_attr_changed_ok);
	fscache_put_operation(op);
	_leave(" = 0");
	return 0;

nobufs:
	spin_unlock(&cookie->lock);
	kfree(op);
	fscache_stat(&fscache_n_attr_changed_nobufs);
	_leave(" = %d", -ENOBUFS);
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_attr_changed);

/*
 * release a retrieval op reference
 */
static void fscache_release_retrieval_op(struct fscache_operation *_op)
{
	struct fscache_retrieval *op =
		container_of(_op, struct fscache_retrieval, op);

	_enter("{OP%x}", op->op.debug_id);

	fscache_hist(fscache_retrieval_histogram, op->start_time);
	if (op->context)
		fscache_put_context(op->op.object->cookie, op->context);

	_leave("");
}

/*
 * allocate a retrieval op
 */
static struct fscache_retrieval *fscache_alloc_retrieval(
	struct address_space *mapping,
	fscache_rw_complete_t end_io_func,
	void *context)
{
	struct fscache_retrieval *op;

	/* allocate a retrieval operation and attempt to submit it */
	op = kzalloc(sizeof(*op), GFP_NOIO);
	if (!op) {
		fscache_stat(&fscache_n_retrievals_nomem);
		return NULL;
	}

	fscache_operation_init(&op->op, NULL, fscache_release_retrieval_op);
	op->op.flags	= FSCACHE_OP_MYTHREAD | (1 << FSCACHE_OP_WAITING);
	op->mapping	= mapping;
	op->end_io_func	= end_io_func;
	op->context	= context;
	op->start_time	= jiffies;
	INIT_LIST_HEAD(&op->to_do);
	return op;
}

/*
 * wait for a deferred lookup to complete
 */
static int fscache_wait_for_deferred_lookup(struct fscache_cookie *cookie)
{
	unsigned long jif;

	_enter("");

	if (!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags)) {
		_leave(" = 0 [imm]");
		return 0;
	}

	fscache_stat(&fscache_n_retrievals_wait);

	jif = jiffies;
	if (wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			fscache_wait_bit_interruptible,
			TASK_INTERRUPTIBLE) != 0) {
		fscache_stat(&fscache_n_retrievals_intr);
		_leave(" = -ERESTARTSYS");
		return -ERESTARTSYS;
	}

	ASSERT(!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags));

	smp_rmb();
	fscache_hist(fscache_retrieval_delay_histogram, jif);
	_leave(" = 0 [dly]");
	return 0;
}

/*
 * wait for an object to become active (or dead)
 */
static int fscache_wait_for_retrieval_activation(struct fscache_object *object,
						 struct fscache_retrieval *op,
						 atomic_t *stat_op_waits,
						 atomic_t *stat_object_dead)
{
	int ret;

	if (!test_bit(FSCACHE_OP_WAITING, &op->op.flags))
		goto check_if_dead;

	_debug(">>> WT");
	fscache_stat(stat_op_waits);
	if (wait_on_bit(&op->op.flags, FSCACHE_OP_WAITING,
			fscache_wait_bit_interruptible,
			TASK_INTERRUPTIBLE) < 0) {
		ret = fscache_cancel_op(&op->op);
		if (ret == 0)
			return -ERESTARTSYS;

		/* it's been removed from the pending queue by another party,
		 * so we should get to run shortly */
		wait_on_bit(&op->op.flags, FSCACHE_OP_WAITING,
			    fscache_wait_bit, TASK_UNINTERRUPTIBLE);
	}
	_debug("<<< GO");

check_if_dead:
	if (unlikely(fscache_object_is_dead(object))) {
		fscache_stat(stat_object_dead);
		return -ENOBUFS;
	}
	return 0;
}

/*
 * read a page from the cache or allocate a block in which to store it
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -ERESTARTSYS - interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   -ENODATA	- no data available in the backing object for this block
 *   0		- dispatched a read - it'll call end_io_func() when finished
 */
int __fscache_read_or_alloc_page(struct fscache_cookie *cookie,
				 struct page *page,
				 fscache_rw_complete_t end_io_func,
				 void *context,
				 gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	int ret;

	_enter("%p,%p,,,", cookie, page);

	fscache_stat(&fscache_n_retrievals);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(page->mapping, end_io_func, context);
	if (!op) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	ASSERTCMP(object->state, >, FSCACHE_OBJECT_LOOKING_UP);

	atomic_inc(&object->n_reads);
	set_bit(FSCACHE_OP_DEC_READ_CNT, &op->op.flags);

	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_retrieval_ops);

	/* pin the netfs read context in case we need to do the actual netfs
	 * read because we've encountered a cache read failure */
	fscache_get_context(object->cookie, op->context);

	/* we wait for the operation to become active, and then process it
	 * *here*, in this thread, and not in the thread pool */
	ret = fscache_wait_for_retrieval_activation(
		object, op,
		__fscache_stat(&fscache_n_retrieval_op_waits),
		__fscache_stat(&fscache_n_retrievals_object_dead));
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	if (test_bit(FSCACHE_COOKIE_NO_DATA_YET, &object->cookie->flags)) {
		fscache_stat(&fscache_n_cop_allocate_page);
		ret = object->cache->ops->allocate_page(op, page, gfp);
		fscache_stat_d(&fscache_n_cop_allocate_page);
		if (ret == 0)
			ret = -ENODATA;
	} else {
		fscache_stat(&fscache_n_cop_read_or_alloc_page);
		ret = object->cache->ops->read_or_alloc_page(op, page, gfp);
		fscache_stat_d(&fscache_n_cop_read_or_alloc_page);
	}

error:
	if (ret == -ENOMEM)
		fscache_stat(&fscache_n_retrievals_nomem);
	else if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_retrievals_intr);
	else if (ret == -ENODATA)
		fscache_stat(&fscache_n_retrievals_nodata);
	else if (ret < 0)
		fscache_stat(&fscache_n_retrievals_nobufs);
	else
		fscache_stat(&fscache_n_retrievals_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock:
	spin_unlock(&cookie->lock);
	kfree(op);
nobufs:
	fscache_stat(&fscache_n_retrievals_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_read_or_alloc_page);

/*
 * read a list of page from the cache or allocate a block in which to store
 * them
 * - we return:
 *   -ENOMEM	- out of memory, some pages may be being read
 *   -ERESTARTSYS - interrupted, some pages may be being read
 *   -ENOBUFS	- no backing object or space available in which to cache any
 *                pages not being read
 *   -ENODATA	- no data available in the backing object for some or all of
 *                the pages
 *   0		- dispatched a read on all pages
 *
 * end_io_func() will be called for each page read from the cache as it is
 * finishes being read
 *
 * any pages for which a read is dispatched will be removed from pages and
 * nr_pages
 */
int __fscache_read_or_alloc_pages(struct fscache_cookie *cookie,
				  struct address_space *mapping,
				  struct list_head *pages,
				  unsigned *nr_pages,
				  fscache_rw_complete_t end_io_func,
				  void *context,
				  gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	int ret;

	_enter("%p,,%d,,,", cookie, *nr_pages);

	fscache_stat(&fscache_n_retrievals);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(*nr_pages, >, 0);
	ASSERT(!list_empty(pages));

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(mapping, end_io_func, context);
	if (!op)
		return -ENOMEM;

	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	atomic_inc(&object->n_reads);
	set_bit(FSCACHE_OP_DEC_READ_CNT, &op->op.flags);

	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_retrieval_ops);

	/* pin the netfs read context in case we need to do the actual netfs
	 * read because we've encountered a cache read failure */
	fscache_get_context(object->cookie, op->context);

	/* we wait for the operation to become active, and then process it
	 * *here*, in this thread, and not in the thread pool */
	ret = fscache_wait_for_retrieval_activation(
		object, op,
		__fscache_stat(&fscache_n_retrieval_op_waits),
		__fscache_stat(&fscache_n_retrievals_object_dead));
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	if (test_bit(FSCACHE_COOKIE_NO_DATA_YET, &object->cookie->flags)) {
		fscache_stat(&fscache_n_cop_allocate_pages);
		ret = object->cache->ops->allocate_pages(
			op, pages, nr_pages, gfp);
		fscache_stat_d(&fscache_n_cop_allocate_pages);
	} else {
		fscache_stat(&fscache_n_cop_read_or_alloc_pages);
		ret = object->cache->ops->read_or_alloc_pages(
			op, pages, nr_pages, gfp);
		fscache_stat_d(&fscache_n_cop_read_or_alloc_pages);
	}

error:
	if (ret == -ENOMEM)
		fscache_stat(&fscache_n_retrievals_nomem);
	else if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_retrievals_intr);
	else if (ret == -ENODATA)
		fscache_stat(&fscache_n_retrievals_nodata);
	else if (ret < 0)
		fscache_stat(&fscache_n_retrievals_nobufs);
	else
		fscache_stat(&fscache_n_retrievals_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock:
	spin_unlock(&cookie->lock);
	kfree(op);
nobufs:
	fscache_stat(&fscache_n_retrievals_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_read_or_alloc_pages);

/*
 * allocate a block in the cache on which to store a page
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -ERESTARTSYS - interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   0		- block allocated
 */
int __fscache_alloc_page(struct fscache_cookie *cookie,
			 struct page *page,
			 gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	int ret;

	_enter("%p,%p,,,", cookie, page);

	fscache_stat(&fscache_n_allocs);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(page->mapping, NULL, NULL);
	if (!op)
		return -ENOMEM;

	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_alloc_ops);

	ret = fscache_wait_for_retrieval_activation(
		object, op,
		__fscache_stat(&fscache_n_alloc_op_waits),
		__fscache_stat(&fscache_n_allocs_object_dead));
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	fscache_stat(&fscache_n_cop_allocate_page);
	ret = object->cache->ops->allocate_page(op, page, gfp);
	fscache_stat_d(&fscache_n_cop_allocate_page);

error:
	if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_allocs_intr);
	else if (ret < 0)
		fscache_stat(&fscache_n_allocs_nobufs);
	else
		fscache_stat(&fscache_n_allocs_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock:
	spin_unlock(&cookie->lock);
	kfree(op);
nobufs:
	fscache_stat(&fscache_n_allocs_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_alloc_page);

/*
 * release a write op reference
 */
static void fscache_release_write_op(struct fscache_operation *_op)
{
	_enter("{OP%x}", _op->debug_id);
}

/*
 * perform the background storage of a page into the cache
 */
static void fscache_write_op(struct fscache_operation *_op)
{
	struct fscache_storage *op =
		container_of(_op, struct fscache_storage, op);
	struct fscache_object *object = op->op.object;
	struct fscache_cookie *cookie;
	struct page *page;
	unsigned n;
	void *results[1];
	int ret;

	_enter("{OP%x,%d}", op->op.debug_id, atomic_read(&op->op.usage));

	spin_lock(&object->lock);
	cookie = object->cookie;
	spin_unlock(&object->lock);
	ret = wait_on_bit(&cookie->flags, FSCACHE_COOKIE_WRITTINGBACK,
			  fscache_wait_bit_killable, TASK_KILLABLE);
	if (ret)
		return;

	spin_lock(&object->lock);

	if (!fscache_object_is_active(object) || !cookie) {
		spin_unlock(&object->lock);
		_leave("");
		return;
	}

	spin_lock(&cookie->stores_lock);

	fscache_stat(&fscache_n_store_calls);

	/* find a page to store */
	page = NULL;
	n = radix_tree_gang_lookup_tag(&cookie->stores, results, 0, 1,
				       FSCACHE_COOKIE_PENDING_TAG);
	if (n != 1)
		goto superseded;
	page = results[0];
	_debug("gang %d [%lx]", n, page->index);

	if (page->index > op->store_limit) {
		fscache_stat(&fscache_n_store_pages_over_limit);
		goto superseded;
	}

	radix_tree_tag_set(&cookie->stores, page->index,
			   FSCACHE_COOKIE_STORING_TAG);
	radix_tree_tag_clear(&cookie->stores, page->index,
			     FSCACHE_COOKIE_PENDING_TAG);

	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);

	fscache_stat(&fscache_n_store_pages);
	fscache_stat(&fscache_n_cop_write_page);
	ret = object->cache->ops->write_page(op, page);
	fscache_stat_d(&fscache_n_cop_write_page);
	fscache_end_page_write(object, page,
			       test_bit(FSCACHE_OP_DIRTY, &_op->flags));
	if (ret < 0) {
		fscache_abort_object(object);
	} else {
		fscache_enqueue_operation(&op->op);
	}

	_leave("");
	return;

superseded:
	/* this writer is going away and there aren't any more things to
	 * write */
	_debug("cease");
	spin_unlock(&cookie->stores_lock);
	clear_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags);
	spin_unlock(&object->lock);
	_leave("");
}

/*
 * request a page be stored in the cache
 * - returns:
 *   -ENOMEM	- out of memory, nothing done
 *   -ENOBUFS	- no backing object available in which to cache the page
 *   0		- dispatched a write - it'll call end_io_func() when finished
 *
 * if the cookie still has a backing object at this point, that object can be
 * in one of a few states with respect to storage processing:
 *
 *  (1) negative lookup, object not yet created (FSCACHE_COOKIE_CREATING is
 *      set)
 *
 *	(a) no writes yet (set FSCACHE_COOKIE_PENDING_FILL and queue deferred
 *	    fill op)
 *
 *	(b) writes deferred till post-creation (mark page for writing and
 *	    return immediately)
 *
 *  (2) negative lookup, object created, initial fill being made from netfs
 *      (FSCACHE_COOKIE_INITIAL_FILL is set)
 *
 *	(a) fill point not yet reached this page (mark page for writing and
 *          return)
 *
 *	(b) fill point passed this page (queue op to store this page)
 *
 *  (3) object extant (queue op to store this page)
 *
 * any other state is invalid
 */
int __fscache_write_page(struct fscache_cookie *cookie,
			 struct page *page,
			 int dirty,
			 gfp_t gfp)
{
	struct fscache_storage *op;
	struct fscache_object *object;
	int ret;

	_enter("%p,%x,", cookie, (u32) page->flags);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERT(PageFsCache(page));

	fscache_stat(&fscache_n_stores);

	op = kzalloc(sizeof(*op), GFP_NOIO);
	if (!op)
		goto nomem;

	fscache_operation_init(&op->op, fscache_write_op,
			       fscache_release_write_op);
	op->op.flags = FSCACHE_OP_ASYNC | (1 << FSCACHE_OP_WAITING);
	if (dirty)
		set_bit(FSCACHE_OP_DIRTY, &op->op.flags);

	ret = radix_tree_preload(gfp & ~__GFP_HIGHMEM);
	if (ret < 0)
		goto nomem_free;

	ret = -ENOBUFS;
	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);
	if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
		goto nobufs;

	/* add the page to the pending-storage radix tree on the backing
	 * object */
	spin_lock(&object->lock);
	spin_lock(&cookie->stores_lock);

	_debug("store limit %llx", (unsigned long long) object->store_limit);

	ret = radix_tree_insert(&cookie->stores, page->index, page);
	if (ret < 0) {
		if (ret == -EEXIST && dirty)
			goto continue_write;
		if (ret == -EEXIST)
			goto already_queued;
		_debug("insert failed %d", ret);
		goto nobufs_unlock_obj;
	}

continue_write:
	radix_tree_tag_set(&cookie->stores, page->index,
			   FSCACHE_COOKIE_PENDING_TAG);
	page_cache_get(page);

	/* we only want one writer at a time, but we do need to queue new
	 * writers after exclusive ops */
	if (test_and_set_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags) &&
			!dirty)
		goto already_pending;

	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);

	op->op.debug_id	= atomic_inc_return(&fscache_op_debug_id);
	op->store_limit = object->store_limit;

	if (fscache_submit_op(object, &op->op) < 0)
		goto submit_failed;

	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	fscache_stat(&fscache_n_store_ops);
	fscache_stat(&fscache_n_stores_ok);

	/* the work queue now carries its own ref on the object */
	fscache_put_operation(&op->op);
	_leave(" = 0");
	return 0;

already_queued:
	fscache_stat(&fscache_n_stores_again);
already_pending:
	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);
	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	kfree(op);
	fscache_stat(&fscache_n_stores_ok);
	_leave(" = 0");
	return 0;

submit_failed:
	spin_lock(&cookie->stores_lock);
	radix_tree_delete(&cookie->stores, page->index);
	spin_unlock(&cookie->stores_lock);
	page_cache_release(page);
	ret = -ENOBUFS;
	goto nobufs;

nobufs_unlock_obj:
	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);
nobufs:
	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	kfree(op);
	fscache_stat(&fscache_n_stores_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;

nomem_free:
	kfree(op);
nomem:
	fscache_stat(&fscache_n_stores_oom);
	_leave(" = -ENOMEM");
	return -ENOMEM;
}
EXPORT_SYMBOL(__fscache_write_page);

inline void __fscache_set_wbc(struct fscache_cookie *cookie,
		       struct writeback_control *wbc)
{
	cookie->wbc = wbc;
}
EXPORT_SYMBOL(__fscache_set_wbc);

/*
 * Adjust backing store limit. Should be called before storing dirty
 * pages into fscache
 */
void __fscache_prepare_writeback(struct fscache_cookie *cookie)
{
	uint64_t i_size;
	struct fscache_object *object;

	cookie->def->get_attr(cookie->netfs_data, &i_size);

	spin_lock(&cookie->lock);
	if (hlist_empty(&cookie->backing_objects)) {
		spin_unlock(&cookie->lock);
		return;
	}
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);
	fscache_set_store_limit(object, i_size);
	spin_unlock(&cookie->lock);
}
EXPORT_SYMBOL(__fscache_prepare_writeback);

/*
 * totally a void function to be used to call __fscache_read_or_alloc_page
 */
static void fscache_wb_read_complete(struct page *page, void *contex, int error)
{
	return;
}

/*
 * allocate a new page to serve the write-back specifically
 */
static struct page *
fscache_create_writeback_page(struct fscache_wbpage *fsc_page)
{
	struct page *page;
	page = alloc_page(GFP_KERNEL | __GFP_HIGHMEM | __GFP_COLD);
	if (unlikely(!page))
		return NULL;

	page->index = fsc_page->index;
	page->mapping = fsc_page->mapping;
	page->mapping->host = fsc_page->mapping->host;
	fsc_page->wb_page = page;
	ClearPagePrivate(page);
	SetPageFsCache(page);
	SetPageUptodate(page);
	get_page(page);
	lock_page(page);

	return page;
}

/*
 * write back dirty pages stored in cache
 */
int __fscache_writeback_pages(struct fscache_cookie *cookie,
			      fscache_writepage_t writepage,
			      void *data)
{
	int ret = 0;
	int i;
	int done;
	struct page *page;
	struct fscache_wbpage **fsc_pages, *xfsc_page;
	unsigned vec_size, nr;

	fscache_pagevec_get(&fsc_pages, &vec_size);
	if (fsc_pages == NULL)
		return -ENOMEM;

	ret = wait_on_bit_lock(&cookie->flags, FSCACHE_COOKIE_WRITTINGBACK,
			       fscache_wait_bit_killable, TASK_KILLABLE);
	if (ret)
		goto bit_error;

retry:
	spin_lock(&cookie->dirty_lock);
	nr = radix_tree_gang_lookup_tag(&cookie->dirty_tree,
					(void **)fsc_pages,
					0, (pgoff_t)vec_size,
					FSCACHE_COOKIE_DIRTY_TAG);
	spin_unlock(&cookie->dirty_lock);

	done = 1;
	for (i = 0; i < nr; i++) {
		page = fscache_create_writeback_page(fsc_pages[i]);
		if (page == NULL) {
			ret = -ENOMEM;
			goto nomem;
		}

		ret = __fscache_read_or_alloc_page(cookie, page,
						   fscache_wb_read_complete,
						   NULL, GFP_KERNEL);
		switch (ret) {
		case 0:
			_debug("    readpage_from_fscache: BIO submitted\n");
			break;
		case -ENOBUFS:
		case -ENODATA:
			_debug("    readpage_from_fscache error %d\n", ret);
			goto read_error;
			break;
		default:
			goto read_error;
			_debug("    readpage_from_fscache %d\n", ret);
		}

		ret = (*writepage)(fsc_pages[i], data);

		if (!ret) {
			spin_lock(&cookie->dirty_lock);
			radix_tree_tag_clear(&cookie->dirty_tree, page->index,
					FSCACHE_COOKIE_DIRTY_TAG);
			xfsc_page = radix_tree_delete(&cookie->dirty_tree,
					page->index);
			spin_unlock(&cookie->dirty_lock);
			atomic_dec(&cookie->dirty_pages);
			atomic_dec(&cookie->wbi->dirty_pages);
			if (xfsc_page)
				kfree(xfsc_page);
		} else
			done = 0;
read_error:
		fscache_wbpage_release(page);
	}
	if (!done)
		goto retry;

nomem:
	clear_bit_unlock(FSCACHE_COOKIE_WRITTINGBACK, &cookie->flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&cookie->flags, FSCACHE_COOKIE_WRITTINGBACK);
bit_error:
	cond_resched();
	return ret;
}
EXPORT_SYMBOL(__fscache_writeback_pages);

/*
 * flush all dirty pages stored in cache
 */
inline int __fscache_flush_back(struct fscache_cookie *cookie,
				fscache_writepage_t writepage,
				void *data)
{
	int ret = 0;

	while (atomic_read(&cookie->dirty_pages)) {
		ret = __fscache_writeback_pages(cookie, writepage, data);
		if (ret)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(__fscache_flush_back);

/*
 * Should be called when handling fscache writeback page, other than
 * page_cache_release(). PageFsCache() should be checked before calling this.
 */
inline int __fscache_wbpage_release(struct page *page)
{
	if (page_count(page) != 1)
		goto out;

	ClearPageFsCache(page);
	page->mapping = NULL;
out:
	put_page(page);

	return 0;
}
EXPORT_SYMBOL(__fscache_wbpage_release);

/*
 * Should be called when handling fscache writeback page.
 * PageFsCache() should be checked before calling this.
 */
inline int __fscache_page_end_writeback(struct page *page)
{
	if (!TestClearPageWriteback(page))
		BUG();

	return __fscache_wbpage_release(page);
}
EXPORT_SYMBOL(__fscache_page_end_writeback);

/*
 * remove a page from the cache
 */
void __fscache_uncache_page(struct fscache_cookie *cookie, struct page *page)
{
	struct fscache_object *object;

	_enter(",%p", page);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	fscache_stat(&fscache_n_uncaches);

	/* cache withdrawal may beat us to it */
	if (!PageFsCache(page))
		goto done;

	/* get the object */
	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects)) {
		ClearPageFsCache(page);
		goto done_unlock;
	}

	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	/* there might now be stuff on disk we could read */
	clear_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);

	/* only invoke the cache backend if we managed to mark the page
	 * uncached here; this deals with synchronisation vs withdrawal */
	if (TestClearPageFsCache(page) &&
	    object->cache->ops->uncache_page) {
		/* the cache backend releases the cookie lock */
		fscache_stat(&fscache_n_cop_uncache_page);
		object->cache->ops->uncache_page(object, page);
		fscache_stat_d(&fscache_n_cop_uncache_page);
		goto done;
	}

done_unlock:
	spin_unlock(&cookie->lock);
done:
	_leave("");
}
EXPORT_SYMBOL(__fscache_uncache_page);

/**
 * fscache_mark_pages_cached - Mark pages as being cached
 * @op: The retrieval op pages are being marked for
 * @pagevec: The pages to be marked
 *
 * Mark a bunch of netfs pages as being cached.  After this is called,
 * the netfs must call fscache_uncache_page() to remove the mark.
 */
void fscache_mark_pages_cached(struct fscache_retrieval *op,
			       struct pagevec *pagevec)
{
	struct fscache_cookie *cookie = op->op.object->cookie;
	unsigned long loop;

#ifdef CONFIG_FSCACHE_STATS
	atomic_add(pagevec->nr, &fscache_n_marks);
#endif

	for (loop = 0; loop < pagevec->nr; loop++) {
		struct page *page = pagevec->pages[loop];

		_debug("- mark %p{%lx}", page, page->index);
		if (TestSetPageFsCache(page)) {
			static bool once_only;
			if (!once_only) {
				once_only = true;
				printk(KERN_WARNING "FS-Cache:"
				       " Cookie type %s marked page %lx"
				       " multiple times\n",
				       cookie->def->name, page->index);
			}
		}
	}

	if (cookie->def->mark_pages_cached)
		cookie->def->mark_pages_cached(cookie->netfs_data,
					       op->mapping, pagevec);
	pagevec_reinit(pagevec);
}
EXPORT_SYMBOL(fscache_mark_pages_cached);

/*
 * Uncache all the pages in an inode that are marked PG_fscache, assuming them
 * to be associated with the given cookie.
 */
void __fscache_uncache_all_inode_pages(struct fscache_cookie *cookie,
				       struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct pagevec pvec;
	pgoff_t next;
	int i;

	_enter("%p,%p", cookie, inode);

	if (!mapping || mapping->nrpages == 0) {
		_leave(" [no pages]");
		return;
	}

	pagevec_init(&pvec, 0);
	next = 0;
	do {
		if (!pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE))
			break;
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			next = page->index;
			if (PageFsCache(page)) {
				__fscache_wait_on_page_write(cookie, page);
				__fscache_uncache_page(cookie, page);
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	} while (++next);

	_leave("");
}
EXPORT_SYMBOL(__fscache_uncache_all_inode_pages);
