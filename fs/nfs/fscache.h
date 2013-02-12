/* NFS filesystem cache interface definitions
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _NFS_FSCACHE_H
#define _NFS_FSCACHE_H

#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
#include <linux/nfs4_mount.h>
#include <linux/fscache.h>

#ifdef CONFIG_NFS_FSCACHE

/*
 * set of NFS FS-Cache objects that form a superblock key
 */
struct nfs_fscache_key {
	struct rb_node		node;
	struct nfs_client	*nfs_client;	/* the server */

	/* the elements of the unique key - as used by nfs_compare_super() and
	 * nfs_compare_mount_options() to distinguish superblocks */
	struct {
		struct {
			unsigned long	s_flags;	/* various flags
							 * (& NFS_MS_MASK) */
		} super;

		struct {
			struct nfs_fsid fsid;
			int		flags;
			unsigned int	rsize;		/* read size */
			unsigned int	wsize;		/* write size */
			unsigned int	acregmin;	/* attr cache timeouts */
			unsigned int	acregmax;
			unsigned int	acdirmin;
			unsigned int	acdirmax;
		} nfs_server;

		struct {
			rpc_authflavor_t au_flavor;
		} rpc_auth;

		/* uniquifier - can be used if nfs_server.flags includes
		 * NFS_MOUNT_UNSHARED  */
		u8 uniq_len;
		char uniquifier[0];
	} key;
};

/*
 * the track of fscache writen page
 */
struct nfs_fscacheio_descriptor {
	struct list_head pg_list;
	int pg_error;
	int pg_count;
	struct inode *pg_inode;
};

/*
 * fscache-index.c
 */
extern struct fscache_netfs nfs_fscache_netfs;
extern const struct fscache_cookie_def nfs_fscache_server_index_def;
extern const struct fscache_cookie_def nfs_fscache_super_index_def;
extern const struct fscache_cookie_def nfs_fscache_inode_object_def;

extern int nfs_fscache_register(void);
extern void nfs_fscache_unregister(void);

/*
 * fscache.c
 */
extern void nfs_fscache_get_client_cookie(struct nfs_client *);
extern void nfs_fscache_release_client_cookie(struct nfs_client *);

extern void nfs_fscache_get_super_cookie(struct super_block *,
					 const char *,
					 struct nfs_clone_mount *);
extern void nfs_fscache_release_super_cookie(struct super_block *);

extern void nfs_fscache_init_inode_cookie(struct inode *);
extern void nfs_fscache_release_inode_cookie(struct inode *);
extern void nfs_fscache_zap_inode_cookie(struct inode *);
extern void nfs_fscache_set_inode_cookie(struct inode *, struct file *);
extern void nfs_fscache_reset_inode_cookie(struct inode *);

extern void __nfs_fscache_invalidate_page(struct page *, struct inode *);
extern int nfs_fscache_release_page(struct page *, gfp_t);

extern int __nfs_readpage_from_fscache(struct nfs_open_context *,
				       struct inode *, struct page *);
extern int __nfs_readpages_from_fscache(struct nfs_open_context *,
					struct inode *, struct address_space *,
					struct list_head *, unsigned *);
extern void __nfs_readpage_to_fscache(struct inode *, struct page *, int);
extern void __nfs_writepage_to_fscache(struct inode *,
				       struct page *,
				       struct writeback_control *,
				       int);

extern int __nfs_allocpage_from_fscache(struct inode *, struct page *);
extern void __nfs_fscache_prepare_write(struct inode *);

extern int __nfs_fscache_writeback_update(struct inode *);
extern int __nfs_fscache_flush_back(struct inode *,
				    fscache_writepage_t,
				    void *);

extern int __nfs_fscache_writepages_back(struct inode *,
					 fscache_writepage_t,
					 void *);

extern int __nfs_fscache_wbpage_release(struct page *page);
extern int __nfs_fscache_page_end_writeback(struct page *page);

/*
 * wait for a page to complete writing to the cache
 */
static inline void nfs_fscache_wait_on_page_write(struct nfs_inode *nfsi,
						  struct page *page)
{
	if (PageFsCache(page))
		fscache_wait_on_page_write(nfsi->fscache, page);
}

/*
 * release the caching state associated with a page if undergoing complete page
 * invalidation
 */
static inline void nfs_fscache_invalidate_page(struct page *page,
					       struct inode *inode)
{
	if (PageFsCache(page))
		__nfs_fscache_invalidate_page(page, inode);
}

/*
 * Retrieve a page from an inode data storage object.
 */
static inline int nfs_readpage_from_fscache(struct nfs_open_context *ctx,
					    struct inode *inode,
					    struct page *page)
{
	if (NFS_I(inode)->fscache)
		return __nfs_readpage_from_fscache(ctx, inode, page);
	return -ENOBUFS;
}

/*
 * Retrieve a set of pages from an inode data storage object.
 */
static inline int nfs_readpages_from_fscache(struct nfs_open_context *ctx,
					     struct inode *inode,
					     struct address_space *mapping,
					     struct list_head *pages,
					     unsigned *nr_pages)
{
	if (NFS_I(inode)->fscache)
		return __nfs_readpages_from_fscache(ctx, inode, mapping, pages,
						    nr_pages);
	return -ENOBUFS;
}

/*
 * Find or alloc a set of pages from an inode data strorage object
 */
static inline int nfs_allocpage_from_fscache(struct inode *inode,
					     struct page *page)
{
	if (NFS_I(inode)->fscache)
		return __nfs_allocpage_from_fscache(inode, page);
	return -ENOBUFS;
}

/*
 * Store a page newly fetched from the server in an inode data storage object
 * in the cache.
 */
static inline void nfs_readpage_to_fscache(struct inode *inode,
					   struct page *page,
					   int sync)
{
	if (PageFsCache(page))
		__nfs_readpage_to_fscache(inode, page, sync);
}

/*
 * Store a page newly modified by user in an inode data storage object in cache
 */
static inline void nfs_writepage_to_fscache(struct inode *inode,
					    struct page *page,
					    struct writeback_control *wbc,
					    int sync)
{
	if (PageFsCache(page))
		__nfs_writepage_to_fscache(inode, page, wbc, sync);
}

static inline void nfs_fscache_prepare_write(struct inode *inode)
{
	__nfs_fscache_prepare_write(inode);
}

/*
 * Store a page newly modified by user in an inode data storage object in cache
 */
static inline bool nfs_do_writepage_to_fscache(struct inode *inode,
					       struct page *page,
					       struct writeback_control *wbc,
					       int sync)
{
	int ret;

	ret = nfs_allocpage_from_fscache(inode, page);
	if (ret < 0)
		return ret;

	nfs_writepage_to_fscache(inode, page, wbc, sync);

	if (sync)
		fscache_wait_on_page_write(NFS_I(inode)->fscache, page);

	return 0;
}

static inline int nfs_fscache_writepages_back(struct inode *inode,
					      fscache_writepage_t writepage,
					      void *pgio)
{
	return __nfs_fscache_writepages_back(inode, writepage, pgio);
}

static inline int nfs_fscache_writeback_update(struct inode *inode)
{
	return __nfs_fscache_writeback_update(inode);
}

static inline int nfs_fscache_flush_back(struct inode *inode,
					 fscache_writepage_t writepage,
					 void *pgio)
{
	return __nfs_fscache_flush_back(inode, writepage, pgio);
}

static inline int nfs_fscache_wbpage_release(struct page *page)
{
	return __nfs_fscache_wbpage_release(page);
}

static inline int nfs_fscache_page_end_writeback(struct page *page)
{
	return __nfs_fscache_page_end_writeback(page);
}

/*
 * indicate the client caching state as readable text
 */
static inline const char *nfs_server_fscache_state(struct nfs_server *server)
{
	if (server->fscache && (server->options & NFS_OPTION_FSCACHE))
		return "yes";
	return "no ";
}

static inline void nfs_fscacheio_init(struct nfs_fscacheio_descriptor *desc,
		struct inode *inode)
{
	INIT_LIST_HEAD(&desc->pg_list);
	desc->pg_count = 0;
	desc->pg_error = 0;
	desc->pg_inode = inode;
}


#else /* CONFIG_NFS_FSCACHE */
static inline int nfs_fscache_register(void) { return 0; }
static inline void nfs_fscache_unregister(void) {}

static inline void nfs_fscache_get_client_cookie(struct nfs_client *clp) {}
static inline void nfs_fscache_release_client_cookie(struct nfs_client *clp) {}

static inline void nfs_fscache_get_super_cookie(
	struct super_block *sb,
	const char *uniq,
	struct nfs_clone_mount *mntdata)
{
}
static inline void nfs_fscache_release_super_cookie(struct super_block *sb) {}

static inline void nfs_fscache_init_inode_cookie(struct inode *inode) {}
static inline void nfs_fscache_release_inode_cookie(struct inode *inode) {}
static inline void nfs_fscache_zap_inode_cookie(struct inode *inode) {}
static inline void nfs_fscache_set_inode_cookie(struct inode *inode,
						struct file *filp) {}
static inline void nfs_fscache_reset_inode_cookie(struct inode *inode) {}

static inline int nfs_fscache_release_page(struct page *page, gfp_t gfp)
{
	return 1; /* True: may release page */
}
static inline void nfs_fscache_invalidate_page(struct page *page,
					       struct inode *inode) {}
static inline void nfs_fscache_wait_on_page_write(struct nfs_inode *nfsi,
						  struct page *page) {}

static inline int nfs_readpage_from_fscache(struct nfs_open_context *ctx,
					    struct inode *inode,
					    struct page *page)
{
	return -ENOBUFS;
}
static inline int nfs_readpages_from_fscache(struct nfs_open_context *ctx,
					     struct inode *inode,
					     struct address_space *mapping,
					     struct list_head *pages,
					     unsigned *nr_pages)
{
	return -ENOBUFS;
}
static inline void nfs_readpage_to_fscache(struct inode *inode,
					   struct page *page, int sync) {}
static inline void nfs_writepage_to_fscache(struct inode *inode,
					    struct page *page, int sync) {}
static inline int nfs_do_writepage_to_fscache(struct inode *inode,
					      struct page *page, int sync) {}

static inline int nfs_fscache_writepages_back(struct inode *inode,
					      fscache_writepage_t writepage,
					      void *pgio)
{
	return 0;
}

static inline int nfs_fscache_writeback_update(struct inode *inode)
{
	return 0;
}

static inline int nfs_fscache_flush_back(struct inode *inode,
					 writepage_t writepage,
					 void *pgio)
{
	return 0;
}

static inline int nfs_fscache_wbpage_release(struct page *page)
{
	return 0;
}

static inline int nfs_fscache_page_end_writeback(struct page *page)
{
	return 0;
}

static inline void nfs_fscacheio_init(struct nfs_fscacheio_descriptor *desc) {}

static inline const char *nfs_server_fscache_state(struct nfs_server *server)
{
	return "no ";
}

#endif /* CONFIG_NFS_FSCACHE */
#endif /* _NFS_FSCACHE_H */
