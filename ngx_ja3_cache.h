#ifndef _NGX_JA3_CACHE_H_INCLUDED_
#define _NGX_JA3_CACHE_H_INCLUDED_

#define NGX_JA_CACHE_MAGIC 0x4A413334

typedef struct {
    //rbnode PHẢI là field đầu (nginx rule)
    // check time ttl 
     ngx_rbtree_node_t rbnode;


    uint32_t magic;
    uint32_t hash;          /* fast key */
    ngx_msec_t last_seen;

    ngx_ja_fp_t fp;
} ngx_ja_cache_node_t;

typedef struct {
    ngx_rbtree_t      rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_ja_cache_shctx_t;

typedef struct {
    ngx_ja_cache_shctx_t *sh;
    ngx_slab_pool_t      *slab;
} ngx_ja_cache_ctx_t;
#endif /* _NGX_JA3_CACHE_H_INCLUDED_ */