
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_BROTLI_ENC_ENCODE_H)
#include <brotli/enc/encode.h>
#else
#include <brotli/encode.h>
#endif


typedef struct {
    ngx_flag_t            enable;

    ngx_hash_t            types;

    ngx_bufs_t            bufs;

    ngx_int_t             quality;
    size_t                win_bits;
    ssize_t               min_length;

    ngx_array_t          *types_keys;
} ngx_http_brotli_conf_t;


typedef struct {
    BrotliEncoderState   *encoder;

    off_t                 content_length;

    size_t                bytes_in;
    size_t                bytes_out;

    ngx_chain_t          *in;
    ngx_chain_t          *free;
    ngx_chain_t          *busy;
    ngx_chain_t          *out;
    ngx_chain_t         **last_out;

    ngx_buf_t            *out_buf;
    ngx_int_t             bufs;

    unsigned              done:1;
    unsigned              sent:1;
    unsigned              last:1;
    unsigned              flush:1;
    unsigned              nomem:1;
} ngx_http_brotli_ctx_t;


static BrotliEncoderState *ngx_http_brotli_filter_create_encoder(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_brotli_filter_push(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_pull(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static ngx_int_t ngx_http_brotli_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx);
static void *ngx_http_brotli_filter_alloc(void *opaque, size_t size);
static void ngx_http_brotli_filter_free(void *opaque, void *address);
static void ngx_http_brotli_filter_cleanup(void *data);

static ngx_int_t ngx_http_brotli_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_brotli_accept_encoding(ngx_str_t *ae);

static ngx_int_t ngx_http_brotli_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_brotli_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_brotli_create_conf(ngx_conf_t *cf);
static char *ngx_http_brotli_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_brotli_filter_init(ngx_conf_t *cf);

static char *ngx_http_brotli_window(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_num_bounds_t  ngx_http_brotli_comp_level_bounds = {
    ngx_conf_check_num_bounds, 0, 11
};

static ngx_conf_post_handler_pt  ngx_http_brotli_window_p =
    ngx_http_brotli_window;


static ngx_command_t  ngx_http_brotli_filter_commands[] = {

    { ngx_string("brotli"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, enable),
      NULL },

    { ngx_string("brotli_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, bufs),
      NULL },

    { ngx_string("brotli_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("brotli_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, quality),
      &ngx_http_brotli_comp_level_bounds },

    { ngx_string("brotli_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, win_bits),
      &ngx_http_brotli_window_p },

    { ngx_string("brotli_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brotli_conf_t, min_length),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_brotli_filter_module_ctx = {
    ngx_http_brotli_add_variables,         /* preconfiguration */
    ngx_http_brotli_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_brotli_create_conf,           /* create location configuration */
    ngx_http_brotli_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_brotli_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_brotli_filter_module_ctx,    /* module context */
    ngx_http_brotli_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_brotli_ratio = ngx_string("brotli_ratio");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_brotli_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t         *h;
    ngx_http_brotli_ctx_t   *ctx;
    ngx_http_brotli_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    if (!conf->enable
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || ngx_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (ngx_http_brotli_ok(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_brotli_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->last_out = &ctx->out;

    ctx->content_length = r->headers_out.content_length_n;

    ngx_http_set_ctx(r, ctx, ngx_http_brotli_filter_module);

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "br");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_brotli_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int                     rc;
    ngx_uint_t              flush;
    ngx_chain_t            *cl;
    ngx_pool_cleanup_t     *cln;
    ngx_http_brotli_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http brotli filter");

    if (ctx->encoder == NULL) {
        ctx->encoder = ngx_http_brotli_filter_create_encoder(r);
        if (ctx->encoder == NULL) {
            goto failed;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            goto failed;
        }

        cln->handler = ngx_http_brotli_filter_cleanup;
        cln->data = ctx;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }

        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_brotli_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            rc = ngx_http_brotli_filter_push(r, ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            rc = ngx_http_brotli_filter_pull(r, ctx);

            if (rc == NGX_OK) {
                break;
            }

            if (rc == NGX_ERROR) {
                goto failed;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_brotli_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            ctx->sent = 1;

            if (ctx->encoder) {
                BrotliEncoderDestroyInstance(ctx->encoder);
                ctx->encoder = NULL;
            }

            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    if (ctx->encoder) {
        BrotliEncoderDestroyInstance(ctx->encoder);
        ctx->encoder = NULL;
    }

    return NGX_ERROR;
}


static BrotliEncoderState *
ngx_http_brotli_filter_create_encoder(ngx_http_request_t *r)
{
    int                      wbits;
    BrotliEncoderState      *encoder;
    ngx_http_brotli_ctx_t   *ctx;
    ngx_http_brotli_conf_t  *conf;

    encoder = BrotliEncoderCreateInstance(ngx_http_brotli_filter_alloc,
                                          ngx_http_brotli_filter_free,
                                          r->pool);
    if (encoder == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "BrotliEncoderCreateInstance() failed");
        return NULL;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    if (!BrotliEncoderSetParameter(encoder, BROTLI_PARAM_QUALITY,
                                   (uint32_t) conf->quality))
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "BrotliEncoderSetParameter(QUALITY, %uD) failed",
                      (uint32_t) conf->quality);
        goto failed;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

    wbits = conf->win_bits;

    if (ctx->content_length > 0) {
        while (ctx->content_length < (1 << (wbits - 1))
               && wbits > BROTLI_MIN_WINDOW_BITS)
        {
            wbits--;
        }
    }

    if (!BrotliEncoderSetParameter(encoder, BROTLI_PARAM_LGWIN,
                                   (uint32_t) wbits)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "BrotliEncoderSetParameter(LGWIN, %uD) failed",
                      (uint32_t) wbits);
        goto failed;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli encoder: lvl:%i win:%d",
                   conf->quality, (1 << wbits));

    return encoder;

failed:

    BrotliEncoderDestroyInstance(encoder);

    return NULL;
}


static ngx_int_t
ngx_http_brotli_filter_push(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx)
{
    size_t                 available_input, input_size, consumed_input, zero;
    ngx_buf_t              *b;
    BrotliEncoderOperation op;
    const uint8_t          *next_input_byte;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli in: %p", ctx->in);

    if (BrotliEncoderIsFinished(ctx->encoder)) {
        return NGX_DECLINED;
    }

    if (ctx->in == NULL) {
        return ctx->last ? NGX_OK : NGX_DECLINED;
    }

    b = ctx->in->buf;

    if (b->last_buf) {
        ctx->last = 1;

    } else if (b->flush) {
        ctx->flush = 1;
    }

    input_size = ngx_buf_size(b);
    if (input_size == 0) {
        if (!ctx->flush && !ctx->last) {
            ctx->in = ctx->in->next;
            return NGX_AGAIN;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "brotli push: %p, size:%uz", b, input_size);

    available_input = input_size;
    op = ctx->last ? BROTLI_OPERATION_FINISH :
         ctx->flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;
    zero = 0;
    next_input_byte = (const uint8_t *) b->pos;
    if (!BrotliEncoderCompressStream(ctx->encoder, op, &available_input,
                                     &next_input_byte, &zero, NULL, NULL)) {
        return NGX_ERROR;
    }

    consumed_input = input_size - available_input;
    b->pos += consumed_input;
    ctx->bytes_in += consumed_input;

    return (consumed_input != 0) ? NGX_AGAIN : NGX_OK;
}


static ngx_int_t
ngx_http_brotli_filter_pull(ngx_http_request_t *r, ngx_http_brotli_ctx_t *ctx)
{
    int           rc;
    size_t        size;
    const uint8_t *out;
    ngx_chain_t  *cl;

    cl = NULL;

    while (BrotliEncoderHasMoreOutput(ctx->encoder)) {

        rc = ngx_http_brotli_filter_get_buf(r, ctx);

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        size = ctx->out_buf->end - ctx->out_buf->last;

        out = BrotliEncoderTakeOutput(ctx->encoder, &size);

        ngx_memcpy(ctx->out_buf->last, out, size);

        ctx->out_buf->last += size;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "brotli out: %p, size:%uz",
                       ctx->out_buf, ngx_buf_size(ctx->out_buf));

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;
    }

    if (ctx->last || ctx->flush) {

        if (cl == NULL) {
            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = ngx_calloc_buf(r->pool);
            if (cl->buf == NULL) {
                return NGX_ERROR;
            }

            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;
        }

        if (ctx->last) {
            ctx->done = 1;
            cl->buf->last_buf = 1;

        } else if (ctx->flush) {
            cl->buf->flush = 1;
        }

        ctx->last = 0;
        ctx->flush = 0;

        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        return NGX_OK;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_brotli_filter_get_buf(ngx_http_request_t *r,
    ngx_http_brotli_ctx_t *ctx)
{
    ngx_http_brotli_conf_t  *conf;

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brotli_filter_module);

    if (ctx->bufs < conf->bufs.num) {
        ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_brotli_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static void *
ngx_http_brotli_filter_alloc(void *opaque, size_t size)
{
    ngx_pool_t  *pool = opaque;
    void        *p;

    p = ngx_palloc(pool, size);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "brotli alloc: %p, size:%uz", p, size);

    return p;
}


static void
ngx_http_brotli_filter_free(void *opaque, void *address)
{
#if (NGX_DEBUG)
    ngx_pool_t  *pool = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "brotli free: %p", address);
#endif
}


static void
ngx_http_brotli_filter_cleanup(void *data)
{
    ngx_http_brotli_ctx_t  *ctx = data;

    if (ctx->encoder) {
        BrotliEncoderDestroyInstance(ctx->encoder);
        ctx->encoder = NULL;
    }
}


static ngx_int_t
ngx_http_brotli_ok(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NGX_DECLINED;
    }

    if (ae->value.len < sizeof("br") - 1) {
        return NGX_DECLINED;
    }

    if (ngx_memcmp(ae->value.data, "br,", sizeof("br,") - 1) != 0
        && ngx_http_brotli_accept_encoding(&ae->value) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brotli_accept_encoding(ngx_str_t *ae)
{
    u_char  *p;

    p = ngx_strcasestrn(ae->data, "br", sizeof("br") - 2);
    if (p == NULL) {
        return NGX_DECLINED;
    }

    if (p == ae->data || (*(p - 1) == ',' || *(p - 1) == ' ')) {

        p += sizeof("br") - 1;

        if (p == ae->data + ae->len || *p == ',' || *p == ';' || *p == ' ') {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_brotli_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_brotli_ratio, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_brotli_ratio_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_brotli_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t              ratio_int, ratio_frac;
    ngx_http_brotli_ctx_t  *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brotli_filter_module);

    if (ctx == NULL || ctx->bytes_out == 0 || !ctx->sent) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN + 3);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ratio_int = (ngx_uint_t) (ctx->bytes_in / ctx->bytes_out);
    ratio_frac = (ngx_uint_t) ((ctx->bytes_in * 100 / ctx->bytes_out) % 100);

    if ((ctx->bytes_in * 1000 / ctx->bytes_out) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        ratio_frac++;

        if (ratio_frac > 99) {
            ratio_int++;
            ratio_frac = 0;
        }
    }

    v->len = ngx_sprintf(v->data, "%ui.%02ui", ratio_int, ratio_frac) - v->data;

    return NGX_OK;
}


static void *
ngx_http_brotli_create_conf(ngx_conf_t *cf)
{
    ngx_http_brotli_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_brotli_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = NGX_CONF_UNSET;

    conf->quality = NGX_CONF_UNSET;
    conf->win_bits = NGX_CONF_UNSET_SIZE;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_brotli_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brotli_conf_t  *prev = parent;
    ngx_http_brotli_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    ngx_conf_merge_value(conf->quality, prev->quality, 6);
    ngx_conf_merge_size_value(conf->win_bits, prev->win_bits, 19);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_brotli_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_brotli_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_brotli_body_filter;

    return NGX_OK;
}


static char *
ngx_http_brotli_window(ngx_conf_t *cf, void *post, void *data)
{
    size_t  *np = data;
    size_t   wbits, wsize, mbits;

    wbits = BROTLI_MAX_WINDOW_BITS;
    mbits = BROTLI_MIN_WINDOW_BITS;

    for (wsize = (1 << wbits); wsize >= (1U << mbits); wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NGX_CONF_OK;
        }

        wbits--;
    }

    return "must be 1k, 2k, 4k, 8k, 16k, 32k, 64k, "
           "128k, 256k, 512k, 1m, 2m, 4m, 8m or 16m";
}
