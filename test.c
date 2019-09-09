#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "monokex.h"
#include "utils.h"

static void check(int condition, const char *error)
{
    if (!condition) {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }
}

static void check_equal(const u8 *a, const u8 *b, size_t size,
                        const char *error)
{
    check(!memcmp(a, b, size), error);
}

typedef struct {
    u8 client_sk  [32];
    u8 server_sk  [32];
    u8 client_seed[32];
    u8 server_seed[32];
    u8 prelude    [32]; int has_prelude;    size_t prelude_size;
    u8 payloads[4][32]; int has_payload[4]; size_t payload_size[4];
} inputs;

void fill_inputs(inputs *i, unsigned nb)
{
    p_random(i->client_sk  , 32);
    p_random(i->server_sk  , 32);
    p_random(i->client_seed, 32);
    p_random(i->server_seed, 32);
    i->prelude_size    = 32;
    i->payload_size[0] = 32;
    i->payload_size[1] = 32;
    i->payload_size[2] = 32;
    i->payload_size[3] = 32;
    i->has_prelude     = nb &  1 ? 1 : 0;
    i->has_payload[0]  = nb &  2 ? 1 : 0;
    i->has_payload[1]  = nb &  4 ? 1 : 0;
    i->has_payload[2]  = nb &  8 ? 1 : 0;
    i->has_payload[3]  = nb & 16 ? 1 : 0;
    if (i->has_prelude   ) { memset(i->prelude    , 0x33, 32); }
    if (i->has_payload[0]) { memset(i->payloads[0], 0x44, 32); }
    if (i->has_payload[1]) { memset(i->payloads[1], 0x55, 32); }
    if (i->has_payload[2]) { memset(i->payloads[2], 0x66, 32); }
    if (i->has_payload[3]) { memset(i->payloads[3], 0x77, 32); }
}

/* void print_inputs(const inputs *i) */
/* { */
/*     printf("client_sk  : "); print_vector(i->client_sk  , 32); */
/*     printf("server_sk  : "); print_vector(i->server_sk  , 32); */
/*     printf("client_seed: "); print_vector(i->client_seed, 32); */
/*     printf("server_seed: "); print_vector(i->server_seed, 32); */
/*     if (i->has_prelude) { */
/*         printf("prelude    : "); */
/*         print_vector(i->prelude, 32); */
/*     } */
/*     FOR (j, 0, 4) { */
/*         if (i->has_payload[j]) { */
/*             printf("payload[%lu]    : ", j); */
/*             print_vector(i->payloads[j], 32); */
/*         } */
/*     } */
/* } */

typedef struct {
    crypto_kex_ctx ctx;
    u8 session_key[ 32];
    u8 extra_key  [ 32];
    u8 remote_key [ 32];
    u8 payloads[4][ 32];
    u8 messages[4][128];
    unsigned msg_num;
} handshake_ctx;


/* static void print_handshake(handshake_ctx *ctx) */
/* { */
/*     printf("session key  ");  print_vector(ctx->session_key,  32); */
/*     printf("extra   key  ");  print_vector(ctx->extra_key  ,  32); */
/*     printf("remote  key  ");  print_vector(ctx->remote_key ,  32); */
/*     printf("payload 1    ");  print_vector(ctx->payloads[0],  32); */
/*     printf("payload 2    ");  print_vector(ctx->payloads[1],  32); */
/*     printf("payload 3    ");  print_vector(ctx->payloads[2],  32); */
/*     printf("payload 4    ");  print_vector(ctx->payloads[3],  32); */
/*     printf("message 1    ");  print_vector(ctx->messages[0], 128); */
/*     printf("message 2    ");  print_vector(ctx->messages[1], 128); */
/*     printf("message 3    ");  print_vector(ctx->messages[2], 128); */
/*     printf("message 4    ");  print_vector(ctx->messages[3], 128); */
/* } */

static void step(handshake_ctx *ctx, u8 *msg, const inputs *i)
{
    do {
        u8 pld_size = ctx->msg_num < 4 && i->has_payload[ctx->msg_num]
                    ? i->payload_size[ctx->msg_num]
                    : 0;
        size_t msg_size;
        crypto_kex_action action = crypto_kex_next_action(&ctx->ctx, &msg_size);
        msg_size += pld_size;
        switch (action) {
        case CRYPTO_KEX_READ: {
            u8 *pld = ctx->payloads[ctx->msg_num];
            check(!crypto_kex_read_p(&ctx->ctx, pld, pld_size, msg, msg_size),
                  "corrupt message");
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_WRITE: {
            const u8 *pld = i->payloads[ctx->msg_num];
            crypto_kex_write_p(&ctx->ctx, msg, msg_size, pld, pld_size);
            memcpy(ctx->messages[ctx->msg_num], msg, msg_size);
            memcpy(ctx->payloads[ctx->msg_num], pld, pld_size);
            ctx->msg_num++;
            break;
        }
        case CRYPTO_KEX_REMOTE_KEY:
            crypto_kex_remote_key(&ctx->ctx, ctx->remote_key);
            break;
        case CRYPTO_KEX_FINAL:
            crypto_kex_final(&ctx->ctx, ctx->session_key, ctx->extra_key);
            break;
        default:
            break;
        }
    } while (crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_NONE &&
             crypto_kex_next_action(&ctx->ctx, 0) != CRYPTO_KEX_READ);
}

static void session(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    const inputs *i)
{
    client_ctx->msg_num = 0;
    server_ctx->msg_num = 0;
    FOR (i, 0, 4) {
        memset(client_ctx->messages[i], 255, 128);
        memset(server_ctx->messages[i], 255, 128);
        memset(client_ctx->payloads[i], 255,  32);
        memset(server_ctx->payloads[i], 255,  32);
    }
    if (i->has_prelude) {
        crypto_kex_add_prelude(&client_ctx->ctx, i->prelude, i->prelude_size);
        crypto_kex_add_prelude(&server_ctx->ctx, i->prelude, i->prelude_size);
    }

    u8 msg[128]; // maximum size of messages without 32 bytes payloads
    while (crypto_kex_next_action(&client_ctx->ctx, 0) != CRYPTO_KEX_NONE ||
           crypto_kex_next_action(&server_ctx->ctx, 0) != CRYPTO_KEX_NONE) {
        step(client_ctx, msg, i);
        step(server_ctx, msg, i);
    }

    /* printf("Client handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(client_ctx); */
    /* printf("\n"); */
    /* printf("Server handshake\n"); */
    /* printf("----------------\n"); */
    /* print_handshake(server_ctx); */

}


static void compare(handshake_ctx *client_ctx,
                    handshake_ctx *server_ctx,
                    const u8 client_key[32],
                    const u8 server_key[32])
{
    check_equal(client_ctx->session_key, server_ctx->session_key, 32,
          "Different session keys");
    check_equal(client_ctx->extra_key, server_ctx->extra_key, 32,
          "Different extra keys");
    if (client_key) {
        check_equal(server_ctx->remote_key, client_key, 32,
                    "Server has wrong client key");
    }
    if (server_key) {
        check_equal(client_ctx->remote_key, server_key, 32,
                    "Client has wrong server key");
    }
    check(client_ctx->msg_num == server_ctx->msg_num,
          "Message numbers don't match");
    FOR (i, 0, 4) {
        check_equal(client_ctx->messages[i], server_ctx->messages[i], 128,
                    "Message doesn't match");
        check_equal(client_ctx->payloads[i], server_ctx->payloads[i],  32,
                    "Payload doesn't match");
    }
}

static void xk1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xk1_client_init(&client_ctx.ctx, client_seed,
                               i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xk1_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void x1k_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1k_client_init(&client_ctx.ctx, client_seed,
                               i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x1k_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}


static void xk_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xk_client_init(&client_ctx.ctx, client_seed,
                               i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xk_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}



static void x1k1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1k1_client_init(&client_ctx.ctx, client_seed,
                                i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x1k1_server_init(&server_ctx.ctx, server_seed,
                                i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void ix_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_ix_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_ix_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void ix1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_ix1_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_ix1_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void i1x1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_i1x1_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_i1x1_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}



static void i1x_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_i1x_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_i1x_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}


static void x1x_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1x_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x1x_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void xx1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xx1_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xx1_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void x1x1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1x1_client_init(&client_ctx.ctx, client_seed,
                              i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x1x1_server_init(&server_ctx.ctx, server_seed,
                              i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}




static void nk1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nk1_client_init(&client_ctx.ctx, client_seed, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_nk1_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}

static void n_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_n_client_init(&client_ctx.ctx, client_seed, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_n_server_init(&server_ctx.ctx, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}

static void nk_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nk_client_init(&client_ctx.ctx, client_seed, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_nk_server_init(&server_ctx.ctx, server_seed,
                               i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}

static void nn_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nn_client_init(&client_ctx.ctx, client_seed);

    handshake_ctx server_ctx;
    crypto_kex_nn_server_init(&server_ctx.ctx, server_seed);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, 0);
}

static void nx_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nx_client_init(&client_ctx.ctx, client_seed);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_nx_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}

static void nx1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_nx1_client_init(&client_ctx.ctx, client_seed);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_nx1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, 0, server_pk);
}


static void xn_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xn_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_xn_server_init(&server_ctx.ctx, server_seed);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}

static void x1n_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x1n_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_x1n_server_init(&server_ctx.ctx, server_seed);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}



static void xx_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_xx_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_xx_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}



static void x_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_x_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_x_server_init(&server_ctx.ctx, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void ik_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_ik_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_ik_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void i1k_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_i1k_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_i1k_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void ik1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_ik1_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_ik1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void i1k1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_i1k1_client_init(&client_ctx.ctx, client_seed,
                             i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_i1k1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}


static void in_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_in_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_in_server_init(&server_ctx.ctx, server_seed);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}

static void i1n_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_i1n_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_i1n_server_init(&server_ctx.ctx, server_seed);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}



static void k_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_k_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void k1k_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k1k_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_k1k_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void kk1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_kk1_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_kk1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void k1k1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k1k1_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_k1k1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}


static void kk_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_kk_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk, server_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_kk_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void kn_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_kn_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_kn_server_init(&server_ctx.ctx, server_seed, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}

static void k1n_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k1n_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);

    handshake_ctx server_ctx;
    crypto_kex_k1n_server_init(&server_ctx.ctx, server_seed, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, 0);
}


static void kx_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_kx_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_kx_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void k1x_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k1x_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_k1x_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}


static void kx1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_kx1_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_kx1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}

static void k1x1_session(unsigned nb)
{
    inputs i;
    fill_inputs(&i, nb);
    u8 client_pk  [32];  crypto_key_exchange_public_key(client_pk, i.client_sk);
    u8 server_pk  [32];  crypto_key_exchange_public_key(server_pk, i.server_sk);
    u8 client_seed[32];  memcpy(client_seed, i.client_seed, 32);
    u8 server_seed[32];  memcpy(server_seed, i.server_seed, 32);

    handshake_ctx client_ctx;
    crypto_kex_k1x1_client_init(&client_ctx.ctx, client_seed, i.client_sk, client_pk);
    memcpy(client_ctx.remote_key, server_pk, 32);

    handshake_ctx server_ctx;
    crypto_kex_k1x1_server_init(&server_ctx.ctx, server_seed, i.server_sk, server_pk, client_pk);
    memcpy(server_ctx.remote_key, client_pk, 32);

    session(&client_ctx, &server_ctx, &i);
    compare(&client_ctx, &server_ctx, client_pk, server_pk);
}




int main()
{
    size_t Z = 32;

    FOR(i, 0, Z) { xk1_session (i); } printf("xk1  session OK\n");
    FOR(i, 0, Z) { x1k_session (i); } printf("x1k  session OK\n");
    FOR(i, 0, Z) { x1x_session (i); } printf("x1x  session OK\n");
    FOR(i, 0, Z) { xx1_session (i); } printf("xx1  session OK\n");
    FOR(i, 0, Z) { x1x1_session(i); } printf("x1x1 session OK\n");
    FOR(i, 0, Z) { xk_session  (i); } printf("xk   session OK\n");
    FOR(i, 0, Z) { x1k1_session(i); } printf("x1k1 session OK\n");
    FOR(i, 0, Z) { ix_session  (i); } printf("ix   session OK\n");
    FOR(i, 0, Z) { ix1_session (i); } printf("ix1  session OK\n");
    FOR(i, 0, Z) { i1x1_session(i); } printf("i1x1 session OK\n");
    FOR(i, 0, Z) { i1x_session (i); } printf("i1x  session OK\n");
    FOR(i, 0, Z) { nk1_session (i); } printf("nk1  session OK\n");
    FOR(i, 0, Z) { nk_session  (i); } printf("nk   session OK\n");
    FOR(i, 0, Z) { n_session   (i); } printf("n    session OK\n");
    FOR(i, 0, Z) { nn_session  (i); } printf("nn   session OK\n");
    FOR(i, 0, Z) { xn_session  (i); } printf("xn   session OK\n");
    FOR(i, 0, Z) { x1n_session (i); } printf("x1n  session OK\n");
    FOR(i, 0, Z) { xx_session  (i); } printf("xx   session OK\n");
    FOR(i, 0, Z) { nx_session  (i); } printf("nx   session OK\n");
    FOR(i, 0, Z) { nx1_session (i); } printf("nx1  session OK\n");
    FOR(i, 0, Z) { x_session   (i); } printf("x    session OK\n");
    FOR(i, 0, Z) { ik_session  (i); } printf("ik   session OK\n");
    FOR(i, 0, Z) { i1k_session (i); } printf("i1k  session OK\n");
    FOR(i, 0, Z) { ik1_session (i); } printf("ik1  session OK\n");
    FOR(i, 0, Z) { i1k1_session(i); } printf("i1k1 session OK\n");
    FOR(i, 0, Z) { in_session  (i); } printf("in   session OK\n");
    FOR(i, 0, Z) { i1n_session (i); } printf("i1n  session OK\n");
    FOR(i, 0, Z) { k_session   (i); } printf("k    session OK\n");
    FOR(i, 0, Z) { k1k_session (i); } printf("k1k  session OK\n");
    FOR(i, 0, Z) { kk1_session (i); } printf("kk1  session OK\n");
    FOR(i, 0, Z) { k1k1_session(i); } printf("k1k1 session OK\n");
    FOR(i, 0, Z) { kk_session  (i); } printf("kk   session OK\n");
    FOR(i, 0, Z) { kn_session  (i); } printf("kn   session OK\n");
    FOR(i, 0, Z) { k1n_session (i); } printf("k1n  session OK\n");
    FOR(i, 0, Z) { kx_session  (i); } printf("kx   session OK\n");
    FOR(i, 0, Z) { k1x_session (i); } printf("k1x  session OK\n");
    FOR(i, 0, Z) { kx1_session (i); } printf("kx1  session OK\n");
    FOR(i, 0, Z) { k1x1_session(i); } printf("k1x1 session OK\n");
    return 0;
}
