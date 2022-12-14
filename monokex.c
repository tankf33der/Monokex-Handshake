#include "monocypher.h"
#include "monokex.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR(i, start, end)  for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)       crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))

// Message token bytecode
typedef enum { E=1, S=2, EE=3, ES=4, SE=5, SS=6 } action;
static int is_key     (unsigned i) { return i <= S;  }
static int is_exchange(unsigned i) { return i >= EE; }

// Context status flags
#define IS_OK        1 // Allways 1 (becomes zero when wiped)
#define HAS_KEY      2 // True if we have a symmetric key
#define HAS_REMOTE   4 // True if we have the remote DH key
#define GETS_REMOTE  8 // True if the remote key is transmitted to us
#define SHOULD_SEND 16 // Send/receive toggle

typedef uint8_t u8;

// memcpy clone
static void copy(u8 *out, const u8 *in, size_t nb)
{
    FOR(i, 0, nb) out[i] = in[i];
}

static void encrypt(u8 *out, const u8 *in, size_t size, const u8 key[32])
{
    static const u8 zero[8] = {0};
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, zero);
    crypto_chacha20_encrypt(&ctx, out, in, size);
    WIPE_CTX(&ctx);
}

static void mix_hash(u8 after[64], const u8 before[64],
                     const u8 *input, size_t input_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init  (&ctx);
    crypto_blake2b_update(&ctx, before, 64);
    crypto_blake2b_update(&ctx, input, input_size);
    crypto_blake2b_final (&ctx, after);
}

/////////////////////
/// State machine ///
/////////////////////

#define kex_mix_hash crypto_kex_add_prelude // it's the same thing

void kex_mix_hash(crypto_kex_ctx *ctx, const u8 *input, size_t input_size)
{
    mix_hash(ctx->hash, ctx->hash, input, input_size);
}

static void kex_extra_hash(crypto_kex_ctx *ctx, u8 *out)
{
    u8 zero[1] = {0};
    u8 one [1] = {1};
    mix_hash(ctx->hash, ctx->hash, zero, 1); // next chaining hash
    mix_hash(out      , ctx->hash, one , 1); // extra hash
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const u8 secret_key[32],
                           const u8 public_key[32])
{
    u8 tmp[32];
    crypto_x25519(tmp, secret_key, public_key);
    kex_mix_hash(ctx, tmp, 32);
    ctx->flags |= HAS_KEY;
    WIPE_BUFFER(tmp);
}

static void kex_auth(crypto_kex_ctx *ctx, u8 tag[16])
{
    if (!(ctx->flags & HAS_KEY)) { return; }
    u8 tmp[64];
    kex_extra_hash(ctx, tmp);
    copy(tag, tmp, 16);
    WIPE_BUFFER(tmp);
}

static int kex_verify(crypto_kex_ctx *ctx, const u8 tag[16])
{
    if (!(ctx->flags & HAS_KEY)) { return 0; }
    u8 real_tag[64]; // actually 16 useful bytes
    kex_extra_hash(ctx, real_tag);
    if (crypto_verify16(tag, real_tag)) {
        WIPE_CTX(ctx);
        WIPE_BUFFER(real_tag);
        return -1;
    }
    WIPE_BUFFER(real_tag);
    return 0;
}

static void kex_write_raw(crypto_kex_ctx *ctx, u8 *msg,
                          const u8 *src, size_t size)
{
    copy(msg, src, size);
    kex_mix_hash(ctx, msg, size);
}

static void kex_read_raw(crypto_kex_ctx *ctx, u8 *dest,
                         const u8 *msg, size_t size)
{
    kex_mix_hash(ctx, msg, size);
    copy(dest, msg, size);
}

static void kex_write(crypto_kex_ctx *ctx, u8 *msg, const u8 *src, size_t size)
{
    if (!(ctx->flags & HAS_KEY)) {
        kex_write_raw(ctx, msg, src, size);
        return;
    }
    // we have a key, we encrypt
    u8 key[64]; // actually 32 useful bytes
    kex_extra_hash(ctx, key);
    encrypt(msg, src, size, key);
    kex_mix_hash(ctx, msg, size);
    kex_auth(ctx, msg + size);
    WIPE_BUFFER(key);
}

static int kex_read(crypto_kex_ctx *ctx, u8 *dest, const u8 *msg, size_t size)
{
    if (!(ctx->flags & HAS_KEY)) {
        kex_read_raw(ctx, dest, msg, size);
        return 0;
    }
    // we have a key, we decrypt
    u8 key[64]; // actually 32 useful bytes
    kex_extra_hash(ctx, key);
    kex_mix_hash(ctx, msg, size);
    if (kex_verify(ctx, msg + size)) {
        WIPE_BUFFER(key);
        return -1;
    }
    encrypt(dest, msg, size, key);
    WIPE_BUFFER(key);
    return 0;
}

static unsigned kex_next_token(crypto_kex_ctx *ctx)
{
    unsigned token = ctx->messages[0] & 7;
    ctx->messages[0] >>= 3;
    return token;
}

static void kex_next_message(crypto_kex_ctx *ctx)
{
    FOR (i, 0, 3) {
        ctx->messages[i] = ctx->messages[i+1];
    }
    ctx->messages[3] = 0;
}

//////////////////////
/// Initialisation ///
//////////////////////
static void kex_init(crypto_kex_ctx *ctx, const u8 pid[32])
{
    copy(ctx->hash, pid, 64);
    ctx->flags = IS_OK;
}

static void kex_seed(crypto_kex_ctx *ctx, u8 random_seed[32])
{
    copy(ctx->e, random_seed, 32);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->ep, ctx->e);
}

static void kex_locals(crypto_kex_ctx *ctx, const u8 s[32], const u8 sp[32])
{
    if (sp == 0) { crypto_x25519_public_key(ctx->sp, s);      }
    else         { copy                    (ctx->sp, sp, 32); }
    copy(ctx->s, s, 32);
}

//////////////////////
/// Send & receive ///
//////////////////////
int crypto_kex_read (crypto_kex_ctx *ctx, const u8 *m, size_t m_size)
{
    return crypto_kex_read_p(ctx, 0, 0, m, m_size);
}

void crypto_kex_write(crypto_kex_ctx *ctx, u8 *m, size_t m_size)
{
    crypto_kex_write_p(ctx, m, m_size, 0, 0);
}

int crypto_kex_read_p(crypto_kex_ctx *ctx,
                      u8             *p, size_t p_size,
                      const u8       *m, size_t m_size)
{
    // Do nothing & fail if we should not receive
    size_t min_size;
    if (crypto_kex_next_action(ctx, &min_size) != CRYPTO_KEX_READ ||
        m_size < min_size + p_size) {
        WIPE_CTX(ctx);
        return -1;
    }
    // Next time, we'll send
    ctx->flags |= SHOULD_SEND;

    // receive core message
    while (ctx->messages[0] != 0) { // message not yet empty
        size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
        switch (kex_next_token(ctx)) {
        case E : kex_read_raw(ctx, ctx->er, m, 32);  m += 32;  break;
        case S : if (kex_read(ctx, ctx->sr, m, 32)) { return -1; }
                 m += 32 + tag_size;
                 ctx->flags |= HAS_REMOTE;                     break;
        case EE: kex_update_key(ctx, ctx->e, ctx->er);         break;
        case ES: kex_update_key(ctx, ctx->e, ctx->sr);         break;
        case SE: kex_update_key(ctx, ctx->s, ctx->er);         break;
        case SS: kex_update_key(ctx, ctx->s, ctx->sr);         break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Read payload, if any
    if (p != 0) { if (kex_read(ctx, p, m, p_size)) { return -1; } }
    else        { if (kex_verify(ctx, m)         ) { return -1; } }
    return 0;
}

void crypto_kex_write_p(crypto_kex_ctx *ctx,
                        u8             *m, size_t m_size,
                        const u8       *p, size_t p_size)
{
    // Fail if we should not send (the failure is alas delayed)
    size_t min_size;
    if (crypto_kex_next_action(ctx, &min_size) != CRYPTO_KEX_WRITE ||
        m_size < min_size + p_size) {
        WIPE_CTX(ctx);
        return;
    }
    // Next time, we'll receive
    ctx->flags &= ~SHOULD_SEND;

    // Send core message
    while (ctx->messages[0] != 0) { // message not yet empty
        size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
        switch (kex_next_token(ctx)) {
        case E : kex_write_raw (ctx, m, ctx->ep, 32); m += 32;            break;
        case S : kex_write     (ctx, m, ctx->sp, 32); m += 32 + tag_size; break;
        case EE: kex_update_key(ctx, ctx->e, ctx->er);                    break;
        case ES: kex_update_key(ctx, ctx->e, ctx->sr);                    break;
        case SE: kex_update_key(ctx, ctx->s, ctx->er);                    break;
        case SS: kex_update_key(ctx, ctx->s, ctx->sr);                    break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Write payload, if any
    size_t tag_size = ctx->flags & HAS_KEY ? 16 : 0;
    if (p != 0) { kex_write(ctx, m, p, p_size); m += tag_size + p_size; }
    else        { kex_auth (ctx, m);            m += tag_size;          }

    // Pad
    FOR (i, 0, m_size - min_size - p_size) {
        m[i] = 0;
    }
}

///////////////
/// Outputs ///
///////////////
void crypto_kex_remote_key(crypto_kex_ctx *ctx, u8 key[32])
{
    if (!(ctx->flags & HAS_REMOTE)) {
        WIPE_CTX(ctx);
        return;
    }
    copy(key, ctx->sr, 32);
    ctx->flags &= ~GETS_REMOTE;
}

void crypto_kex_final(crypto_kex_ctx *ctx, u8 key[32], u8 extra[32])
{
    if (crypto_kex_next_action(ctx, 0) == CRYPTO_KEX_FINAL) {
        copy(key, ctx->hash, 32);
        if (extra != 0) {
            copy(extra, ctx->hash + 32, 32);
        }
    }
    WIPE_CTX(ctx);
}

///////////////////
/// Next action ///
///////////////////
crypto_kex_action crypto_kex_next_action(const crypto_kex_ctx *ctx,
                                         size_t *next_message_size)
{
    // Next message size (if any)
    if (next_message_size) {
        unsigned has_key = ctx->flags & HAS_KEY ? 16 : 0;
        uint16_t message = ctx->messages[0];
        size_t   size    = 0;
        while (message != 0) {
            if (is_exchange(message & 7)) { has_key = 16;         }
            if (is_key     (message & 7)) { size += 32 + has_key; }
            message >>= 3;
        }
        *next_message_size = size + has_key;
    }
    // Next action
    int should_get_remote =
        (ctx->flags & HAS_REMOTE) &&
        (ctx->flags & GETS_REMOTE);
    return !(ctx->flags & IS_OK)    ? CRYPTO_KEX_NONE
        :  should_get_remote        ? CRYPTO_KEX_REMOTE_KEY
        :  ctx->messages[0] == 0    ? CRYPTO_KEX_FINAL
        :  ctx->flags & SHOULD_SEND ? CRYPTO_KEX_WRITE
        :                             CRYPTO_KEX_READ;
}


///////////
/// XK1 ///
///////////
static const u8 pid_xk1[64] = "Monokex XK1";

void crypto_kex_xk1_client_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        client_sk  [32],
                                const u8        client_pk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_xk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_xk1_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_xk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}

///////////
/// X1K ///
///////////
static const u8 pid_x1k[64] = "Monokex X1K";

void crypto_kex_x1k_client_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        client_sk  [32],
                                const u8        client_pk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S;
    ctx->messages[3] = SE;
}

void crypto_kex_x1k_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}

////////////
/// X1K1 ///
////////////
static const u8 pid_x1k1[64] = "Monokex X1K1";

void crypto_kex_x1k1_client_init(crypto_kex_ctx *ctx,
                                 u8              random_seed[32],
                                 const u8        client_sk  [32],
                                 const u8        client_pk  [32],
                                 const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = S;
    ctx->messages[3] = SE;
}

void crypto_kex_x1k1_server_init(crypto_kex_ctx *ctx,
                                 u8              random_seed[32],
                                 const u8        server_sk  [32],
                                 const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}

//////////
/// IX ///
//////////
static const u8 pid_ix[64] = "Monokex IX";

void crypto_kex_ix_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        client_sk  [32],
                               const u8        client_pk  [32])
{
    kex_init    (ctx, pid_ix);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (S << 9) + (ES << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_ix_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ix);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9) + (SE << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// I1X ///
//////////
static const u8 pid_i1x[64] = "Monokex I1X";

void crypto_kex_i1x_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        client_sk  [32],
                               const u8        client_pk  [32])
{
    kex_init    (ctx, pid_i1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (ES << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_i1x_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// IX1 ///
//////////
static const u8 pid_ix1[64] = "Monokex IX1";

void crypto_kex_ix1_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        client_sk  [32],
                               const u8        client_pk  [32])
{
    kex_init    (ctx, pid_ix1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (S << 9);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

void crypto_kex_ix1_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ix1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

//////////
/// I1X1 ///
//////////
static const u8 pid_i1x1[64] = "Monokex I1X1";

void crypto_kex_i1x1_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32],
                               const u8        client_sk  [32],
                               const u8        client_pk  [32])
{
    kex_init    (ctx, pid_i1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = SE + (ES << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_i1x1_server_init(crypto_kex_ctx *ctx,
                                u8              random_seed[32],
                                const u8        server_sk  [32],
                                const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES + (SE << 3);
    ctx->messages[3] = 0;
}


///////////
/// NK1 ///
///////////
static const u8 pid_nk1[64] = "Monokex NK1";

void crypto_kex_nk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk1);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_nk1_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


/////////
/// X ///
/////////
static const u8 pid_x[64] = "Monokex X";

void crypto_kex_x_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_x_server_init(crypto_kex_ctx *ctx,
                              const u8        server_sk [32],
                              const u8        server_pk [32])
{
    kex_init    (ctx, pid_x);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// IK ///
//////////
static const u8 pid_ik[64] = "Monokex IK";

void crypto_kex_ik_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ik);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_ik_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ik);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// IN ///
//////////
static const u8 pid_in[64] = "Monokex IN";

void crypto_kex_in_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_in);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_in_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32])
{
    kex_init    (ctx, pid_in);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

/////////
/// K ///
/////////
static const u8 pid_k[64] = "Monokex K";

void crypto_kex_k_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (SS << 6);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_k_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (SS << 6);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

/////////
/// K1K ///
/////////
static const u8 pid_k1k[64] = "Monokex K1K";

void crypto_kex_k1k_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_k1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_k1k_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

/////////
/// KK1 ///
/////////
static const u8 pid_kk1[64] = "Monokex KK1";

void crypto_kex_kk1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_kk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (ES << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_kk1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kk1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

/////////
/// K1K1 ///
/////////
static const u8 pid_k1k1[64] = "Monokex K1K1";

void crypto_kex_k1k1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_k1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_k1k1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}


//////////
/// KK ///
//////////
static const u8 pid_kk[64] = "Monokex KK";

void crypto_kex_kk_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_kk);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (SS << 6);
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_kk_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kk);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (SS << 6);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


//////////
/// KN ///
//////////
static const u8 pid_kn[64] = "Monokex KN";

void crypto_kex_kn_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kn);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_kn_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              //const u8        server_sk  [32],
                              //const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kn);
    kex_seed    (ctx, random_seed);
    //kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// K1N ///
//////////
static const u8 pid_k1n[64] = "Monokex K1N";

void crypto_kex_k1n_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1n);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_k1n_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1n);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}



//////////
/// KX ///
//////////
static const u8 pid_kx[64] = "Monokex KX";

void crypto_kex_kx_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kx);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (S << 9) + (ES << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_kx_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kx);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9) + (SE << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// K1X ///
//////////
static const u8 pid_k1x[64] = "Monokex K1X";

void crypto_kex_k1x_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (ES << 9);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_k1x_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

//////////
/// KX1 ///
//////////
static const u8 pid_kx1[64] = "Monokex KX1";

void crypto_kex_kx1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kx1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (S << 9);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

void crypto_kex_kx1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_kx1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

//////////
/// K1X1 ///
//////////
static const u8 pid_k1x1[64] = "Monokex K1X1";

void crypto_kex_k1x1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, client_pk, 32);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = SE + (ES << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_k1x1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_k1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, client_pk, 32);
    copy(ctx->sr, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES + (SE << 3);
    ctx->messages[3] = 0;
}


/////////
/// N ///
/////////
static const u8 pid_n[64] = "Monokex N";

void crypto_kex_n_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_n);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_n_server_init(crypto_kex_ctx *ctx,
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_n);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// NK ///
//////////
static const u8 pid_nk[64] = "Monokex NK";

void crypto_kex_nk_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_nk_server_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_sk  [32],
                                const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


//////////
/// NN ///
//////////
static const u8 pid_nn[64] = "Monokex NN";

void crypto_kex_nn_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32])
{
    kex_init    (ctx, pid_nn);
    kex_seed    (ctx, random_seed);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_nn_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32])
{
    kex_init    (ctx, pid_nn);
    kex_seed    (ctx, random_seed);
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// NX ///
//////////
static const u8 pid_nx[64] = "Monokex NX";

void crypto_kex_nx_client_init(crypto_kex_ctx *ctx,
                               u8             random_seed[32])
{
    kex_init    (ctx, pid_nx);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (ES << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_nx_server_init(crypto_kex_ctx *ctx,
                               u8             random_seed[32],
                               const u8       server_sk  [32], 
                               const u8       server_pk  [32]) 
{
    kex_init    (ctx, pid_nx);
    kex_locals  (ctx, server_sk, server_pk);
    kex_seed    (ctx, random_seed);
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


///////////
/// XK ///
///////////
static const u8 pid_xk[64] = "Monokex XK";

void crypto_kex_xk_client_init(crypto_kex_ctx *ctx,
                               u8             random_seed[32],
                               const u8       client_sk  [32],
                               const u8       client_pk  [32],
                               const u8       server_pk  [32])
{
    kex_init    (ctx, pid_xk);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_xk_server_init(crypto_kex_ctx *ctx,
                                u8            random_seed[32],
                                const u8      server_sk  [32],
                                const u8      server_pk  [32])
{
    kex_init    (ctx, pid_xk);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}


//////////
/// XN ///
//////////
static const u8 pid_xn[64] = "Monokex XN";

void crypto_kex_xn_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32])
{
    kex_init    (ctx, pid_xn);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_xn_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32])
{
    kex_init    (ctx, pid_xn);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}


///////////
/// XX ///
///////////
static const u8 pid_xx[64] = "Monokex XX";

void crypto_kex_xx_client_init(crypto_kex_ctx *ctx,
                               u8             random_seed[32],
                               const u8       client_sk  [32],
                               const u8       client_pk  [32])
{
    kex_init    (ctx, pid_xx);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (ES << 9);
    ctx->messages[2] = S + (SE << 3);
    ctx->messages[3] = 0;
}

void crypto_kex_xx_server_init(crypto_kex_ctx *ctx,
                                u8            random_seed[32],
                                const u8      server_sk  [32],
                                const u8      server_pk  [32])
{
    kex_init    (ctx, pid_xx);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}


///////////
/// NX1 ///
///////////
static const u8 pid_nx1[64] = "Monokex NX1";

void crypto_kex_nx1_client_init(crypto_kex_ctx *ctx,
                               u8              random_seed[32])
{
    kex_init    (ctx, pid_nx1);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

void crypto_kex_nx1_server_init(crypto_kex_ctx *ctx,
                                u8            random_seed[32],
                                const u8      server_sk  [32],
                                const u8      server_pk  [32])
{
    kex_init    (ctx, pid_nx1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

//////////
/// X1N ///
//////////
static const u8 pid_x1n[64] = "Monokex X1N";

void crypto_kex_x1n_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32])
{
    kex_init    (ctx, pid_x1n);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S;
    ctx->messages[3] = SE;
}

void crypto_kex_x1n_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32])
{
    kex_init    (ctx, pid_x1n);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}


//////////
/// X1X ///
//////////
static const u8 pid_x1x[64] = "Monokex X1X";

void crypto_kex_x1x_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32])
{
    kex_init    (ctx, pid_x1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (ES << 9);
    ctx->messages[2] = S;
    ctx->messages[3] = SE;
}

void crypto_kex_x1x_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_x1x);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}


//////////
/// XX1 ///
//////////
static const u8 pid_xx1[64] = "Monokex XX1";

void crypto_kex_xx1_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32])
{
    kex_init    (ctx, pid_xx1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES + (S << 3) + (SE << 6);
    ctx->messages[3] = 0;
}

void crypto_kex_xx1_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_xx1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = SE + (S << 3) + (ES << 6);
    ctx->messages[3] = 0;
}

//////////
/// X1X1 ///
//////////
static const u8 pid_x1x1[64] = "Monokex X1X1";

void crypto_kex_x1x1_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   client_sk  [32],
                              const uint8_t   client_pk  [32])
{
    kex_init    (ctx, pid_x1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= GETS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES + (S << 3);
    ctx->messages[3] = SE;
}

void crypto_kex_x1x1_server_init(crypto_kex_ctx *ctx,
                               uint8_t         random_seed[32],
                               const uint8_t   server_sk  [32],
                               const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_x1x1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = SE + (S << 3);
    ctx->messages[3] = ES;
}

//////////
/// I1N ///
//////////
static const u8 pid_i1n[64] = "Monokex I1N";

void crypto_kex_i1n_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32])
{
    kex_init    (ctx, pid_i1n);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    ctx->flags |= SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_i1n_server_init(crypto_kex_ctx *ctx,
                              u8       random_seed[32])
{
    kex_init    (ctx, pid_i1n);
    kex_seed    (ctx, random_seed);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

//////////
/// I1K ///
//////////
static const u8 pid_i1k[64] = "Monokex I1K";

void crypto_kex_i1k_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (ES << 3) + (S << 6);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_i1k_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1k);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}


//////////
/// IK1 ///
//////////
static const u8 pid_ik1[64] = "Monokex IK1";

void crypto_kex_ik1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ik1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6) + (ES << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

void crypto_kex_ik1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_ik1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// I1K1 ///
//////////
static const u8 pid_i1k1[64] = "Monokex IK1";

void crypto_kex_i1k1_client_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        client_sk  [32],
                              const u8        client_pk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, client_sk, client_pk);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->sr, server_pk, 32);
    ctx->flags |= HAS_REMOTE | SHOULD_SEND;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

void crypto_kex_i1k1_server_init(crypto_kex_ctx *ctx,
                              u8              random_seed[32],
                              const u8        server_sk  [32],
                              const u8        server_pk  [32])
{
    kex_init    (ctx, pid_i1k1);
    kex_seed    (ctx, random_seed);
    kex_locals  (ctx, server_sk, server_pk);
    kex_mix_hash(ctx, ctx->sp, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}
