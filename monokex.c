#include "monocypher.h"
#include "monokex.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR(i, start, end)   for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)        crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)  crypto_wipe(buffer, sizeof(buffer))

// Message token bytecode
#define E   1 // ephemeral key
#define S   2 // static key (plaintext)
#define Sk  3 // static key (encrypted)
#define EE  4 // ee exchange
#define ES  5 // es exchange
#define SE  6 // se exchange
#define SS  7 // ss exchange

// Context status flags
#define IS_OK        1 // Allways 1 (becomes zero when wiped)
#define HAS_KEY      2 // True if we have a symmetric key
#define HAS_REMOTE   4 // True if we have the remote DH key
#define GETS_REMOTE  8 // True if the remote key is transmitted to us
#define SHOULD_SEND 16 // Send/receive toggle

typedef uint8_t u8;

// memcmp clone
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

void kex_extra_hash(crypto_kex_ctx *ctx, u8 *out)
{
    u8 zero[1] = {0};
    u8 one [1] = {1};
    mix_hash(ctx->hash, ctx->hash, zero, 1); // next chaining hash
    mix_hash(out      , ctx->hash, one , 1); // extra hash
}

static void kex_update_key(crypto_kex_ctx *ctx,
                           const u8        secret_key[32],
                           const u8        public_key[32])
{
    u8 tmp[32];
    crypto_x25519(tmp, secret_key, public_key);
    kex_mix_hash(ctx, tmp, 32);
    ctx->flags |= HAS_KEY;
    WIPE_BUFFER(tmp);
}

static void kex_auth(crypto_kex_ctx *ctx, u8 tag[16])
{
    u8 tmp[64];
    kex_extra_hash(ctx, tmp);
    copy(tag, tmp, 16);
    WIPE_BUFFER(tmp);
}

static int kex_verify(crypto_kex_ctx *ctx, const u8 tag[16])
{
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

static void kex_encrypt(crypto_kex_ctx *ctx,
                        u8 *msg, const u8 *src, size_t size)
{
    u8 key[64]; // actually 32 useful bytes
    kex_extra_hash(ctx, key);
    encrypt(msg, src, size, key);

    kex_mix_hash(ctx, msg, size);
    kex_auth(ctx, msg + size);
     WIPE_BUFFER(key);
}

static int kex_decrypt(crypto_kex_ctx *ctx,
                       u8 *dest, const u8 *msg, size_t size)
{
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
    if (token == S && (ctx->flags & HAS_KEY)) { token = Sk; }
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
    WIPE_CTX(ctx);
    copy(ctx->hash, pid, 32);
    ctx->flags = IS_OK; // wiping the context sets it to false
}

static void kex_seed(crypto_kex_ctx *ctx, u8 random_seed[32])
{
    copy(ctx->local_ske, random_seed, 32);
    crypto_wipe(random_seed, 32); // auto wipe seed to avoid reuse
    crypto_x25519_public_key(ctx->local_pke, ctx->local_ske);
}

static void kex_locals(crypto_kex_ctx *ctx,
                       const u8        local_sk[32],
                       const u8        local_pk[32])
{
    if (local_pk == 0) crypto_x25519_public_key(ctx->local_pk, local_sk);
    else               copy                    (ctx->local_pk, local_pk, 32);
    copy(ctx->local_sk, local_sk, 32);
}

//////////////////////
/// Send & receive ///
//////////////////////
void crypto_kex_write(crypto_kex_ctx *ctx,
                      u8 *message, size_t message_size)
{
    crypto_kex_write_p(ctx, message, message_size, 0, 0);
}

int crypto_kex_read(crypto_kex_ctx *ctx,
                    const u8 *message, size_t message_size)
{
    return crypto_kex_read_p(ctx, 0, 0, message, message_size);
}

#define SKIP(i)   m += (i); m_size -= (i)
#define ABSORB(i) kex_mix_hash(ctx, m, i); SKIP(i)

void crypto_kex_write_p(crypto_kex_ctx *ctx,
                        u8       *m, size_t m_size,
                        const u8 *p, size_t p_size)
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
        switch (kex_next_token(ctx)) {
        case E : copy(m, ctx->local_pke, 32);             ABSORB(32);  break;
        case S : copy(m, ctx->local_pk , 32);             ABSORB(32);  break;
        case Sk: kex_encrypt(ctx, m, ctx->local_pk, 32);  SKIP(48);    break;
        case EE: kex_update_key(ctx, ctx->local_ske, ctx->remote_pke); break;
        case ES: kex_update_key(ctx, ctx->local_ske, ctx->remote_pk ); break;
        case SE: kex_update_key(ctx, ctx->local_sk , ctx->remote_pke); break;
        case SS: kex_update_key(ctx, ctx->local_sk , ctx->remote_pk ); break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Authentictate (possibly with payload)
    if (ctx->flags & HAS_KEY) {
        if (p != 0) { kex_encrypt(ctx, m, p, p_size); SKIP(p_size); }
        else        { kex_auth(ctx, m);                             }
        SKIP(16); // final authentication tag
    } else {
        if (p != 0) {
            copy(m, p, p_size);
            ABSORB(p_size);
        }
    }

    // Pad
    FOR (i, 0, m_size) { m[i] = 0; }
}

int crypto_kex_read_p(crypto_kex_ctx *ctx,
                      u8       *p, size_t p_size,
                      const u8 *m, size_t m_size)
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
        switch (kex_next_token(ctx)) {
        case E : copy(ctx->remote_pke, m, 32);  ABSORB(32);            break;
        case S : copy(ctx->remote_pk , m, 32);  ABSORB(32);
                 ctx->flags |= HAS_REMOTE;                             break;
        case Sk: if (kex_decrypt(ctx, ctx->remote_pk, m, 32)) { return -1; }
                 SKIP(48);
                 ctx->flags |= HAS_REMOTE;                             break;
        case EE: kex_update_key(ctx, ctx->local_ske, ctx->remote_pke); break;
        case ES: kex_update_key(ctx, ctx->local_ske, ctx->remote_pk ); break;
        case SE: kex_update_key(ctx, ctx->local_sk , ctx->remote_pke); break;
        case SS: kex_update_key(ctx, ctx->local_sk , ctx->remote_pk ); break;
        default:; // never happens
        }
    }
    kex_next_message(ctx);

    // Verify (possibly with payload)
    if (ctx->flags & HAS_KEY) {
        int error;
        if (p != 0) { error = kex_decrypt(ctx, p, m, p_size); }
        else        { error = kex_verify(ctx, m);             }
        if (error) { return -1; }
    } else {
        if (p != 0) {
            copy(p, m, p_size);
            kex_mix_hash(ctx, m, p_size);
        }
    }
    return 0;
}

///////////////
/// Outputs ///
///////////////
void crypto_kex_remote_key(crypto_kex_ctx *ctx, uint8_t key[32])
{
    if (!(ctx->flags & HAS_REMOTE)) {
        WIPE_CTX(ctx);
        return;
    }
    copy(key, ctx->remote_pk, 32);
    ctx->flags &= ~GETS_REMOTE;
}

void crypto_kex_final(crypto_kex_ctx *ctx,
                                u8 key[32], u8 extra[32])
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
            if ((message & 7) >= 4) { has_key = 16;         }
            if ((message & 7) <= 3) { size += 32 + has_key; }
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
static const u8 pid_xk1[32] = "Monokex XK1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}

///////////
/// X1K ///
///////////
static const u8 pid_x1k[32] = "Monokex X1K";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}


////////////
/// X1K1 ///
////////////
static const u8 pid_x1k1[32] = "Monokex X1K1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = S;
    ctx->messages[3] = ES;
}

//////////
/// IX ///
//////////
static const u8 pid_ix[32] = "Monokex IX";

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
static const u8 pid_i1x[32] = "Monokex I1X";

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
static const u8 pid_ix1[32] = "Monokex IX1";

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
static const u8 pid_i1x1[32] = "Monokex I1X1";

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
static const u8 pid_nk1[32] = "Monokex NK1";

void crypto_kex_nk1_client_init(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk1);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


/////////
/// X ///
/////////
static const u8 pid_x[32] = "Monokex X";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// IK ///
//////////
static const u8 pid_ik[32] = "Monokex IK";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6) + (SS << 9);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// IN ///
//////////
static const u8 pid_in[32] = "Monokex IN";

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
static const u8 pid_k[32] = "Monokex K";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (SS << 6);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

/////////
/// K1K ///
/////////
static const u8 pid_k1k[32] = "Monokex K1K";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

/////////
/// KK1 ///
/////////
static const u8 pid_kk1[32] = "Monokex KK1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

/////////
/// K1K1 ///
/////////
static const u8 pid_k1k1[32] = "Monokex K1K1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}


//////////
/// KK ///
//////////
static const u8 pid_kk[32] = "Monokex KK";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (SS << 6);
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


//////////
/// KN ///
//////////
static const u8 pid_kn[32] = "Monokex KN";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// K1N ///
//////////
static const u8 pid_k1n[32] = "Monokex K1N";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}



//////////
/// KX ///
//////////
static const u8 pid_kx[32] = "Monokex KX";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9) + (SE << 12);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// K1X ///
//////////
static const u8 pid_k1x[32] = "Monokex K1X";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6) + (SE << 9);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}

//////////
/// KX1 ///
//////////
static const u8 pid_kx1[32] = "Monokex KX1";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (S << 9);
    ctx->messages[2] = SE;
    ctx->messages[3] = 0;
}

//////////
/// K1X1 ///
//////////
static const u8 pid_k1x1[32] = "Monokex K1X1";

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
    copy(ctx->remote_pk, client_pk, 32);
    ctx->flags |= HAS_REMOTE;
    ctx->messages[0] = E;
    ctx->messages[1] = E + (EE << 3) + (S << 6);
    ctx->messages[2] = ES + (SE << 3);
    ctx->messages[3] = 0;
}


/////////
/// N ///
/////////
static const u8 pid_n[32] = "Monokex N";

void crypto_kex_n_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_n);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = 0;
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// NK ///
//////////
static const u8 pid_nk[32] = "Monokex NK";

void crypto_kex_nk_client_init(crypto_kex_ctx *ctx,
                              uint8_t         random_seed[32],
                              const uint8_t   server_pk  [32])
{
    kex_init    (ctx, pid_nk);
    kex_seed    (ctx, random_seed);
    kex_mix_hash(ctx, server_pk, 32);
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}


//////////
/// NN ///
//////////
static const u8 pid_nn[32] = "Monokex NN";

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
static const u8 pid_nx[32] = "Monokex NX";

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
static const u8 pid_xk[32] = "Monokex XK";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = S + (ES << 3);
    ctx->messages[3] = 0;
}


//////////
/// XN ///
//////////
static const u8 pid_xn[32] = "Monokex XN";

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
static const u8 pid_xx[32] = "Monokex XX";

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
static const u8 pid_nx1[32] = "Monokex NX1";

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
static const u8 pid_x1n[32] = "Monokex X1N";

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
static const u8 pid_x1x[32] = "Monokex X1X";

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
static const u8 pid_xx1[32] = "Monokex XX1";

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
static const u8 pid_x1x1[32] = "Monokex X1X1";

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
static const u8 pid_i1n[32] = "Monokex I1N";

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
static const u8 pid_i1k[32] = "Monokex I1K";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (SE << 3) + (S << 6);
    ctx->messages[1] = E + (EE << 3);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}


//////////
/// IK1 ///
//////////
static const u8 pid_ik1[32] = "Monokex IK1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (ES << 6) + (SE << 9);
    ctx->messages[2] = 0;
    ctx->messages[3] = 0;
}

//////////
/// I1K1 ///
//////////
static const u8 pid_i1k1[32] = "Monokex IK1";

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
    copy(ctx->remote_pk, server_pk, 32);
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
    kex_mix_hash(ctx, ctx->local_pk, 32);
    ctx->flags |= GETS_REMOTE;
    ctx->messages[0] = E + (S << 3);
    ctx->messages[1] = E + (EE << 3) + (SE << 6);
    ctx->messages[2] = ES;
    ctx->messages[3] = 0;
}



