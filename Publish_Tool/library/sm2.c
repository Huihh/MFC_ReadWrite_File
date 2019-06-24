/*
 * Reference:
 *
 * http://www.oscca.gov.cn/UpFile/2010122214822692.pdf
 */
#define POLARSSL_SM2_C

#if defined(POLARSSL_ECP_SM2_ENABLED)
#define POLARSSL_SM2_C
#endif

#if defined(POLARSSL_SM2_C)

#include "../polarssl/sm2.h"
#include "../polarssl/sm3.h"
#include "../polarssl/entropy.h"
#include "../polarssl/ctr_drbg.h"

#if defined (POLARSSL_PLATFORM_C)
#include "../polarssl/platform.h"
#else
#define polarssl_printf    printf
#define polarssl_malloc    malloc
#define polarssl_free      free
#endif

int sm2_init( sm2_context *ctx )
{
    ecp_group_init( &ctx->grp );
    mpi_init( &ctx->d );
    ecp_point_init( &ctx->Q );
    mpi_init( &ctx->r );
    mpi_init( &ctx->s );

    return( ecp_use_known_dp( &ctx->grp, POLARSSL_ECP_SM2 ) );
}

void sm2_free( sm2_context *ctx )
{
    ecp_group_free( &ctx->grp );
    mpi_free( &ctx->d );
    ecp_point_free( &ctx->Q );
    mpi_free( &ctx->r );
    mpi_free( &ctx->s );
}

/* default random generate function */
static int random_gen( void * param, unsigned char *rnd, size_t size )
{
    int ret;
    entropy_context entropy;
    ctr_drbg_context drbg;
    unsigned char pers[] = "sm2_gen_keypair";

    ((void) param);
    /* prepare random */
    entropy_init( &entropy );

    if( ( ret = ctr_drbg_init( &drbg, entropy_func, &entropy, pers, sizeof(pers)) ) != 0 )
    {
        ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
        goto cleanup;
    }

    ctr_drbg_set_prediction_resistance( &drbg, CTR_DRBG_PR_ON);

    MPI_CHK( ctr_drbg_random( &drbg, rnd, size ) );

cleanup:
    ctr_drbg_free( &drbg ) ;
    entropy_free( &entropy );
    return( ret );
}

int sm2_gen_keypair( sm2_context *ctx,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret, key_tries;
    mpi n;
    unsigned char rnd[POLARSSL_ECP_MAX_BYTES];
    size_t n_size = ( ctx->grp.nbits + 7 ) / 8;

    ret = 0;
    mpi_init( &n );

    MPI_CHK( mpi_sub_int( &n, &ctx->grp.N, 2 ) );

    if( f_rng == NULL )
        f_rng = random_gen;

    /* generate d: 1 <= d <= N-2 */
    key_tries = 0;
    do
    {
        if( ++key_tries > 30 )
        {
            ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
            break;
        }
        MPI_CHK( f_rng( p_rng, rnd, n_size) );
        MPI_CHK( mpi_read_binary( &ctx->d, rnd, n_size ) );
    }while( mpi_cmp_int( &ctx->d, 1 ) < 0 ||
            mpi_cmp_mpi( &ctx->d, &n ) > 0 );

    if( ret != 0 )
        goto cleanup;

    ret = ecp_mul( &ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, NULL, NULL );

cleanup:
    mpi_free( &n );
    return( ret );

}

int sm2_pubkey_read_binary( sm2_context *ctx, const unsigned char *x,
                            const unsigned char *y )
{
    int ret;

    if( ctx == NULL || x == NULL || y == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ctx->grp.id != POLARSSL_ECP_SM2 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    MPI_CHK( mpi_read_binary( &ctx->Q.X, x, 32 ) );
    MPI_CHK( mpi_read_binary( &ctx->Q.Y, y, 32 ) );
    MPI_CHK( mpi_lset( &ctx->Q.Z, 1) );

    ret = ecp_check_pubkey( &ctx->grp, &ctx->Q );
cleanup:
    return( ret );
}

int sm2_pubkey_read_string( sm2_context *ctx, const char *x, const char *y )
{
    int ret;
    if( ctx == NULL || x == NULL || y == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    if( ctx->grp.id != POLARSSL_ECP_SM2 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    ret = ecp_point_read_string( &ctx->Q, 16, x, y );

    return( ret );
}

int sm2_pubkey_write_binary( const sm2_context *ctx, unsigned char *buf,
                             size_t *len )
{
    int ret;

    if( buf == NULL )
    {
        *len = 65;
        return( 0 );
    }

    if( *len < 65 )
        return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

    *len = 65;

    *buf++ = 0x04;

    MPI_CHK( mpi_write_binary( &ctx->Q.X, buf, 0x20 ) );

    buf += 0x20;

    MPI_CHK( mpi_write_binary( &ctx->Q.Y, buf, 0x20 ) );

cleanup:
    return( ret );
}

int sm2_pubkey_write_string( const sm2_context *ctx, char *buf, size_t *len )
{
    int ret;
    size_t slen;
    char *p;

    if( ctx == NULL || len == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    p = buf;
    slen = 0;
    mpi_write_string( &ctx->Q.X, 16, NULL, &slen );
    p += slen;
    slen = 0;
    mpi_write_string( &ctx->Q.Y, 16, NULL, &slen );
    p += slen;
    p += 2;                     /* appedn 04 */
    if( buf == NULL )
    {
        *len = p - buf;
        return( 0 );
    }

    if( *len < (size_t)(p - buf) )
        return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );


    p = buf;
    *p++ = '0';
    *p++ = '4';
    slen = 0;
    mpi_write_string( &ctx->Q.X, 16, NULL, &slen );
    MPI_CHK( mpi_write_string( &ctx->Q.X, 16, p, &slen ) );
    p += ( slen - 1 );
    slen = 0;
    mpi_write_string( &ctx->Q.Y, 16, NULL, &slen );
    MPI_CHK( mpi_write_string( &ctx->Q.Y, 16, p, &slen ) );
    p += slen;
    *len = p - buf;

cleanup:
    return( ret );
}

/*
 * Verify SM2 signature of hashed message ()
 */
int sm2_verify_core( ecp_group *grp,
                const unsigned char *buf, size_t blen,
                const ecp_point *Q, const mpi *r, const mpi *s)
{
    int ret;
    mpi e, t;
    ecp_point R, P;

    ecp_point_init( &R ); ecp_point_init( &P );
    mpi_init( &e ); mpi_init( &t );

    if( grp->id != POLARSSL_ECP_SM2 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    /*
     * Step 1 2: make sure r and s are in range 1..n-1
     */
    if( mpi_cmp_int( r, 1 ) < 0 || mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        mpi_cmp_int( s, 1 ) < 0 || mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure Q is valid
     */
    MPI_CHK( ecp_check_pubkey( grp, Q ) );

    /*
     * Step 4: derive MPI from hashed message
     * Only SM3?
     */
    MPI_CHK( mpi_read_binary( &e, buf, blen ) );

    /*
     * Step 5: t = (r + s)mod n
     */
    MPI_CHK( mpi_add_mpi( &t, r, s) );
    MPI_CHK( mpi_mod_mpi( &t, &t, &grp->N ) );

    /* t = 0 ? */
    if( mpi_cmp_int( &t, 0 ) == 0 )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Setp 6: P = s G + t Pa
     */
    MPI_CHK( ecp_mul( grp, &R, s, &grp->G, NULL, NULL ) );
    MPI_CHK( ecp_mul( grp, &P, &t, Q, NULL, NULL ) );
    MPI_CHK( ecp_add( grp, &P, &R, &P ) );

    if( ecp_is_zero( &P ) )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Set 7: R = (e + x1)mod n
     * x1 = P.x;
     */
    MPI_CHK( mpi_add_mpi( &R.X, &e, &P.X ) );
    MPI_CHK( mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * check if R (that is, R.X) is equal to r
     */
    if( mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    ecp_point_free( &R ); ecp_point_free( &P );
    mpi_free( &e ); mpi_free( &t );

    return( ret );
}

int sm2_verify( sm2_context *ctx,
                const unsigned char *hash, size_t hlen,
                const unsigned char *r,
                const unsigned char *s )
{
    int ret;
    mpi R, S;
    mpi_init( &R ); mpi_init( &S );
    if( ctx->grp.id != POLARSSL_ECP_SM2 )
    {
        return( POLARSSL_ERR_ECP_INVALID_KEY );
    }

    MPI_CHK( mpi_read_binary( &R, r, 32) );
    MPI_CHK( mpi_read_binary( &S, s, 32) );

    ret = sm2_verify_core( &ctx->grp, hash, hlen,
                      &ctx->Q, &R, &S );
cleanup:
    mpi_free( &R ); mpi_free( &S );
    return( ret );
}

int sm2_sign_core( ecp_group *grp, mpi *r, mpi *s,
                   const mpi *d, const unsigned char *hash, size_t hlen,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries;
    mpi e, t;
    sm2_context tmp_key;
    mpi *k;
    ecp_point *Q;

    if( hash == NULL || hlen == 0 )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

    mpi_init( &e ); mpi_init( &t );
    MPI_CHK( mpi_read_binary( &e, hash, hlen ) );

    sign_tries = 0;
    do
    {
        if( sign_tries++ > 10 )
        {
            ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        key_tries = 0;
        do
        {
            if( key_tries++ > 10 )
            {
                ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
            MPI_CHK( sm2_init( &tmp_key ) );
            /* 1 <= k <= n-1, but use gen_keypair 1 <= k <= n-2 ^_^ */
            MPI_CHK( sm2_gen_keypair(&tmp_key, f_rng, p_rng) );

            k = &tmp_key.d;
            Q = &tmp_key.Q;
            mpi_lset( &t, 0 );
            /* r =  (e + x1)/mod n*/
            MPI_CHK( mpi_add_mpi( r, &e, &Q->X ) );
            MPI_CHK( mpi_mod_mpi( r, r, &grp->N ) );
            MPI_CHK( mpi_add_mpi( &t, k, r ) );

        }while( mpi_cmp_int( r, 0 ) == 0 ||
                mpi_cmp_mpi( &t, &grp->N ) == 0 );

        /* s = ((1 + dA)^−1 · (k − r · dA)) modn */

        /* s = 1 + dA */
        MPI_CHK( mpi_add_int( s, d, 1) );
        /* s = s^-1 mod n */
        MPI_CHK( mpi_inv_mod( s, s, &grp->N ) );

        /* t = r*dA */
        MPI_CHK( mpi_mul_mpi( &t, r, d ) );
        /* t = k - t */
        MPI_CHK( mpi_sub_mpi( &t, k, &t) );
        /* t = t mod n */
        MPI_CHK( mpi_mod_mpi( &t, &t, &grp->N ) );

        MPI_CHK( mpi_mul_mpi( s, s, &t ) );
        MPI_CHK( mpi_mod_mpi( s, s, &grp->N ) );
    }
    while( mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    mpi_free( &e ); mpi_free( &t );
    sm2_free( &tmp_key );
    return( ret );
}


int sm2_sign( sm2_context *ctx,
              const unsigned char *hash, size_t hlen,
              unsigned char *r, unsigned char *s,
              int (*f_rng)(void *, unsigned char *, size_t),
              void *p_rng )
{
    int ret;
    mpi R, S;
    mpi_init( &R ); mpi_init( &S );

    if( ( ret = sm2_sign_core( &ctx->grp, &R, &S,
                               &ctx->d, hash, hlen,
                               f_rng, p_rng ) ) != 0 )
    {
        goto cleanup;
    }

    MPI_CHK( mpi_write_binary( &R, r, 32 ) );
    MPI_CHK( mpi_write_binary( &S, s, 32 ) );

cleanup:
    mpi_free( &R ); mpi_free( &S );
    return( ret );
}


/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
    {                                                   \
        (n) = ( (uint32_t) (b)[(i)    ] << 24 )         \
            | ( (uint32_t) (b)[(i) + 1] << 16 )         \
            | ( (uint32_t) (b)[(i) + 2] <<  8 )         \
            | ( (uint32_t) (b)[(i) + 3]       );        \
    }
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
    {                                                   \
        (b)[(i)    ] = (unsigned char) ( (n) >> 24 );   \
        (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );   \
        (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );   \
        (b)[(i) + 3] = (unsigned char) ( (n)       );   \
    }
#endif

/*
 * derive key
 * klen: Bytes length
 */
int sm2_kdf( const unsigned char *z, size_t zlen,
             unsigned char *key, size_t klen )
{
    sm3_context ctx, ctx2;
    unsigned char ct[4];
    unsigned char h[32];
    uint32_t part;
    uint32_t i;

    sm3_starts( &ctx );
    sm3_update( &ctx, z, zlen );

    for( i = 1; i <= klen/32; i++ )
    {
        memcpy(&ctx2, &ctx, sizeof( ctx ) ); /* speed up */
        PUT_UINT32_BE( i, ct, 0);
        sm3_update( &ctx2, ct, 4);
        sm3_finish( &ctx2, key );
        key += 32;
    }

    if( ( part = klen%32 ) != 0 )
    {
        memcpy(&ctx2, &ctx, sizeof( ctx ) ); /* speed up */
        PUT_UINT32_BE( i, ct, 0);
        sm3_update( &ctx2, ct, 4);
        sm3_finish( &ctx2, h );
        memcpy( key, h, part );
    }

    sm3_free( &ctx ); sm3_free( &ctx2 );
    return( 0 );
}

int sm2_kdf_is_zero(const unsigned char *t, size_t l)
{
    int ret = 0;
    while( l --> 0 )
    {
        ret = (*t++ == 0);
        if( ret == 0)
            break;
    }

    return( ret );
}

/* compute C2 */
int sm2_encrypt_core( ecp_group *grp, ecp_point *Q,
                      const unsigned char* msg, size_t mlen,
                      sm2_context *tmp_key, unsigned char *C2,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret, key_tries, encrypt_tries;
    unsigned char *t;
    unsigned char z[64];
    ecp_point P;


    if( !msg || !mlen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    if( !C2 || !tmp_key )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( t = polarssl_malloc( mlen ) ) == NULL )
        return( POLARSSL_ERR_ECP_MALLOC_FAILED );

    ecp_point_init( &P );

    encrypt_tries = 0;
    do
    {
        if( encrypt_tries++ > 10 )
        {
            ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        key_tries = 0;
        do
        {
            if( key_tries++ > 10 )
            {
                ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
            sm2_init( tmp_key );
            MPI_CHK( sm2_gen_keypair( tmp_key, f_rng, p_rng ) );
        }while( ecp_check_pubkey( grp, &tmp_key->Q ) != 0 );

        /* [k]Pb = (x2, y2) */
        MPI_CHK( ecp_mul( grp, &P, &tmp_key->d, Q, NULL, NULL ) );

        /* z = x2||y2 */
        MPI_CHK( mpi_write_binary( &P.X, z, 32 ) );
        MPI_CHK( mpi_write_binary( &P.Y, z+32, 32 ) );

        /* kdf */
        MPI_CHK( sm2_kdf( z, 64, t, mlen ) );
    }while( sm2_kdf_is_zero( t, mlen ) );

    /* c2 = M ^ t */
    while( (int)mlen --> 0)
        C2[mlen] = msg[mlen] ^ t[mlen];

cleanup:
    polarssl_free( t );
    ecp_point_free( &P );
    return( ret );
}

int sm2_encrypt( sm2_context *ctx, const unsigned char *msg, size_t mlen,
                 unsigned char *enc, size_t *elen,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng )
{
    int ret;
    size_t len;
    size_t c1len;
    unsigned char C1[0x41];     /* 1 + 0x20 + 0x20 */
    unsigned char *C2;
    unsigned char C3[0x20];      /* the lenght of SM3 hash result */
    sm2_context tmp_key;
    ecp_point P2;
    sm3_context sm3;

    if( !msg || !mlen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    len = sizeof(C1) + mlen + sizeof(C3);

    if( !enc )
    {
        *elen = len;
        return( 0 );
    }

    if( *elen < len )
        return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

    C2 = (unsigned char*) polarssl_malloc( mlen );
    if( C2 == NULL )
        return( POLARSSL_ERR_ECP_MALLOC_FAILED );

    sm2_init( &tmp_key ); ecp_point_init( &P2 );

    MPI_CHK( sm2_encrypt_core( &ctx->grp, &ctx->Q, msg, mlen, &tmp_key, C2,
                          f_rng, p_rng) );
    MPI_CHK( ecp_mul( &ctx->grp, &P2, &tmp_key.d, &ctx->Q, NULL, NULL ) );

    /* c3 = hash( x2||msg||y2 ) */
    c1len = sizeof( C1 );
    MPI_CHK( mpi_write_binary( &P2.X, C1, 0x20 ) );
    sm3_starts( &sm3 );
    sm3_update( &sm3, C1, 0x20 );
    sm3_update( &sm3, msg, mlen );

    MPI_CHK( mpi_write_binary( &P2.Y, C1, 0x20 ) );
    sm3_update( &sm3, C1, 0x20 );
    sm3_finish( &sm3, C3 );

    /* c1 */
    c1len = sizeof( C1 );
    MPI_CHK( sm2_pubkey_write_binary( &tmp_key, C1, &c1len ) );

#if defined(SM2_ENCRYPTED_DATA_IS_C1_C2_C3)
    memcpy( enc, C1, c1len );
    enc += c1len;
    memcpy( enc, C2, mlen );
    enc += mlen;
    memcpy( enc, C3, sizeof( C3 ) );
    enc += sizeof(C3);
#elif defined(SM2_ENCRYPTED_DATA_IS_C1_C3_C2)
    memcpy( enc, C1, c1len );
    enc += c1len;
	memcpy( enc, C3, sizeof( C3 ) );
	enc += sizeof(C3);
    memcpy( enc, C2, mlen );
#endif
    *elen = c1len + mlen + sizeof( C3 );
cleanup:
    polarssl_free(C2);
    sm2_free( &tmp_key );
    ecp_point_free( &P2 );
    return( ret );
}

/* decrypt C2 */
int sm2_decrypt_core( ecp_group *grp, mpi *d, ecp_point *P,
                      const unsigned char *enc,
                      size_t elen, unsigned char *M )
{
    int ret;
    unsigned char z[64];
    unsigned char *t;
    ecp_point P2;

    if( !enc || !elen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    if( !M )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( t = (unsigned char *) polarssl_malloc( elen ) ) == NULL )
        return( POLARSSL_ERR_ECP_MALLOC_FAILED );

    ecp_point_init( &P2 );

    /* [db]P = (x2, y2) */
    MPI_CHK( ecp_mul( grp, &P2, d, P, NULL, NULL ) );

    /* kdf */
    /* z = (x2||y2) */
    MPI_CHK( mpi_write_binary( &P2.X, z, 32) );
    MPI_CHK( mpi_write_binary( &P2.Y, z+32, 32 ) );
    MPI_CHK( sm2_kdf( z, sizeof(z), t, elen ) );

    if( sm2_kdf_is_zero( t, elen ) )
    {
        ret = POLARSSL_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    while( (int)elen --> 0 )
        M[elen] = enc[elen] ^ t[elen];

cleanup:
    polarssl_free( t );
    ecp_point_free( &P2 );
    return( ret );
}

int sm2_decrypt( sm2_context *ctx, const unsigned char *enc, size_t elen,
                 unsigned char *msg, size_t *mlen )
{
    int ret;
    const unsigned char *c1, *c2, *c3;
    unsigned char hash[0x20];
    size_t c1len, c2len, c3len;
    ecp_point P2;
    sm2_context tmp_key;
    sm3_context sm3;
    if( !enc || !elen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    c1len = 0x41; c3len = 0x20; c2len = elen - c1len - c3len;

    if( !msg )
    {
        *mlen = c2len;
        return( 0 );
    }

    if( *mlen < c2len )
        return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

    sm2_init( &tmp_key ); ecp_point_init( &P2 );

#if defined(SM2_ENCRYPTED_DATA_IS_C1_C2_C3)
    c1 = enc;
    c2 = c1 + c1len;
    c3 = c2 + c2len;
#elif defined(SM2_ENCRYPTED_DATA_IS_C1_C3_C2)
    c1 = enc;
    c3 = c1 + c1len;
    c2 = c3 + c3len;
#endif

    MPI_CHK( sm2_pubkey_read_binary(  &tmp_key, c1+1, c1+0x21) );
    MPI_CHK( sm2_decrypt_core( &ctx->grp, &ctx->d, &tmp_key.Q, c2, c2len, msg ) );
    MPI_CHK( ecp_mul( &ctx->grp, &P2, &ctx->d, &tmp_key.Q, NULL, NULL ) );
    *mlen = c2len;

    /* check hash */
    /* c3 = hash( x2||msg||y2 ) */
    sm3_init( &sm3 );
    sm3_starts( &sm3 );
    MPI_CHK( mpi_write_binary( &P2.X, hash, 0x20 ) );
    sm3_update( &sm3, hash, 0x20 );
    sm3_update( &sm3, msg, *mlen );
    MPI_CHK( mpi_write_binary( &P2.Y, hash, 0x20 ) );
    sm3_update( &sm3, hash, 0x20 );
    sm3_finish( &sm3, hash);

    if( memcmp( c3, hash, c3len ) != 0 )
        ret = POLARSSL_ERR_ECP_BAD_INPUT_DATA;

cleanup:
    sm3_free(&sm3);
    ecp_point_free( &P2 );
    sm2_free( &tmp_key );
    return( ret );
}

int compute_Z( const sm2_context *ctx,
               const unsigned char *user_id, size_t user_id_len,
               unsigned char *output)
{
    unsigned char entl[2];
    unsigned char M[32];
    size_t m_len;
    sm3_context sm3;

    int ret;

    if( ctx->grp.id != POLARSSL_ECP_SM2 )
    {
        return( POLARSSL_ERR_ECP_INVALID_KEY );
    }


    if( user_id_len*8 > 0xffff || user_id_len < 1 )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

    /*
     * h = H(Za||M)
     * Za = (ENTLa || user_id || a || b || Gx || Gy || Ax || Ay)
     *
     */

    sm3_init( &sm3 );

    sm3_starts( &sm3 );

    /* ENTLa */
    /* bits length */
    entl[0] = ( (user_id_len*8) >> 8)&0xff;
    entl[1] = (user_id_len*8) & 0xff;
    sm3_update( &sm3, entl, sizeof( entl ) );

    /* user_id */
    sm3_update( &sm3, user_id, user_id_len );

    m_len = (ctx->grp.nbits + 7)/8;

    /* a */
    MPI_CHK( mpi_write_binary( &ctx->grp.A, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    /* b */
    MPI_CHK( mpi_write_binary( &ctx->grp.B, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    /* Gx */
    MPI_CHK( mpi_write_binary( &ctx->grp.G.X, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    /* Gy */
    MPI_CHK( mpi_write_binary( &ctx->grp.G.Y, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    /* Ax */
    MPI_CHK( mpi_write_binary( &ctx->Q.X, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    /* Ay */
    MPI_CHK( mpi_write_binary( &ctx->Q.Y, M, m_len ) );
    sm3_update( &sm3, M, m_len );

    sm3_finish( &sm3, output );

cleanup:
    sm3_free( &sm3 );
    return( ret );
}

int hash_msg_with_user_id( const sm2_context *ctx,
                           const unsigned char *buf, size_t buf_len,
                           const unsigned char *user_id, size_t user_id_len,
                           unsigned char* output )
{
    int ret;
    size_t m_len;
    sm3_context sm3;

    if( ( ret = compute_Z( ctx, user_id, user_id_len, output ) ) != 0 )
    {
        return( ret );
    }

    sm3_init( &sm3 );
    m_len = 0x20;

    sm3_starts( &sm3 );
    sm3_update( &sm3, output, m_len );
    sm3_update( &sm3, buf, buf_len );
    sm3_finish( &sm3, output );

    sm3_free( &sm3 );
    return( ret );
}

#if defined(POLARSSL_SELF_TEST)

#ifdef SM2_TEST
/*
 * 注意:
 *     算法描述的文档上的曲线和正式使用的曲线不是一条。
 *     为了方便SM2算法的验证，定义了一个宏:SM2_TEST
 *     如果需要测试SM2算法，在编译的时候会自动使用算法文档上的曲线
 *     曲线定义在: ecp_curves.c 中
 *
 */
static int sign_random_gen( void* param, unsigned char *rnd, size_t size)
{

    unsigned char k[] = {
        /* sign */
        0x6C, 0xB2, 0x8D, 0x99, 0x38, 0x5C, 0x17, 0x5C,
        0x94, 0xF9, 0x4E, 0x93, 0x48, 0x17, 0x66, 0x3F,
        0xC1, 0x76, 0xD9, 0x25, 0xDD, 0x72, 0xB7, 0x27,
        0x26, 0x0D, 0xBA, 0xAE, 0x1F, 0xB2, 0xF9, 0x6F,
    };
    ((void)param);
    ((void)rnd);
    ((void)size);

    memcpy(rnd, k, sizeof(k));

    return 0;
}

int sm2_self_test_sign( int verbose )
{
    int ret ;
    char *exponents[] =
        {
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", /* d */
            "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A", /* px */
            "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857", /* py */
// 			"6356e73a5c3868c315f7757178bc2b4b9c2bd3bca83617eb1c4429e7e6db0821", /* d */
//             "d53c6883a35e086de6652d2355020b44d2fa419d760e5bc84a7bc081e4b67a37", /* px */
//             "f2a55c2f6cb5875479cf8ec54cc26b2a32fd2048459d8b189d1ceb73e1eb9482", /* py */
        };
    unsigned char result[][32] =
        {
            /* e */
            {
                0xB5, 0x24, 0xF5, 0x52, 0xCD, 0x82, 0xB8, 0xB0,
                0x28, 0x47, 0x6E, 0x00, 0x5C, 0x37, 0x7F, 0xB1,
                0x9A, 0x87, 0xE6, 0xFC, 0x68, 0x2D, 0x48, 0xBB,
                0x5D, 0x42, 0xE3, 0xD9, 0xB9, 0xEF, 0xFE, 0x76,
            },
            /* r */
            {
                0x40, 0xF1, 0xEC, 0x59, 0xF7, 0x93, 0xD9, 0xF4,
                0x9E, 0x09, 0xDC, 0xEF, 0x49, 0x13, 0x0D, 0x41,
                0x94, 0xF7, 0x9F, 0xB1, 0xEE, 0xD2, 0xCA, 0xA5,
                0x5B, 0xAC, 0xDB, 0x49, 0xC4, 0xE7, 0x55, 0xD1,
            },
            /* s */
            {
                0x6F, 0xC6, 0xDA, 0xC3, 0x2C, 0x5D, 0x5C, 0xF1,
                0x0C, 0x77, 0xDF, 0xB2, 0x0F, 0x7C, 0x2E, 0xB6,
                0x67, 0xA4, 0x57, 0x87, 0x2F, 0xB0, 0x9E, 0xC5,
                0x63, 0x27, 0xA6, 0x7E, 0xC7, 0xDE, 0xEB, 0xE7,
            },
        };

    unsigned char user_id[] = "ALICE123@YAHOO.COM";
    unsigned char msg[] = "message digest";
    unsigned char output[32], r[32], s[32];
    size_t user_id_len = sizeof( user_id ) - 1;
    size_t msg_len = sizeof( msg ) - 1;
    sm2_context ctx;

    ((void) verbose);

    //do not use sm2_init.
    sm2_init( &ctx );

    mpi_read_string( &ctx.d, 16, exponents[0] );

    sm2_pubkey_read_string( &ctx, exponents[1], exponents[2] );

    ret = hash_msg_with_user_id( &ctx,
                                 msg, msg_len,
                                 user_id, user_id_len,
                                 output);
    polarssl_printf( "---- sm2 sign/verify test ----\n");
    polarssl_printf( "compute e: \n" );
    if( ret !=  0 )
    {
        polarssl_printf( "compute failed \n" );
        goto cleanup;
    }

    if( memcmp( output, result[0], 32 ) == 0 )
    {
        polarssl_printf( "compute e pass\n");
    }
    else
    {
        polarssl_printf( "compute e faliled\n");
        ret = 1;
        goto cleanup;
    }

    polarssl_printf( "sm2 sign operation\n" );

    ret = sm2_sign( &ctx, output, 0x20, r, s, sign_random_gen, NULL);

    if( ret != 0 )
    {
        polarssl_printf( "  sm2 sign operation failed\n");
        goto cleanup;
    }

    if( memcmp( r, result[1], 32 ) != 0 || memcmp( s, result[2], 32 ) != 0 )
    {
        polarssl_printf( "  sm2 sign operation faliled\n ");
        ret = 1;
    }
    else
    {
        polarssl_printf( "  sm2 sign operation passed\n");
    }
    polarssl_printf( "\n");
    polarssl_printf( "sm2 verify operation\n");
    ret = sm2_verify( &ctx, output, 0x20, r, s);

    if( ret != 0 )
    {
        polarssl_printf( "  sm2 verify operation faliled\n");
    }
    else
    {
        polarssl_printf( "  sm2 verify operation passed\n");
    }
    polarssl_printf( "\n");

cleanup:
    sm2_free( &ctx );
    return( ret );
}

static int encrypt_random_gen( void* param, unsigned char *rnd, size_t size)
{

    unsigned char k[] = {
        /* encrypt */
        0x4C, 0x62, 0xEE, 0xFD, 0x6E, 0xCF, 0xC2, 0xB9,
        0x5B, 0x92, 0xFD, 0x6C, 0x3D, 0x95, 0x75, 0x14,
        0x8A, 0xFA, 0x17, 0x42, 0x55, 0x46, 0xD4, 0x90,
        0x18, 0xE5, 0x38, 0x8D, 0x49, 0xDD, 0x7B, 0x4F
    };
    ((void)param);
    ((void)rnd);
    ((void)size);

    memcpy(rnd, k, sizeof(k));

    return 0;
}

int sm2_self_test_encrypt( int verbose )
{
    int ret ;
    char *exponents[] =
    {
        "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", /* d */
        "435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A", /* px */
        "75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42", /* py */
// 		"6356e73a5c3868c315f7757178bc2b4b9c2bd3bca83617eb1c4429e7e6db0821", /* d */
// 		"d53c6883a35e086de6652d2355020b44d2fa419d760e5bc84a7bc081e4b67a37", /* px */
// 		"f2a55c2f6cb5875479cf8ec54cc26b2a32fd2048459d8b189d1ceb73e1eb9482", /* py */

    };
    char *msg = "encryption standard";
    unsigned char result[] = {
        0x04, 0x24, 0x5C, 0x26, 0xFB, 0x68, 0xB1, 0xDD,
        0xDD, 0xB1, 0x2C, 0x4B, 0x6B, 0xF9, 0xF2, 0xB6,
        0xD5, 0xFE, 0x60, 0xA3, 0x83, 0xB0, 0xD1, 0x8D,
        0x1C, 0x41, 0x44, 0xAB, 0xF1, 0x7F, 0x62, 0x52,
        0xE7, 0x76, 0xCB, 0x92, 0x64, 0xC2, 0xA7, 0xE8,
        0x8E, 0x52, 0xB1, 0x99, 0x03, 0xFD, 0xC4, 0x73,
        0x78, 0xF6, 0x05, 0xE3, 0x68, 0x11, 0xF5, 0xC0,
        0x74, 0x23, 0xA2, 0x4B, 0x84, 0x40, 0x0F, 0x01,
        0xB8, 0x65, 0x00, 0x53, 0xA8, 0x9B, 0x41, 0xC4,
        0x18, 0xB0, 0xC3, 0xAA, 0xD0, 0x0D, 0x88, 0x6C,
        0x00, 0x28, 0x64, 0x67, 0x9C, 0x3D, 0x73, 0x60,
        0xC3, 0x01, 0x56, 0xFA, 0xB7, 0xC8, 0x0A, 0x02,
        0x76, 0x71, 0x2D, 0xA9, 0xD8, 0x09, 0x4A, 0x63,
        0x4B, 0x76, 0x6D, 0x3A, 0x28, 0x5E, 0x07, 0x48,
        0x06, 0x53, 0x42, 0x6D};
    unsigned char out[512];
    size_t outlen = sizeof(out);

    sm2_context ctx;
    ((void)verbose);

    sm2_init( &ctx );
    /* read private key */
    mpi_read_string( &ctx.d, 16, exponents[0] );
    /* read public key */
    sm2_pubkey_read_string( &ctx, exponents[1], exponents[2] );

    polarssl_printf( "---- sm2 encrypt/decrypt test ----\n" );
    polarssl_printf( "sm2 encrypt operation\n");
    /* encrypt */
    ret = sm2_encrypt( &ctx,
                       (unsigned char*)msg, strlen(msg),
                       out, &outlen, encrypt_random_gen, NULL );

    if( ret == 0 && outlen == sizeof(result) && 0 == memcmp(result, out, outlen) )
    {
        polarssl_printf("  sm2 encrypt test passed\n");
    }
    else
    {
        polarssl_printf("  sm2 encrypt test faild\n");
    }

    /* decrypt */
    polarssl_printf( "\n" );
    polarssl_printf( "sm2 decrypt operation\n" );
    outlen = sizeof(out);
    ret = sm2_decrypt( &ctx, result, sizeof(result), out, &outlen );

    if( ret == 0 && outlen == strlen(msg) && 0 == memcmp(out, msg, strlen(msg)))
    {
        polarssl_printf(" sm2 decrypt test passed\n");
    }
    else
    {
        polarssl_printf(" sm2 decrypt test faild\n");
    }
    polarssl_printf( "\n" );
    sm2_free( &ctx );
    return( ret );
}
#else                            /* SM2_TEST */
static void _hex_to_str( unsigned char *bin, size_t len, char *out )
{
    unsigned char c;
    size_t i;

    for( i = 0; i < len; i++ )
    {
        c = bin[i];
        *out++ =  "0123456789ABCDEF" [c / 16];;
        *out++ =  "0123456789ABCDEF" [c % 16];;
    }
    *out++ = 0x00;
}
int sm2_self_test_sign( int verbose )
{
    char msg[] = "sm2_key_algorithm_test_msg";
    size_t mlen = sizeof(msg) - 1;
    char user_id[] = "1234567812345678";
    size_t user_id_len = sizeof(msg) - 1;

    int ret;
    sm2_context ctx;

    unsigned char e[0x32], r[0x20], s[0x20];
    char buf[0x100];
    size_t len;

    ((void) verbose);
    sm2_init( &ctx );

    polarssl_printf( "---- sm2 sign/verify test ----\n");
    polarssl_printf( "sm2 gen keypair:\n");
    ret = sm2_gen_keypair( &ctx, NULL, NULL );

    if( ret != 0 )
    {
        polarssl_printf( "  sm2 gen keypair failed\n");
        goto cleanup;
    }
    polarssl_printf( "  sm2 gen keypair success\n");

    len = sizeof( buf );
    mpi_write_string(&ctx.d, 16, buf, &len);
    polarssl_printf( "\n" );
    polarssl_printf( "sm2 key pair:\n" );
    polarssl_printf( "  pri key: "
                     "    %s\n", buf );

    len = sizeof( buf );
    sm2_pubkey_write_string( &ctx, buf, &len );

    polarssl_printf( "  pub key: "
                     "    %s\n", buf );

    polarssl_printf( "\n");

    polarssl_printf( "sm2 sign operation:\n");
    polarssl_printf( "  msg: "
                     "    %s\n", msg);
    polarssl_printf( "  user id: "
                     "    %s\n", user_id );
    ret = hash_msg_with_user_id( &ctx, (unsigned char*)msg, mlen,
                                 (unsigned char*)user_id, user_id_len,
                                 e);

    polarssl_printf("\n");
    if( ret != 0 )
    {
        polarssl_printf("hash msg failed\n");
        goto cleanup;
    }
    polarssl_printf( "hash msg success\n");

    _hex_to_str( e, 0x20, buf );
    polarssl_printf( "  hash: "
                     "    %s", buf );

    polarssl_printf( "\n" );


    ret = sm2_sign( &ctx, e, 0x20, r, s, NULL, NULL );
    if( ret != 0 )
    {
        polarssl_printf( "sm2 sign operation failed\n");
        goto cleanup;
    }
    polarssl_printf( "sm2 sign operation success\n");
    _hex_to_str( r, 0x20, buf );
    polarssl_printf( "  r: %s\n", buf);
    _hex_to_str( s, 0x20, buf );
    polarssl_printf( "  s: %s\n", buf);

    polarssl_printf( "\n" );
    polarssl_printf( "sm2 verify:\n");

    ret = sm2_verify( &ctx, e, 0x20, r, s);
    if( ret != 0 )
    {
        polarssl_printf("  sm2 verify opration failed\n" );
        goto cleanup;
    }
    polarssl_printf("  sm2 verify operation success\n" );
cleanup:
    sm2_free( &ctx );
    return( ret );
}

int sm2_self_test_encrypt( int verbose )
{

    char msg[] = "sm2_key_algorithm_test_msg";
    size_t mlen = sizeof(msg) - 1;


    int ret;
    sm2_context ctx;
    char buf[0x400];
    unsigned char enc[0x400];
    unsigned char m[0x100];
    size_t elen = sizeof(enc);
    size_t len;

    ((void) verbose);
    sm2_init( &ctx );

    polarssl_printf( "---- sm2 encrypt/decrypt test ----\n");
    polarssl_printf( "sm2 gen keypair:\n");
    ret = sm2_gen_keypair( &ctx, NULL, NULL );

    if( ret != 0 )
    {
        polarssl_printf( "  sm2 gen keypair failed\n");
        goto cleanup;
    }
    polarssl_printf( "  sm2 gen keypair success\n");

    len = sizeof( buf );
    mpi_write_string(&ctx.d, 16, buf, &len);
    polarssl_printf( "\n" );
    polarssl_printf( "sm2 key pair:\n" );
    polarssl_printf( "  pri key: "
                     "    %s\n", buf );

    len = sizeof( buf );
    sm2_pubkey_write_string( &ctx, buf, &len );

    polarssl_printf( "  pub key: "
                     "    %s\n", buf );

    polarssl_printf( "\n");
    polarssl_printf( "sm2 encrypt:\n");

    polarssl_printf( "  msg: "
                     "    %s\n", msg);

    ret = sm2_encrypt( &ctx, (unsigned char*)msg, mlen, enc, &elen, NULL, NULL );
    if( ret != 0 )
    {
        polarssl_printf( "  sm2 encrypt operation failed\n" );
        goto cleanup;
    }

    polarssl_printf( "  sm2 encrypt operation success\n");

    _hex_to_str(enc, elen, buf);
    polarssl_printf( "  encrypted msg: %s \n", buf );
    polarssl_printf( "\n" );

    polarssl_printf( "sm2 decrypt:\n");

    len = sizeof(m);
    ret = sm2_decrypt( &ctx, enc, elen, m, &len );

    if( ret != 0 || len != mlen || 0 != memcmp( m, msg, len ) )
    {
        polarssl_printf( "  sm2 decrypt failed\n" );
        goto cleanup;
    }

    polarssl_printf("  sm2 decrypt success\n");

cleanup:
    sm2_free( &ctx );
    return( ret);
}
#endif  /* SM2_TEST */
int sm2_self_test( int verbose )
{
    sm2_self_test_sign( verbose );
    sm2_self_test_encrypt( verbose );

    return( 0 );
}
#endif  /* POLARSSL_SELF_TEST */

#endif  /* POLARSSL_SM2_C */
