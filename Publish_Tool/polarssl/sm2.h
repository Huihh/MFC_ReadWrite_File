#ifndef POLARSSL_SM2_H
#define POLARSSL_SM2_H

#include "ecp.h"

/*
 * SM2 context. same as ecdsa context
 * DO NOT modify!!
 */
typedef struct
{
   ecp_group grp;      /*!<  elliptic curve used           */
   mpi d;              /*!<  secret signature key          */
   ecp_point Q;        /*!<  public signature key          */
   mpi r;              /*!<  first integer from signature  */
   mpi s;              /*!<  second integer from signature */
}
sm2_context;

/* encrypted data format  */
#define SM2_ENCRYPTED_DATA_IS_C1_C2_C3 /* 2010 standard */
//#define SM2_ENCRYPTED_DATA_IS_C1_C3_C2 /* 2012 standard */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Initialize SM2 context
 *
 * \param ctx       Context to initialize
 *
 * \return          0 success, or an POLARSSL_ERR_ECP code
 */
int sm2_init( sm2_context *ctx );

/**
 * \brief           Free SM2 context
 *
 * \param ctx       Context to free
 */
void sm2_free( sm2_context *ctx );

/**
 * \brief           Generate an SM2 keypair
 *
 * \param ctx       SM2 context in which the keypair should be stroed
 * \param f_rng     Random generate function.
 *                  Can be NULL, if NULL use default generate function.
 * \param p_rng     Param for f_rng.
 *
 * \return          0 success, or an POLARSSL_ERR_ECP code.
 */
int sm2_gen_keypair( sm2_context *ctx,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );


/**
 * \brief           Read SM2 public key from buffer (x, y)
 *
 * \param ctx       SM2 context
 * \param x         X
 * \param y         Y
 *
 * \return          0 success, or an POLARSSL_ERR_ECP code
 */
int sm2_pubkey_read_binary( sm2_context *ctx, const unsigned char *x,
                            const unsigned char *y );


/**
 * \brief           Write SM2 public key to buffer.
 * \note            Not compression, (04|x|y)
 *
 * \param ctx       SM2 context
 * \param buf       Buffer to hold binary SM2 keypair
 * \param len       The length of buffer
 *
 * \return          0 success, or an POLARSSL_ERR_ECP code.
 */
int sm2_pubkey_write_binary( const sm2_context *ctx, unsigned char *buf,
                             size_t *len );

/**
 * \brief          Read SM2 public key from string (x, y)
 *
 * \param ctx      SM2 context
 * \param x        X
 * \param y        Y
 *
 * \return         0 success, or an POLARSSL_ERR_ECP code
 */
int sm2_pubkey_read_string( sm2_context *ctx, const char *x, const char *y);

/**
 * \brief           Write SM2 public key to string
 *
 * \note            Not compression, "04|x|y"
 *
 * \param ctx       SM2 context
 * \param buf       Buffer to hold string SM2 keypair
 * \param len       The length of buffer.
 */
int sm2_pubkey_write_string( const sm2_context *ctx, char* buf, size_t *len);

/**
 * \brief           Verify an SM2 signature, signatrue is in buffers
 *
 * \param ctx       SM2 key pair context
 * \param hash      Message hash
 * \param hlen      Size of hash
 * \param r         First part of signature
 * \param s         Second part of signature
 *
 * \return          0 if successful,
 *                  POLARSSL_ERR_ECP_BAD_INPUT_DATA if signature is invalid,
 *                  POLARSSL_ERR_ECP_SIG_LEN_MISTMATCH if the signature is
 *                  valid but its actual length is less than siglen,
 *                  or a POLARSSL_ERR_ECP or POLARSSL_ERR_MPI error code
 */
int sm2_verify( sm2_context *ctx,
                const unsigned char *hash, size_t hlen,
                const unsigned char *r,
                const unsigned char *s );

/**
 * \brief           Compute SM2 signature.
 *
 * \param ctx       SM2 context
 * \param hash      Message hash
 * \param hlen      Length of hash
 * \param r         Buffer that hold first part of signature
 * \param s         Buffer that hold second part of signature
 * \param f_rng     RNG function, if NULL use default generate function
 * \param p_rng     RNG parameter
 *
 * \note            r s buffer must be at least as large as the size of 32Bytes
 * \return          0 if successful,
 *                  or a POLARSSL_ERR_ECP, POLARSSL_ERR_MPI or
 *                  POLARSSL_ERR_ASN1 error code
 */
int sm2_sign( sm2_context *ctx,
              const unsigned char *hash, size_t hlen,
              unsigned char *r, unsigned char *s,
              int (*f_rng)(void *, unsigned char *, size_t),
              void *p_rng );

/**
 * \brief           Encrypt data
 *
 * \param ctx       SM2 context
 * \param msg       Message to encrypt
 * \param mlen      The length of msg
 * \param enc       Buffer holde encrypted data
 * \param elen      The length of buffer.
 *                  return the lenght needed when buf is NULL.
 * \param f_rng     RNG function, if NULL use default generate function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successufl, or an POLARSSL_ERR_ECP error code
 *
 * \note            Encrypted data format is controled by micro
 *                  SM2_ENCRYPTED_DATA_IS_xxxx
 */
int sm2_encrypt( sm2_context *ctx, const unsigned char *msg, size_t mlen,
                 unsigned char *enc, size_t *elen,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng );

/**
 * \brief           Decrypt encrypt message
 *
 * \param ctx       SM2 context
 * \param enc       Encrypted message
 * \param elen      Length of encrypted message
 * \param msg       Buffer to hold message
 * \param mlen      Length of msg. Return needed length when msg is NULL
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP error code
 */
int sm2_decrypt( sm2_context *ctx, const unsigned char *enc, size_t elen,
                 unsigned char *msg, size_t *mlen );
 
/**
 * \brief              Use SM3 algorithm compute Z value
 *
 * \param ctx          SM2 context
 * \param user_id      User ID.
 * \param user_id_len  Length of user_id
 * \param output       Output buffer which lenght is equal to length of SM3 result
 *
 * \return             0 successful, ohterwish faild
 */
int compute_Z( const sm2_context *ctx,
               const unsigned char *user_id, size_t user_id_len,
               unsigned char *output );

/**
 * \brief              Use SM3 algorithm HASH message.
 *
 * \param ctx          SM2 context
 * \param buf          Message to hash
 * \param buf_len      Length of message
 * \param user_id      User ID.
 * \param user_id_len  Length of user_id
 * \param output       Output buffer which lenght is equal to length of SM3 result
 *
 * \return             0 if successful, otherwish faild.
 */
int hash_msg_with_user_id( const sm2_context *ctx,
                           const unsigned char *buf, size_t buf_len,
                           const unsigned char *user_id, size_t user_id_len,
                           unsigned char* output );

#if defined(POLARSSL_SELF_TEST)
int sm2_self_test( int );
#endif
#ifdef __cplusplus
}
#endif

#endif  /* POLARSSL_SM2_H */
