#ifndef TWEETNACL_H
#define TWEETNACL_H

// --- crypto_auth ---
#define crypto_auth_PRIMITIVE "hmacsha512256"
#define crypto_auth_BYTES 32
#define crypto_auth_KEYBYTES 32
extern int crypto_auth_hmacsha512256_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_hmacsha512256_tweet_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

// --- crypto_box ---
#define crypto_box_PRIMITIVE "curve25519xsalsa20poly1305"
#define crypto_box_PUBLICKEYBYTES 32
#define crypto_box_SECRETKEYBYTES 32
#define crypto_box_BEFORENMBYTES 32
#define crypto_box_NONCEBYTES 24
#define crypto_box_ZEROBYTES 32
#define crypto_box_BOXZEROBYTES 16
extern int crypto_box(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_box_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_box_keypair(unsigned char *,unsigned char *);
extern int crypto_box_beforenm(unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_box_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_box_open_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

// --- crypto_core ---
#define crypto_core_PRIMITIVE "salsa20"
#define crypto_core crypto_core_salsa20
#define crypto_core_OUTPUTBYTES crypto_core_salsa20_OUTPUTBYTES
#define crypto_core_INPUTBYTES crypto_core_salsa20_INPUTBYTES
#define crypto_core_KEYBYTES crypto_core_salsa20_KEYBYTES
#define crypto_core_CONSTBYTES crypto_core_salsa20_CONSTBYTES
#define crypto_core_IMPLEMENTATION crypto_core_salsa20_IMPLEMENTATION
#define crypto_core_VERSION crypto_core_salsa20_VERSION
#define crypto_core_salsa20_tweet_OUTPUTBYTES 64
#define crypto_core_salsa20_tweet_INPUTBYTES 16
#define crypto_core_salsa20_tweet_KEYBYTES 32
#define crypto_core_salsa20_tweet_CONSTBYTES 16
extern int crypto_core_salsa20_tweet(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
#define crypto_core_salsa20_tweet_VERSION "-"
#define crypto_core_salsa20 crypto_core_salsa20_tweet
#define crypto_core_salsa20_OUTPUTBYTES crypto_core_salsa20_tweet_OUTPUTBYTES
#define crypto_core_salsa20_INPUTBYTES crypto_core_salsa20_tweet_INPUTBYTES
#define crypto_core_salsa20_KEYBYTES crypto_core_salsa20_tweet_KEYBYTES
#define crypto_core_salsa20_CONSTBYTES crypto_core_salsa20_tweet_CONSTBYTES
#define crypto_core_salsa20_VERSION crypto_core_salsa20_tweet_VERSION
#define crypto_core_salsa20_IMPLEMENTATION "crypto_core/salsa20/tweet"
#define crypto_core_hsalsa20_tweet_OUTPUTBYTES 32
#define crypto_core_hsalsa20_tweet_INPUTBYTES 16
#define crypto_core_hsalsa20_tweet_KEYBYTES 32
#define crypto_core_hsalsa20_tweet_CONSTBYTES 16
extern int crypto_core_hsalsa20_tweet(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
#define crypto_core_hsalsa20_tweet_VERSION "-"
#define crypto_core_hsalsa20 crypto_core_hsalsa20_tweet
#define crypto_core_hsalsa20_OUTPUTBYTES crypto_core_hsalsa20_tweet_OUTPUTBYTES
#define crypto_core_hsalsa20_INPUTBYTES crypto_core_hsalsa20_tweet_INPUTBYTES
#define crypto_core_hsalsa20_KEYBYTES crypto_core_hsalsa20_tweet_KEYBYTES
#define crypto_core_hsalsa20_CONSTBYTES crypto_core_hsalsa20_tweet_CONSTBYTES
#define crypto_core_hsalsa20_VERSION crypto_core_hsalsa20_tweet_VERSION
#define crypto_core_hsalsa20_IMPLEMENTATION "crypto_core/hsalsa20/tweet"

// --- crypto_hashblocks ---
#define crypto_hashblocks_PRIMITIVE "sha512"
#define crypto_hashblocks_STATEBYTES crypto_hashblocks_sha512_STATEBYTES
#define crypto_hashblocks_BLOCKBYTES crypto_hashblocks_sha512_BLOCKBYTES
#define crypto_hashblocks_IMPLEMENTATION crypto_hashblocks_sha512_IMPLEMENTATION
#define crypto_hashblocks_VERSION crypto_hashblocks_sha512_VERSION
#define crypto_hashblocks_sha512_tweet_STATEBYTES 64
#define crypto_hashblocks_sha512_tweet_BLOCKBYTES 128
extern int crypto_hashblocks(unsigned char *,const unsigned char *,unsigned long long);
#define crypto_hashblocks_sha512_tweet_VERSION "-"
#define crypto_hashblocks_sha512_STATEBYTES crypto_hashblocks_sha512_tweet_STATEBYTES
#define crypto_hashblocks_sha512_BLOCKBYTES crypto_hashblocks_sha512_tweet_BLOCKBYTES
#define crypto_hashblocks_sha512_VERSION crypto_hashblocks_sha512_tweet_VERSION
#define crypto_hashblocks_sha512_IMPLEMENTATION "crypto_hashblocks/sha512/tweet"

// --- crypto_hash ---
#define crypto_hash_PRIMITIVE "sha512"
#define crypto_hash_BYTES 64
extern int crypto_hash(unsigned char *,const unsigned char *,unsigned long long);

// --- crypto_onetimeauth ---
#define crypto_onetimeauth_PRIMITIVE "poly1305"
#define crypto_onetimeauth_BYTES 16
#define crypto_onetimeauth_KEYBYTES 32
extern int crypto_onetimeauth(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_onetimeauth_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

// --- crypto_scalarmult ---
#define crypto_scalarmult_PRIMITIVE "curve25519"
#define crypto_scalarmult_BYTES 32
#define crypto_scalarmult_SCALARBYTES 32
extern int crypto_scalarmult(unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_scalarmult_base(unsigned char *,const unsigned char *);

// --- crypto_secretbox ---
#define crypto_secretbox_PRIMITIVE "xsalsa20poly1305"
#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 24
#define crypto_secretbox_ZEROBYTES 32
#define crypto_secretbox_BOXZEROBYTES 16
extern int crypto_secretbox(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_secretbox_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

// --- crypto_sign ---
#define crypto_sign_PRIMITIVE "ed25519"
#define crypto_sign_BYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_SECRETKEYBYTES 64
extern int crypto_sign(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_keypair(unsigned char *,unsigned char *);

// --- crypto_stream ---
#define crypto_stream_PRIMITIVE "xsalsa20"
#define crypto_stream crypto_stream_xsalsa20
#define crypto_stream_xor crypto_stream_xsalsa20_xor
#define crypto_stream_KEYBYTES crypto_stream_xsalsa20_KEYBYTES
#define crypto_stream_NONCEBYTES crypto_stream_xsalsa20_NONCEBYTES
#define crypto_stream_IMPLEMENTATION crypto_stream_xsalsa20_IMPLEMENTATION
#define crypto_stream_VERSION crypto_stream_xsalsa20_VERSION
#define crypto_stream_xsalsa20_tweet_KEYBYTES 32
#define crypto_stream_xsalsa20_tweet_NONCEBYTES 24
extern int crypto_stream_xsalsa20_tweet(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_xsalsa20_tweet_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#define crypto_stream_xsalsa20_tweet_VERSION "-"
#define crypto_stream_xsalsa20 crypto_stream_xsalsa20_tweet
#define crypto_stream_xsalsa20_xor crypto_stream_xsalsa20_tweet_xor
#define crypto_stream_xsalsa20_KEYBYTES crypto_stream_xsalsa20_tweet_KEYBYTES
#define crypto_stream_xsalsa20_NONCEBYTES crypto_stream_xsalsa20_tweet_NONCEBYTES
#define crypto_stream_xsalsa20_VERSION crypto_stream_xsalsa20_tweet_VERSION
#define crypto_stream_xsalsa20_IMPLEMENTATION "crypto_stream/xsalsa20/tweet"
#define crypto_stream_salsa20_tweet_KEYBYTES 32
#define crypto_stream_salsa20_tweet_NONCEBYTES 8
extern int crypto_stream_salsa20_tweet(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_tweet_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#define crypto_stream_salsa20_tweet_VERSION "-"
#define crypto_stream_salsa20 crypto_stream_salsa20_tweet
#define crypto_stream_salsa20_xor crypto_stream_salsa20_tweet_xor
#define crypto_stream_salsa20_KEYBYTES crypto_stream_salsa20_tweet_KEYBYTES
#define crypto_stream_salsa20_NONCEBYTES crypto_stream_salsa20_tweet_NONCEBYTES
#define crypto_stream_salsa20_VERSION crypto_stream_salsa20_tweet_VERSION
#define crypto_stream_salsa20_IMPLEMENTATION "crypto_stream/salsa20/tweet"

// --- crypto_verify ---
#define crypto_verify_PRIMITIVE "16"
#define crypto_verify_BYTES crypto_verify_16_BYTES
#define crypto_verify_IMPLEMENTATION crypto_verify_16_IMPLEMENTATION
#define crypto_verify_VERSION crypto_verify_16_VERSION
#define crypto_verify_16_tweet_BYTES 16
extern int crypto_verify_16(const unsigned char *,const unsigned char *);
#define crypto_verify_16_tweet_VERSION "-"
#define crypto_verify_16_BYTES crypto_verify_16_tweet_BYTES
#define crypto_verify_16_VERSION crypto_verify_16_tweet_VERSION
#define crypto_verify_16_IMPLEMENTATION "crypto_verify/16/tweet"
#define crypto_verify_32_tweet_BYTES 32
extern int crypto_verify_32(const unsigned char *,const unsigned char *);
#define crypto_verify_32_tweet_VERSION "-"
#define crypto_verify_32_BYTES crypto_verify_32_tweet_BYTES
#define crypto_verify_32_VERSION crypto_verify_32_tweet_VERSION
#define crypto_verify_32_IMPLEMENTATION "crypto_verify/32/tweet"

#endif /* ifndef TWEETNACL_H */
