/*
 * Modified from auto-generated file by Configure
 */

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * OpenSSL was configured with the following options:
 */

#ifndef OPENSSL_NO_AFALGENG
# define OPENSSL_NO_AFALGENG
#endif
#ifndef OPENSSL_NO_ASYNC
# define OPENSSL_NO_ASYNC
#endif
#ifndef OPENSSL_NO_BF
# define OPENSSL_NO_BF
#endif
#ifndef OPENSSL_NO_CAMELLIA
# define OPENSSL_NO_CAMELLIA
#endif
#ifndef OPENSSL_NO_CAPIENG
# define OPENSSL_NO_CAPIENG
#endif
#ifndef OPENSSL_NO_CAST
# define OPENSSL_NO_CAST
#endif
#ifndef OPENSSL_NO_CMS
# define OPENSSL_NO_CMS
#endif
#ifndef OPENSSL_NO_COMP
# define OPENSSL_NO_COMP
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
# define OPENSSL_NO_CRYPTO_MDEBUG
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# define OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
#endif
#ifndef OPENSSL_NO_DASYNCENG
# define OPENSSL_NO_DASYNCENG
#endif
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
# define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif
#ifndef OPENSSL_NO_EGD
# define OPENSSL_NO_EGD
#endif
#ifndef OPENSSL_NO_DSO
# define OPENSSL_NO_DSO
#endif
#ifndef OPENSSL_NO_GMP
# define OPENSSL_NO_GMP
#endif
#ifndef OPENSSL_NO_GOST
# define OPENSSL_NO_GOST
#endif
#ifndef OPENSSL_NO_HEARTBEATS
# define OPENSSL_NO_HEARTBEATS
#endif
#ifndef OPENSSL_NO_IDEA
# define OPENSSL_NO_IDEA
#endif
#ifndef OPENSSL_NO_JPAKE
# define OPENSSL_NO_JPAKE
#endif
#ifndef OPENSSL_NO_KRB5
# define OPENSSL_NO_KRB5
#endif
#ifndef OPENSSL_NO_LIBUNBOUND
# define OPENSSL_NO_LIBUNBOUND
#endif
#ifndef OPENSSL_NO_MD2
# define OPENSSL_NO_MD2
#endif
#ifndef OPENSSL_NO_MD4
# define OPENSSL_NO_MD4
#endif
#ifndef OPENSSL_NO_MDC2
# define OPENSSL_NO_MDC2
#endif
#ifndef OPENSSL_NO_RC2
# define OPENSSL_NO_RC2
#endif
#ifndef OPENSSL_NO_RC4
# define OPENSSL_NO_RC4
#endif
#ifndef OPENSSL_NO_RC5
# define OPENSSL_NO_RC5
#endif
#ifndef OPENSSL_NO_RFC3779
# define OPENSSL_NO_RFC3779
#endif
#ifndef OPENSSL_NO_RIPEMD
# define OPENSSL_NO_RIPEMD
#endif
#ifndef OPENSSL_NO_RMD160
# define OPENSSL_NO_RMD160
#endif
#ifndef OPENSSL_NO_SCTP
# define OPENSSL_NO_SCTP
#endif
#ifndef OPENSSL_NO_SRP
# define OPENSSL_NO_SRP
#endif
#ifndef OPENSSL_NO_SSL_TRACE
# define OPENSSL_NO_SSL_TRACE
#endif
#ifndef OPENSSL_NO_SSL2
# define OPENSSL_NO_SSL2
#endif
#ifndef OPENSSL_NO_SSL3
# define OPENSSL_NO_SSL3
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
# define OPENSSL_NO_SSL3_METHOD
#endif
#ifndef OPENSSL_NO_STORE
# define OPENSSL_NO_STORE
#endif
#ifndef OPENSSL_NO_UNIT_TEST
# define OPENSSL_NO_UNIT_TEST
#endif
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
# define OPENSSL_NO_WEAK_SSL_CIPHERS
#endif
#ifndef OPENSSL_THREADS
# define OPENSSL_THREADS
#endif
#ifndef OPENSSL_NO_HW
# define OPENSSL_NO_HW
#endif
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
# define OPENSSL_NO_DYNAMIC_ENGINE
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
# define OPENSSL_NO_WHIRLPOOL
#endif

/* The OPENSSL_NO_* macros are also defined as NO_* if the application
   asks for it.  This is a transient feature that is provided for those
   who haven't had the time to do the appropriate changes in their
   applications.  */
#ifdef OPENSSL_ALGORITHM_DEFINES
# if defined(OPENSSL_NO_BF) && !defined(NO_BF)
#  define NO_BF
# endif
# if defined(OPENSSL_NO_CAMELLIA) && !defined(NO_CAMELLIA)
#  define NO_CAMELLIA
# endif
# if defined(OPENSSL_NO_CAST) && !defined(NO_CAST)
#  define NO_CAST
# endif
# if defined(OPENSSL_NO_CMS) && !defined(NO_CMS)
#  define NO_CMS
# endif
# if defined(OPENSSL_NO_COMP) && !defined(NO_COMP)
#  define NO_COMP
# endif
# if defined(OPENSSL_NO_DES) && !defined(NO_DES)
#  define NO_DES
# endif
# if defined(OPENSSL_NO_EC_NISTP_64_GCC_128) && !defined(NO_EC_NISTP_64_GCC_128)
#  define NO_EC_NISTP_64_GCC_128
# endif
# if defined(OPENSSL_NO_FP_API) && !defined(NO_FP_API)
#  define NO_FP_API
# endif
# if defined(OPENSSL_NO_GMP) && !defined(NO_GMP)
#  define NO_GMP
# endif
# if defined(OPENSSL_NO_GOST) && !defined(NO_GOST)
#  define NO_GOST
# endif
# if defined(OPENSSL_NO_IDEA) && !defined(NO_IDEA)
#  define NO_IDEA
# endif
# if defined(OPENSSL_NO_JPAKE) && !defined(NO_JPAKE)
#  define NO_JPAKE
# endif
# if defined(OPENSSL_NO_KRB5) && !defined(NO_KRB5)
#  define NO_KRB5
# endif
# if defined(OPENSSL_NO_LIBUNBOUND) && !defined(NO_LIBUNBOUND)
#  define NO_LIBUNBOUND
# endif
# if defined(OPENSSL_NO_MD2) && !defined(NO_MD2)
#  define NO_MD2
# endif
# if defined(OPENSSL_NO_MD4) && !defined(NO_MD4)
#  define NO_MD4
# endif
# if defined(OPENSSL_NO_MDC2) && !defined(NO_MDC2)
#  define NO_MDC2
# endif
# if defined(OPENSSL_NO_RC2) && !defined(NO_RC2)
#  define NO_RC2
# endif
# if defined(OPENSSL_NO_RC4) && !defined(NO_RC4)
#  define NO_RC4
# endif
# if defined(OPENSSL_NO_RC5) && !defined(NO_RC5)
#  define NO_RC5
# endif
# if defined(OPENSSL_NO_RFC3779) && !defined(NO_RFC3779)
#  define NO_RFC3779
# endif
# if defined(OPENSSL_NO_RIPEMD) && !defined(NO_RIPEMD)
#  define NO_RIPEMD
# endif
# if defined(OPENSSL_NO_SCTP) && !defined(NO_SCTP)
#  define NO_SCTP
# endif
# if defined(OPENSSL_NO_SRP) && !defined(NO_SRP)
#  define NO_SRP
# endif
# if defined(OPENSSL_NO_SSL_TRACE) && !defined(NO_SSL_TRACE)
#  define NO_SSL_TRACE
# endif
# if defined(OPENSSL_NO_SSL2) && !defined(NO_SSL2)
#  define NO_SSL2
# endif
# if defined(OPENSSL_NO_SSL3) && !defined(NO_SSL3)
#  define NO_SSL3
# endif
# if defined(OPENSSL_NO_STDIO) && !defined(NO_STDIO)
#  define NO_STDIO
# endif
# if defined(OPENSSL_NO_STORE) && !defined(NO_STORE)
#  define NO_STORE
# endif
# if defined(OPENSSL_NO_UNIT_TEST) && !defined(NO_UNIT_TEST)
#  define NO_UNIT_TEST
# endif
#endif

/*
 * Sometimes OPENSSSL_NO_xxx ends up with an empty file and some compilers
 * don't like that.  This will hopefully silence them.
 */
#define NON_EMPTY_TRANSLATION_UNIT static void *dummy = &dummy;

/*
 * Applications should use -DOPENSSL_API_COMPAT=<version> to suppress the
 * declarations of functions deprecated in or before <version>. Otherwise, they
 * still won't see them if the library has been built to disable deprecated
 * functions.
 */
#if defined(OPENSSL_NO_DEPRECATED)
# define DECLARE_DEPRECATED(f)
#elif defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0))
# define DECLARE_DEPRECATED(f)    f __attribute__ ((deprecated));
#else
# define DECLARE_DEPRECATED(f)   f;
#endif

#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

#ifndef OPENSSL_MIN_API
# define OPENSSL_MIN_API 0
#endif

#if !defined(OPENSSL_API_COMPAT) || OPENSSL_API_COMPAT < OPENSSL_MIN_API
# undef OPENSSL_API_COMPAT
# define OPENSSL_API_COMPAT OPENSSL_MIN_API
#endif

#if OPENSSL_API_COMPAT < 0x10100000L
# define DEPRECATEDIN_1_1_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_1_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x10000000L
# define DEPRECATEDIN_1_0_0(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_1_0_0(f)
#endif

#if OPENSSL_API_COMPAT < 0x00908000L
# define DEPRECATEDIN_0_9_8(f)   DECLARE_DEPRECATED(f)
#else
# define DEPRECATEDIN_0_9_8(f)
#endif

/* Generate 80386 code? */
#undef I386_ONLY

#if !(defined(VMS) || defined(__VMS)) /* VMS uses logical names instead */
#if defined(HEADER_CRYPTLIB_H) && !defined(OPENSSLDIR)
#define ENGINESDIR "/usr/lib/engines"
#define OPENSSLDIR "/usr"
#endif
#endif

#undef OPENSSL_UNISTD
#define OPENSSL_UNISTD <unistd.h>

#define OPENSSL_EXPORT_VAR_AS_FUNCTION

#ifdef  __cplusplus
}
#endif
