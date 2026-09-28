/* libhelios: NAR pipeline and Nix binary cache formats. */
#ifndef HELIOS_H
#define HELIOS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HL_OK 0
#define HL_E_IO (-1)
#define HL_E_UNSUPPORTED_FILE (-2)
#define HL_E_ZSTD (-3)
#define HL_E_ABORTED (-4)
#define HL_E_INVALID (-5)
#define HL_E_NOMEM (-6)
#define HL_E_CHANGED (-7)
#define HL_E_UNSUPPORTED_OS (-8)
#define HL_E_TRUNCATED (-9)
#define HL_E_NOT_NAR (-10)
#define HL_E_BUFFER (-11)

const char *hl_strerror(int rc);
/* errno of the last failed syscall on the calling thread. */
int hl_last_errno(void);

/* ── nix32 ── */

/* Writes ceil(len * 8 / 5) chars (32 for 20 bytes, 52 for 32 bytes). */
size_t hl_nix32_encode(const uint8_t *bytes, size_t len, char *out);
int hl_nix32_decode(const char *text, size_t text_len, uint8_t *out, size_t out_len);
bool hl_store_basename_valid(const char *base, size_t len);

/* ── Compressing NAR pipeline ── */

typedef struct {
    uint8_t file_hash[32]; /* sha256 of the compressed stream */
    uint64_t file_size;
    uint8_t nar_hash[32]; /* sha256 of the uncompressed NAR */
    uint64_t nar_size;
} hl_digest;

typedef struct {
    int level;          /* zstd level; 0 disables compression */
    int threads;        /* zstd worker threads; 0 = calling thread */
    uint64_t size_hint; /* expected NAR size, 0 if unknown */
} hl_dump_options;

/* Return non-zero to abort the pipeline with HL_E_ABORTED. */
typedef int (*hl_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/* Serialise `path` as a NAR, compress it, and stream it to `write`.
 * Linux only; returns HL_E_UNSUPPORTED_OS elsewhere. */
int hl_nar_dump(const char *path, const hl_dump_options *opts, hl_write_fn write, void *ctx, hl_digest *out);

/* Same pipeline, fed with NAR bytes from elsewhere (e.g. nix store dump-path). */
typedef struct hl_compressor hl_compressor;
hl_compressor *hl_compressor_new(const hl_dump_options *opts, hl_write_fn write, void *ctx);
int hl_compressor_update(hl_compressor *c, const uint8_t *data, size_t len);
int hl_compressor_finish(hl_compressor *c, hl_digest *out);
void hl_compressor_free(hl_compressor *c);

/* ── Upload verifier ── */

#define HL_COMPRESSION_NONE 0
#define HL_COMPRESSION_ZSTD 1

typedef struct hl_verifier hl_verifier;
hl_verifier *hl_verifier_new(int compression);
int hl_verifier_update(hl_verifier *v, const uint8_t *data, size_t len);
/* Fails with HL_E_TRUNCATED or HL_E_NOT_NAR on bad input. */
int hl_verifier_finish(hl_verifier *v, hl_digest *out);
void hl_verifier_free(hl_verifier *v);

/* ── Signing and narinfo ── */

typedef struct hl_signer hl_signer;
/* Parses a Nix secret key: "<name>:<base64>". */
hl_signer *hl_signer_new(const char *key, size_t len);
void hl_signer_free(hl_signer *s);
/* Writes "<name>:<base64 public key>". Sets *out_len even on HL_E_BUFFER. */
int hl_signer_public_key(const hl_signer *s, char *out, size_t cap, size_t *out_len);

typedef struct {
    const char *ptr;
    size_t len;
} hl_str;

typedef struct {
    hl_str store_path;         /* /nix/store/<hash>-<name> */
    const uint8_t *nar_hash;   /* 32 bytes */
    uint64_t nar_size;
    const uint8_t *file_hash;  /* 32 bytes */
    uint64_t file_size;
    hl_str compression;        /* zstd | none | xz | bzip2 */
    hl_str references;         /* space-separated basenames */
    hl_str deriver;            /* basename or empty */
    hl_str system;             /* or empty */
} hl_narinfo_input;

/* Validates every field and renders a (signed, if signer != NULL) narinfo
 * into a heap buffer that must be released with hl_free. */
int hl_narinfo_render(const hl_narinfo_input *in, const hl_signer *signer, char **out, size_t *out_len);
void hl_free(char *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
