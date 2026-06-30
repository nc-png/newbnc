#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* Parameters for KDF and AEAD */
#define GC_VERSION          1
#define GC_SALT_LEN         16
#define GC_IV_LEN           12
#define GC_TAG_LEN          16
#define GC_KEY_LEN          32   /* AES-256 */
#define GC_PBKDF2_ITERS     100000

/* Simple password prompt with echo disabled */
static int prompt_password(const char *prompt, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return -1;

    struct termios oldt, newt;
    int fd = STDIN_FILENO;

    if (tcgetattr(fd, &oldt) != 0) {
        perror("tcgetattr");
        return -1;
    }
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    if (tcsetattr(fd, TCSAFLUSH, &newt) != 0) {
        perror("tcsetattr");
        return -1;
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if (!fgets(buf, (int)buflen, stdin)) {
        tcsetattr(fd, TCSAFLUSH, &oldt);
        fprintf(stderr, "\n");
        return -1;
    }

    size_t len = strlen(buf);
    if (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[len-1] = '\0';
    }

    tcsetattr(fd, TCSAFLUSH, &oldt);
    fprintf(stderr, "\n");
    return 0;
}

/* Hex encode */
static char *hex_encode(const uint8_t *data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;

    for (size_t i = 0; i < len; i++) {
        out[2*i]     = hex[(data[i] >> 4) & 0xF];
        out[2*i + 1] = hex[data[i] & 0xF];
    }
    out[len * 2] = '\0';
    return out;
}

/* Hex decode */
static uint8_t *hex_decode(const char *hexstr, size_t *out_len) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0) return NULL;

    size_t bytes = len / 2;
    uint8_t *out = malloc(bytes);
    if (!out) return NULL;

    for (size_t i = 0; i < bytes; i++) {
        char c1 = hexstr[2*i];
        char c2 = hexstr[2*i + 1];
        int v1, v2;

        if (c1 >= '0' && c1 <= '9') v1 = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') v1 = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') v1 = c1 - 'A' + 10;
        else { free(out); return NULL; }

        if (c2 >= '0' && c2 <= '9') v2 = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') v2 = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') v2 = c2 - 'A' + 10;
        else { free(out); return NULL; }

        out[i] = (uint8_t)((v1 << 4) | v2);
    }

    if (out_len) *out_len = bytes;
    return out;
}

/* Derive key from password and salt using PBKDF2-HMAC-SHA256 */
static int derive_key(const char *password,
                      const uint8_t *salt, size_t saltlen,
                      uint8_t *key, size_t keylen) {
    if (!password || !salt || !key) return 0;

    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, (int)saltlen,
                           GC_PBKDF2_ITERS,
                           EVP_sha256(),
                           (int)keylen, key)) {
        return 0;
    }
    return 1;
}

/* Encrypt plaintext using AES-256-GCM.
   Output format (binary): [version][salt][iv][tag][ciphertext]
*/
static char *encrypt_config(const uint8_t *plain, size_t plen,
                            const char *password) {
    uint8_t salt[GC_SALT_LEN];
    uint8_t iv[GC_IV_LEN];
    uint8_t tag[GC_TAG_LEN];
    uint8_t key[GC_KEY_LEN];

    if (!RAND_bytes(salt, sizeof(salt))) {
        fprintf(stderr, "genconfig: RAND_bytes(salt) failed\n");
        return NULL;
    }
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "genconfig: RAND_bytes(iv) failed\n");
        return NULL;
    }
    if (!derive_key(password, salt, sizeof(salt), key, sizeof(key))) {
        fprintf(stderr, "genconfig: key derivation failed\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "genconfig: EVP_CIPHER_CTX_new failed\n");
        return NULL;
    }

    int ok = 0;
    uint8_t *cipher = NULL;
    int len = 0, outlen = 0;

    cipher = malloc(plen + GC_TAG_LEN); /* ciphertext only; tag is separate */
    if (!cipher) {
        fprintf(stderr, "genconfig: out of memory\n");
        goto cleanup;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "genconfig: EVP_EncryptInit_ex failed\n");
        goto cleanup;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GC_IV_LEN, NULL)) {
        fprintf(stderr, "genconfig: EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "genconfig: EVP_EncryptInit_ex (key/iv) failed\n");
        goto cleanup;
    }

    if (!EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plen)) {
        fprintf(stderr, "genconfig: EVP_EncryptUpdate failed\n");
        goto cleanup;
    }
    outlen = len;

    if (!EVP_EncryptFinal_ex(ctx, cipher + outlen, &len)) {
        fprintf(stderr, "genconfig: EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    outlen += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GC_TAG_LEN, tag)) {
        fprintf(stderr, "genconfig: EVP_CTRL_GCM_GET_TAG failed\n");
        goto cleanup;
    }

    /* Build final binary blob: version + salt + iv + tag + ciphertext */
    size_t blob_len = 1 + GC_SALT_LEN + GC_IV_LEN + GC_TAG_LEN + (size_t)outlen;
    uint8_t *blob = malloc(blob_len);
    if (!blob) {
        fprintf(stderr, "genconfig: out of memory (blob)\n");
        goto cleanup;
    }

    size_t pos = 0;
    blob[pos++] = GC_VERSION;
    memcpy(blob + pos, salt, GC_SALT_LEN); pos += GC_SALT_LEN;
    memcpy(blob + pos, iv, GC_IV_LEN);     pos += GC_IV_LEN;
    memcpy(blob + pos, tag, GC_TAG_LEN);   pos += GC_TAG_LEN;
    memcpy(blob + pos, cipher, (size_t)outlen);

    char *hex = hex_encode(blob, blob_len);
    free(blob);

    if (!hex) {
        fprintf(stderr, "genconfig: hex encode failed\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (cipher) {
        memset(cipher, 0, (size_t)(plen + GC_TAG_LEN));
        free(cipher);
    }
    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, sizeof(key));
    memset(salt, 0, sizeof(salt));
    memset(iv, 0, sizeof(iv));
    memset(tag, 0, sizeof(tag));

    if (!ok) return NULL;
    return hex;
}

/* Decrypt binary blob produced by encrypt_config */
static uint8_t *decrypt_config(const char *password,
                               const uint8_t *blob, size_t blob_len,
                               size_t *out_plen) {
    if (!password || !blob || blob_len < 1 + GC_SALT_LEN + GC_IV_LEN + GC_TAG_LEN)
        return NULL;

    size_t pos = 0;
    uint8_t version = blob[pos++];
    if (version != GC_VERSION) {
        fprintf(stderr, "genconfig: unsupported config version\n");
        return NULL;
    }

    if (blob_len < pos + GC_SALT_LEN + GC_IV_LEN + GC_TAG_LEN) {
        fprintf(stderr, "genconfig: truncated blob\n");
        return NULL;
    }

    const uint8_t *salt = blob + pos; pos += GC_SALT_LEN;
    const uint8_t *iv   = blob + pos; pos += GC_IV_LEN;
    const uint8_t *tag  = blob + pos; pos += GC_TAG_LEN;
    const uint8_t *ciphertext = blob + pos;
    size_t clen = blob_len - pos;

    uint8_t key[GC_KEY_LEN];
    if (!derive_key(password, salt, GC_SALT_LEN, key, sizeof(key))) {
        fprintf(stderr, "genconfig: key derivation failed\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "genconfig: EVP_CIPHER_CTX_new failed\n");
        memset(key, 0, sizeof(key));
        return NULL;
    }

    uint8_t *plain = malloc(clen + 1);
    if (!plain) {
        fprintf(stderr, "genconfig: out of memory (plain)\n");
        EVP_CIPHER_CTX_free(ctx);
        memset(key, 0, sizeof(key));
        return NULL;
    }

    int len = 0, outlen = 0;
    int ok = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "genconfig: EVP_DecryptInit_ex failed\n");
        goto cleanup;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GC_IV_LEN, NULL)) {
        fprintf(stderr, "genconfig: EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "genconfig: EVP_DecryptInit_ex (key/iv) failed\n");
        goto cleanup;
    }

    if (!EVP_DecryptUpdate(ctx, plain, &len, ciphertext, (int)clen)) {
        fprintf(stderr, "genconfig: EVP_DecryptUpdate failed\n");
        goto cleanup;
    }
    outlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GC_TAG_LEN, (void *)tag)) {
        fprintf(stderr, "genconfig: EVP_CTRL_GCM_SET_TAG failed\n");
        goto cleanup;
    }

    if (!EVP_DecryptFinal_ex(ctx, plain + outlen, &len)) {
        fprintf(stderr, "genconfig: authentication failed (wrong password or corrupted data)\n");
        goto cleanup;
    }
    outlen += len;

    plain[outlen] = '\0';
    if (out_plen) *out_plen = (size_t)outlen;
    ok = 1;

cleanup:
    if (!ok) {
        free(plain);
        plain = NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, sizeof(key));
    return plain;
}

/* Decrypt mode: read password + hex from stdin, print plaintext */
static int run_decrypt_mode(void) {
    char pass[256];
    char hexbuf[8192];

    if (!fgets(pass, sizeof(pass), stdin)) {
        fprintf(stderr, "genconfig: failed to read password\n");
        return 1;
    }
    size_t plen = strlen(pass);
    if (plen > 0 && (pass[plen-1] == '\n' || pass[plen-1] == '\r')) {
        pass[plen-1] = '\0';
    }

    if (!fgets(hexbuf, sizeof(hexbuf), stdin)) {
        fprintf(stderr, "genconfig: failed to read hex blob\n");
        return 1;
    }
    size_t hlen = strlen(hexbuf);
    if (hlen > 0 && (hexbuf[hlen-1] == '\n' || hexbuf[hlen-1] == '\r')) {
        hexbuf[hlen-1] = '\0';
    }

    size_t blob_len = 0;
    uint8_t *blob = hex_decode(hexbuf, &blob_len);
    if (!blob) {
        fprintf(stderr, "genconfig: invalid hex ciphertext\n");
        return 1;
    }

    size_t out_plen = 0;
    uint8_t *plain = decrypt_config(pass, blob, blob_len, &out_plen);
    free(blob);

    if (!plain) {
        /* decrypt_config logs the reason */
        return 1;
    }

    fwrite(plain, 1, out_plen, stdout);
    free(plain);
    return 0;
}

/* Create mode: generate script with encrypted config */
static int run_create_mode(const char *bind, const char *dest,
                           const char *title, const char *outfile) {
    if (!bind || !dest || !outfile || bind[0] == '\0' || dest[0] == '\0') {
        fprintf(stderr, "genconfig: -b and -d and -o are required\n");
        return 1;
    }

    if (strchr(bind, '\n') || strchr(dest, '\n') ||
        (title && strchr(title, '\n'))) {
        fprintf(stderr, "genconfig: parameters must not contain newlines\n");
        return 1;
    }

    char pass1[256], pass2[256];
    if (prompt_password("Enter config password: ", pass1, sizeof(pass1)) != 0) {
        fprintf(stderr, "genconfig: failed to read password\n");
        return 1;
    }
    if (prompt_password("Confirm password: ", pass2, sizeof(pass2)) != 0) {
        fprintf(stderr, "genconfig: failed to read password confirmation\n");
        return 1;
    }
    if (strcmp(pass1, pass2) != 0) {
        fprintf(stderr, "genconfig: passwords do not match\n");
        return 1;
    }
    if (pass1[0] == '\0') {
        fprintf(stderr, "genconfig: empty password is not allowed\n");
        return 1;
    }

    char plain[1024];
    int n = snprintf(plain, sizeof(plain),
                     "BIND=%s\nDEST=%s\nTITLE=%s\n",
                     bind,
                     dest,
                     title ? title : "");
    if (n < 0 || (size_t)n >= sizeof(plain)) {
        fprintf(stderr, "genconfig: config too large\n");
        return 1;
    }
    size_t plen = (size_t)n;

    char *hex = encrypt_config((const uint8_t *)plain, plen, pass1);
    if (!hex) {
        fprintf(stderr, "genconfig: encryption failed\n");
        return 1;
    }

    int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        fprintf(stderr, "genconfig: cannot open '%s' for writing: %s\n",
                outfile, strerror(errno));
        free(hex);
        return 1;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        fprintf(stderr, "genconfig: fdopen failed: %s\n", strerror(errno));
        close(fd);
        free(hex);
        return 1;
    }

    fprintf(fp,
            "#!/usr/bin/env bash\n"
            "# Generated by genconfig; stores FTP bouncer config encrypted with a password.\n"
            "# Encryption: AES-256-GCM, key derived via PBKDF2-HMAC-SHA256.\n"
            "\n"
            "DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
            "GENCONFIG=\"$DIR/genconfig\"\n"
            "FTPBNC=\"$DIR/ftpbnc\"\n"
            "\n"
            "CFG_HEX='%s'\n"
            "\n"
            "if [ ! -x \"$GENCONFIG\" ]; then\n"
            "  echo \"Error: genconfig binary not found at $GENCONFIG\" >&2\n"
            "  exit 1\n"
            "fi\n"
            "if [ ! -x \"$FTPBNC\" ]; then\n"
            "  echo \"Error: ftpbnc binary not found at $FTPBNC\" >&2\n"
            "  exit 1\n"
            "fi\n"
            "\n"
            "read -s -p \"Config password: \" PASS\n"
            "echo\n"
            "\n"
            "PLAINTEXT=\"$($GENCONFIG --decrypt <<EOF\n"
            "$PASS\n"
            "$CFG_HEX\n"
            "EOF\n"
            ")\"\n"
            "\n"
            "if [ -z \"$PLAINTEXT\" ]; then\n"
            "  echo \"Decryption failed or empty config\" >&2\n"
            "  exit 1\n"
            "fi\n"
            "\n"
            "BIND=\"\"\n"
            "DEST=\"\"\n"
            "TITLE=\"\"\n"
            "\n"
            "while IFS='=' read -r key value; do\n"
            "  case \"$key\" in\n"
            "    BIND) BIND=\"$value\" ;;\n"
            "    DEST) DEST=\"$value\" ;;\n"
            "    TITLE) TITLE=\"$value\" ;;\n"
            "  esac\n"
            "done <<< \"$PLAINTEXT\"\n"
            "\n"
            "if [ -z \"$BIND\" ] || [ -z \"$DEST\" ]; then\n"
            "  echo \"Config incomplete (missing BIND or DEST)\" >&2\n"
            "  exit 1\n"
            "fi\n"
            "\n"
            "CMD=(\"$FTPBNC\" -b \"$BIND\" -d \"$DEST\")\n"
            "if [ -n \"$TITLE\" ]; then\n"
            "  CMD+=( -t \"$TITLE\" )\n"
            "fi\n"
            "\n"
            "# Pass through any additional arguments (timeouts, -v, etc.)\n"
            "CMD+=(\"$@\")\n"
            "\n"
            "exec \"${CMD[@]}\"\n",
            hex);

    fclose(fp);
    free(hex);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--decrypt") == 0) {
        return run_decrypt_mode();
    }

    const char *bind = NULL;
    const char *dest = NULL;
    const char *title = NULL;
    const char *outfile = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "b:d:t:o:")) != -1) {
        switch (opt) {
        case 'b':
            bind = optarg;
            break;
        case 'd':
            dest = optarg;
            break;
        case 't':
            title = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        default:
            fprintf(stderr,
                    "Usage (create mode): %s -b bind_host:port -d dest_host:port [-t title] -o script.sh\n"
                    "Usage (decrypt mode): %s --decrypt\n",
                    argv[0], argv[0]);
            return 1;
        }
    }

    if (!outfile) {
        fprintf(stderr,
                "Usage (create mode): %s -b bind_host:port -d dest_host:port [-t title] -o script.sh\n",
                argv[0]);
        return 1;
    }

    return run_create_mode(bind, dest, title, outfile);
}
