#ifndef P4_CRYPTO_PRIV_H
#define P4_CRYPTO_PRIV_H

#include <stdbool.h>
#include <stddef.h>

#include "psa/crypto.h"

bool p4_crypto_ready(void);
void p4_crypto_detail_set(int detail);
int p4_crypto_last_detail(void);
int p4_crypto_from_psa(psa_status_t status);
void p4_crypto_key_drop(psa_key_id_t key_id, bool key_live,
                        psa_status_t *status);
bool p4_crypto_overlap(const void *a, size_t a_len,
                       const void *b, size_t b_len);

#endif
