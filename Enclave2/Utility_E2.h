/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef UTILITY_E2_H__
#define UTILITY_E2_H__
#include "stdint.h"

typedef struct _param_struct_t
{
    uint32_t var1;
    uint32_t var2;
}param_struct_t;

#ifdef __cplusplus
extern "C" {
#endif

uint32_t unmarshal_input_parameters_e2_setkey(sgx_aes_gcm_128bit_key_t* key, uint8_t* iv, ms_in_msg_exchange_t* ms);
uint32_t marshal_retval_and_output_parameters_e2_setkey(char** resp_buffer, size_t* resp_length, uint32_t retval);
uint32_t unmarshal_input_parameters_e2_decrypt(char** c, size_t* c_size, sgx_aes_gcm_128bit_tag_t *mac, ms_in_msg_exchange_t* ms);
uint32_t marshal_retval_and_output_parameters_e2_decrypt(char** resp_buffer, size_t* resp_length, char *p, size_t p_size);
uint32_t get_plain(sgx_aes_gcm_128bit_key_t *key, char *c, size_t c_size, uint8_t *iv, size_t iv_size, sgx_aes_gcm_128bit_tag_t mac, char **p);

#ifdef __cplusplus
 }
#endif
#endif

