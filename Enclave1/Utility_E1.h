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

#ifndef UTILITY_E1_H__
#define UTILITY_E1_H__

#include "stdint.h"

typedef struct _internal_param_struct_t
{
    uint32_t ivar1;
    uint32_t ivar2;
}internal_param_struct_t;

typedef struct _external_param_struct_t
{
    uint32_t var1;
    uint32_t var2;
    internal_param_struct_t *p_internal_struct;
}external_param_struct_t;

#ifdef __cplusplus
extern "C" {
#endif


uint32_t generate_aeskey(sgx_aes_gcm_128bit_key_t *key, size_t key_size, uint8_t *iv, size_t iv_size);
uint32_t generate_plain(char *p, size_t p_size);
uint32_t get_cipher(sgx_aes_gcm_128bit_key_t *key, char *p, size_t p_size, uint8_t *iv, size_t iv_size, char *c, sgx_aes_gcm_128bit_tag_t *mac);
uint32_t marshal_input_parameters_e2_setkey(uint32_t target_fn_id, uint32_t msg_type, sgx_aes_gcm_128bit_key_t *key, size_t key_size, uint8_t *iv, size_t iv_size, char** marshalled_buff, size_t* marshalled_buff_len);
uint32_t marshal_input_parameters_e2_decrypt(uint32_t target_fn_id, uint32_t msg_type, char *c, size_t c_size, sgx_aes_gcm_128bit_tag_t mac, char** marshalled_buff, size_t* marshalled_buff_len);
uint32_t marshal_input_parameters_e2_encrypt(uint32_t target_fn_id, uint32_t msg_type, char *p, size_t p_size, char** marshalled_buff, size_t* marshalled_buff_len);

uint32_t unmarshal_retval_and_output_parameters_e2_setkey(char* out_buff, char** retval);
uint32_t unmarshal_retval_and_output_parameters_e2_decrypt(char *p, char* out_buff, char** retval);
uint32_t unmarshal_retval_and_output_parameters_e2_encrypt(char *c, char* out_buff, char** retval);

#ifdef __cplusplus
 }
#endif
#endif
