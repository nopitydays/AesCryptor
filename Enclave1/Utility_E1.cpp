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

#include "sgx_eid.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "stdlib.h"
#include "string.h"


uint32_t generate_aeskey(sgx_aes_gcm_128bit_key_t *key, size_t key_size, uint8_t *iv, size_t iv_size)
{
    unsigned char *temp_buff;
    temp_buff = (unsigned char*)malloc(key_size);
    memset(temp_buff, 0, key_size);
    if(!temp_buff)
        return MALLOC_ERROR;
    
    sgx_read_rand(temp_buff, key_size);
    memcpy(key, temp_buff, key_size);

    unsigned char *temp_iv_buff;
    temp_iv_buff = (unsigned char*)malloc(iv_size);
    memset(temp_iv_buff, 0, iv_size);
    if(!temp_iv_buff)
        return MALLOC_ERROR;
    
    sgx_read_rand(temp_iv_buff, iv_size);
    memcpy(iv, temp_iv_buff, iv_size);
    SAFE_FREE(temp_buff);
    SAFE_FREE(temp_iv_buff);
    return SUCCESS;
}

uint32_t generate_plain(char *p, size_t p_size)
{
    unsigned char *temp_buff;
    temp_buff = (unsigned char*)malloc(p_size);
    if(!temp_buff)
        return MALLOC_ERROR;
    
    sgx_read_rand(temp_buff, p_size);
    memcpy(p, temp_buff, p_size);
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t get_cipher(sgx_aes_gcm_128bit_key_t *key, char *p, size_t p_size, uint8_t *iv, size_t iv_size, char *c, sgx_aes_gcm_128bit_tag_t *mac)
{
    char *temp_buff;
    sgx_status_t status;
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_aes_gcm_128bit_tag_t temp_mac;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;
    temp_buff = (char*)malloc(p_size);
    if(!temp_buff)
        return MALLOC_ERROR;
    
    status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *)key, (uint8_t *)p, p_size,
                reinterpret_cast<uint8_t *>(temp_buff),
                reinterpret_cast<uint8_t *>(iv), iv_size, plaintext, plaintext_length,
                &temp_mac);
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(temp_buff);
        return status;
    }
    
    memcpy(c, temp_buff, p_size);
    memcpy(mac, &temp_mac, sizeof(sgx_aes_gcm_128bit_tag_t));
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t marshal_input_parameters_e2_setkey(uint32_t target_fn_id, uint32_t msg_type, sgx_aes_gcm_128bit_key_t *key, size_t key_size, uint8_t *iv, size_t iv_size, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
        
    param_len = key_size + iv_size;
    temp_buff = (char*)malloc(param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    memcpy(temp_buff, key, key_size);
    memcpy(temp_buff + key_size, iv, iv_size);
    ms_len = sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t marshal_input_parameters_e2_decrypt(uint32_t target_fn_id, uint32_t msg_type, char *c, size_t c_size, sgx_aes_gcm_128bit_tag_t mac, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
        
    param_len = c_size + sizeof(sgx_aes_gcm_128bit_tag_t);
    temp_buff = (char*)malloc(param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    memcpy(temp_buff, c, c_size);
    memcpy(temp_buff + c_size, mac, sizeof(sgx_aes_gcm_128bit_tag_t));
    ms_len = sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t marshal_input_parameters_e2_encrypt(uint32_t target_fn_id, uint32_t msg_type, char *p, size_t p_size, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
        
    param_len = p_size;
    temp_buff = (char*)malloc(param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    memcpy(temp_buff, p, p_size);
    ms_len = sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t unmarshal_retval_and_output_parameters_e2_setkey(char* out_buff, char** retval)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *retval = (char*)malloc(retval_len);
    if(!*retval)
        return MALLOC_ERROR;

    memcpy(*retval, ms->ret_outparam_buff, retval_len);
    return SUCCESS;
}


uint32_t unmarshal_retval_and_output_parameters_e2_decrypt(char *p, char* out_buff, char** retval)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff||!p)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *retval = (char*)malloc(retval_len);
    if(!*retval)
        return MALLOC_ERROR;

    memcpy(*retval, ms->ret_outparam_buff, retval_len);

    if (memcmp(p, *retval, retval_len))
        return ATTESTATION_ERROR;

    return SUCCESS;
}


uint32_t unmarshal_retval_and_output_parameters_e2_encrypt(char *c, char* out_buff, char** retval)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff||!c)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *retval = (char*)malloc(retval_len);
    if(!*retval)
        return MALLOC_ERROR;

    memcpy(*retval, ms->ret_outparam_buff, retval_len);

    if (memcmp(c, *retval, retval_len))
        return ATTESTATION_ERROR;

    return SUCCESS;
}


uint32_t umarshal_message_exchange_request(uint32_t* inp_secret_data, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;
    if(!inp_secret_data || !ms)
        return INVALID_PARAMETER_ERROR;
    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;
    if(len != sizeof(uint32_t))
        return ATTESTATION_ERROR;

    memcpy(inp_secret_data, buff, sizeof(uint32_t));    

    return SUCCESS;
}


uint32_t umarshal_message_exchange_response(char* out_buff, char** secret_response)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *secret_response = (char*)malloc(retval_len);
    if(!*secret_response)
    {
        return MALLOC_ERROR;
    }
    memcpy(*secret_response, ms->ret_outparam_buff, retval_len);
    return SUCCESS;
}

