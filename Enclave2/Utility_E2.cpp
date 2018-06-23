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
#include "sgx_tcrypto.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E2.h"
#include "stdlib.h"
#include "string.h"


uint32_t get_plain(sgx_aes_gcm_128bit_key_t *key, char *c, size_t c_size, uint8_t *iv, size_t iv_size, sgx_aes_gcm_128bit_tag_t mac, char **p)
{
    char *temp_buff;
    sgx_status_t status;
    const uint8_t* plaintext;
    uint32_t plaintext_length;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;
    temp_buff = (char*)malloc(c_size);
    if(!temp_buff)
        return MALLOC_ERROR;
    
    status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *)key, (uint8_t*)c, c_size,
                reinterpret_cast<uint8_t *>(temp_buff),
                reinterpret_cast<uint8_t *>(iv), iv_size, plaintext, plaintext_length,
                &mac);
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(temp_buff);
        return status;
    }
    
    *p = temp_buff;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t marshal_retval_and_output_parameters_e2_setkey(char** resp_buffer, size_t* resp_length, uint32_t retval)
{
    ms_out_msg_exchange_t *ms;
    size_t ret_param_len, ms_len;
    char *temp_buff;
    size_t retval_len;
    if(!resp_length)
        return INVALID_PARAMETER_ERROR;
    retval_len = sizeof(retval);
    ret_param_len = retval_len; //no out parameters
    temp_buff = (char*)malloc(ret_param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    memcpy(temp_buff, &retval, sizeof(retval)); 
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(&ms->ret_outparam_buff, temp_buff, ret_param_len);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}


uint32_t unmarshal_input_parameters_e2_setkey(sgx_aes_gcm_128bit_key_t* key, uint8_t* iv, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;

    size_t key_size = 128 / 8;
    size_t iv_size = 12;

    if(!key || !iv || !ms)
        return INVALID_PARAMETER_ERROR;

    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;

    if(len < key_size)
        return ATTESTATION_ERROR;

    if(!key)
        return MALLOC_ERROR;   
    if (!iv)
        return MALLOC_ERROR;

    memcpy(key, buff, key_size);
    memcpy(iv, buff + key_size, len - key_size);

    return SUCCESS;
}


uint32_t unmarshal_input_parameters_e2_decrypt(char** c, size_t* c_size, sgx_aes_gcm_128bit_tag_t *mac, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;
    
    if(!c || !c_size || !ms)
        return INVALID_PARAMETER_ERROR;

    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;

    *c = (char *)malloc(len - sizeof(sgx_aes_gcm_128bit_tag_t));
    if(!c)
        return MALLOC_ERROR;   


    memcpy(*c, buff, len - sizeof(sgx_aes_gcm_128bit_tag_t));
    memcpy(mac, buff + len - sizeof(sgx_aes_gcm_128bit_tag_t), sizeof(sgx_aes_gcm_128bit_tag_t));
    *c_size = len - sizeof(sgx_aes_gcm_128bit_tag_t);

    return SUCCESS;
}


uint32_t marshal_retval_and_output_parameters_e2_decrypt(char** resp_buffer, size_t* resp_length, char *p, size_t p_size)
{
    ms_out_msg_exchange_t *ms;
    size_t ret_param_len, ms_len;
    char *temp_buff;
    size_t retval_len;

    if (!p||!p_size)
        return ATTESTATION_ERROR;

    if(!resp_length)
        return INVALID_PARAMETER_ERROR;
    retval_len = p_size;
    ret_param_len = retval_len; //no out parameters
    temp_buff = (char*)malloc(ret_param_len);
    if(!temp_buff)
        return MALLOC_ERROR;

    memcpy(temp_buff, p, p_size);
    //memset(temp_buff, 0, retval_len);
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(&ms->ret_outparam_buff, temp_buff, ret_param_len);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}

