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


// Enclave2.cpp : Defines the exported functions for the DLL application
#include "sgx_eid.h"
#include "Enclave2_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E2.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include <map>

#define UNUSED(val) (void)(val)

sgx_aes_gcm_128bit_key_t *global_aeskey;
uint8_t *global_iv;
size_t global_key_size = 128 / 8;
size_t global_iv_size = 12;
std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

static uint32_t e2_setkey_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);
static uint32_t e2_decrypt_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);
//static uint32_t e2_encrypt_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);

//Function pointer table containing the list of functions that the enclave exposes
const struct {
    size_t num_funcs;
    const void* table[2];
} func_table = {
    2,
    {
        (const void*)e2_setkey_wrapper,
        (const void*)e2_decrypt_wrapper,
        //(const void*)e2_encrypt_wrapper,
    }
};

//Makes use of the sample code function to establish a secure channel with the destination enclave
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                          sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;
    //Core reference code function for creating a session
    ke_status = create_session(src_enclave_id, dest_enclave_id,&dest_session_info);
    if(ke_status == SUCCESS)
    {
        //Insert the session information into the map under the corresponding destination enclave id
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}


//Makes use of the sample code function to close a current session
uint32_t test_close_session(sgx_enclave_id_t src_enclave_id,
                                sgx_enclave_id_t dest_enclave_id)
{
    dh_session_t dest_session_info;
    ATTESTATION_STATUS ke_status = SUCCESS;
    //Search the map for the session information associated with the destination enclave id passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
         dest_session_info = it->second;
    }
    else
    {
        return NULL;
    }
    //Core reference code function for closing a session
    ke_status = close_session(src_enclave_id, dest_enclave_id);

    //Erase the session information associated with the destination enclave id
    g_src_session_info_map.erase(dest_enclave_id);
    return ke_status;
}

//Function that is used to verify the trust of the other enclave
//Each enclave can have its own way verifying the peer enclave identity
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}

//Dispatch function that calls the approriate enclave function based on the function id
//Each enclave can have its own way of dispatching the calls from other enclave
extern "C" uint32_t enclave_to_enclave_call_dispatcher(char* decrypted_data,
                                                       size_t decrypted_data_length,
                                                       char** resp_buffer,
                                                       size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t (*fn1)(ms_in_msg_exchange_t *ms, size_t, char**, size_t*);
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;
    if(ms->target_fn_id >= func_table.num_funcs)
    {
        return INVALID_PARAMETER_ERROR;
    }
    fn1 = (uint32_t (*)(ms_in_msg_exchange_t*, size_t, char**, size_t*))func_table.table[ms->target_fn_id];
    return fn1(ms, decrypted_data_length, resp_buffer, resp_length);
}


static uint32_t e2_setkey(sgx_aes_gcm_128bit_key_t *key, uint8_t *iv)
{
    global_aeskey = key;
    global_iv = iv;
    return SUCCESS;
}

//Function which is executed on request from the source enclave
static uint32_t e2_setkey_wrapper(ms_in_msg_exchange_t *ms,
                    size_t param_lenth,
                    char** resp_buffer,
                    size_t* resp_length)
{
    UNUSED(param_lenth);
    sgx_aes_gcm_128bit_key_t *key;
    uint8_t *iv;
    uint32_t ret;
    if(!ms || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(unmarshal_input_parameters_e2_setkey(key, iv, ms) != SUCCESS)
        return ATTESTATION_ERROR;

    ret = e2_setkey(key, iv);

    if(marshal_retval_and_output_parameters_e2_setkey(resp_buffer, resp_length, ret) != SUCCESS )
        return MALLOC_ERROR; //can set resp buffer to null here

    return SUCCESS;
}

static uint32_t e2_decrypt(char *c, size_t c_size, char **p)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    ke_status = get_plain(global_aeskey, c, c_size, global_iv, global_iv_size, p);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }
    return SUCCESS;
}

//Function which is executed on request from the source enclave
static uint32_t e2_decrypt_wrapper(ms_in_msg_exchange_t *ms,
                    size_t param_lenth,
                    char** resp_buffer,
                    size_t* resp_length)
{
    UNUSED(param_lenth);
    char *c;
    char *p;
    size_t c_size;
    uint32_t ret;

    p = (char *)malloc(c_size);
    if (!p)
    {
        return MALLOC_ERROR;
    }

    if(!ms || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(unmarshal_input_parameters_e2_decrypt(c, &c_size, ms) != SUCCESS)
        return ATTESTATION_ERROR;

    ret = e2_decrypt(c, c_size, &p);
    
    ret = marshal_retval_and_output_parameters_e2_decrypt(resp_buffer, resp_length, p, c_size);

    if( ret != SUCCESS )
    {
        if (ret != ATTESTATION_ERROR)
            return MALLOC_ERROR; //can set resp buffer to null here
        return ret;
    }
    return SUCCESS;
}

// static uint32_t e2_encrypt(char *key, char *iv)
// {
//     global_aeskey = key;
//     global_iv = iv;
//     return SUCCESS;
// }

// //Function which is executed on request from the source enclave
// static uint32_t e2_encrypt_wrapper(ms_in_msg_exchange_t *ms,
//                     size_t param_lenth,
//                     char** resp_buffer,
//                     size_t* resp_length)
// {
//     UNUSED(param_lenth);
//     char *key, *iv;
//     uint32_t ret;
//     if(!ms || !resp_length)
//     {
//         return INVALID_PARAMETER_ERROR;
//     }
//     if(unmarshal_input_parameters_e2_setkey(key, iv, ms) != SUCCESS)
//         return ATTESTATION_ERROR;

//     ret = e2_setkey(key, iv);

//     if(marshal_retval_and_output_parameters_e2_setkey(resp_buffer, resp_length, ret) != SUCCESS )
//         return MALLOC_ERROR; //can set resp buffer to null here

//     return SUCCESS;
// }
