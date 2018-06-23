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


// Enclave1.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "Enclave1_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include <map>

#define UNUSED(val) (void)(val)

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);

//Function pointer table containing the list of functions that the enclave exposes
const struct {
    size_t num_funcs;
    const void* table[1];
} func_table = {
    1,
    {
        (const void*)e1_foo1_wrapper,
    }
};

sgx_aes_gcm_128bit_key_t *aeskey;
uint8_t *iv;
size_t aeskey_size = 128 / 8;
size_t iv_size = 12;

//Makes use of the sample code function to establish a secure channel with the destination enclave (Test Vector)
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                         sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;

    //Core reference code function for creating a session
    ke_status = create_session(src_enclave_id, dest_enclave_id, &dest_session_info);

    //Insert the session information into the map under the corresponding destination enclave id
    if(ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}


uint32_t test_setkey(sgx_enclave_id_t src_enclave_id,
                                          sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char* retval;

    target_fn_id = 0;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 300;

    // generate a random aeskey and iv
    aeskey = (sgx_aes_gcm_128bit_key_t* )malloc(aeskey_size);
    iv = (uint8_t *)malloc(iv_size);
    ke_status = generate_aeskey(aeskey, aeskey_size, iv, iv_size);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }
 
    //Marshals the input parameters for calling function setkey in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_setkey(target_fn_id, msg_type, aeskey, aeskey_size, iv, iv_size, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }


    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
          dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                            marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);


    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from setkey of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_setkey(out_buff, &retval);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }
    if ( *retval != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return *retval;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;    
}

uint32_t test_decrypt(sgx_enclave_id_t src_enclave_id,
                                          sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char* retval;
    char* plain;
    char* cipher;
    sgx_aes_gcm_128bit_tag_t mac;
    size_t plain_size;
    size_t cipher_size;

    target_fn_id = 1;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 300;

    plain_size = 128;
    cipher_size = plain_size;

    // generate a random plain
    plain = (char *)malloc(plain_size);
    ke_status = generate_plain(plain, plain_size);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }

    cipher = (char *)malloc(plain_size);
    ke_status = get_cipher(aeskey, plain, plain_size, iv, iv_size, cipher, &mac);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }


    //Marshals the input parameters for calling function setkey in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_decrypt(target_fn_id, msg_type, cipher, cipher_size, mac, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }


    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
          dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                            marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);


    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from decrypt of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_decrypt(plain, out_buff, &retval);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;    
}


// uint32_t test_encrypt(sgx_enclave_id_t src_enclave_id,
//                                           sgx_enclave_id_t dest_enclave_id)
// {
//     ATTESTATION_STATUS ke_status = SUCCESS;
//     uint32_t target_fn_id, msg_type;
//     char* marshalled_inp_buff;
//     size_t marshalled_inp_buff_len;
//     char* out_buff;
//     size_t out_buff_len;
//     dh_session_t *dest_session_info;
//     size_t max_out_buff_size;
//     char* retval;
//     char* plain;
//     char* cipher;
//     size_t plain_size;

//     target_fn_id = ;
//     msg_type = ENCLAVE_TO_ENCLAVE_CALL;
//     max_out_buff_size = 50;

//     plain_size = 128

//     // generate a random plain
//     ke_status = generate_plain(&plain, plain_size);
//     if(ke_status != SUCCESS)
//     {
//         return ke_status;
//     }


//     ke_status = get_cipher(aes_key, plain, plain_size, &cipher);
//     if(ke_status != SUCCESS)
//     {
//         return ke_status;
//     }


//     //Marshals the input parameters for calling function setkey in Enclave2 into a input buffer
//     ke_status = marshal_input_parameters_e2_encrypt(target_fn_id, msg_type, plain, plain_size, &marshalled_inp_buff, &marshalled_inp_buff_len);
//     if(ke_status != SUCCESS)
//     {
//         return ke_status;
//     }


//     //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
//     std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
//     if(it != g_src_session_info_map.end())
//     {
//           dest_session_info = &it->second;
//     }
//     else
//     {
//         SAFE_FREE(marshalled_inp_buff);
//         return INVALID_SESSION;
//     }

//     //Core Reference Code function
//     ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
//                                             marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);


//     if(ke_status != SUCCESS)
//     {
//         SAFE_FREE(marshalled_inp_buff);
//         SAFE_FREE(out_buff);
//         return ke_status;
//     }

//     //Un-marshal the return value and output parameters from setkey of Enclave 2
//     ke_status = unmarshal_retval_and_output_parameters_e2_encrypt(cipher, out_buff, &retval);
//     if(ke_status != SUCCESS)
//     {
//         SAFE_FREE(marshalled_inp_buff);
//         SAFE_FREE(out_buff);
//         return ke_status;
//     }

//     SAFE_FREE(marshalled_inp_buff);
//     SAFE_FREE(out_buff);
//     SAFE_FREE(retval);
//     return SUCCESS;    
// }



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


//Dispatcher function that calls the approriate enclave function based on the function id
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


//Function which is executed on request from the source enclave
static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms,
                    size_t param_lenth,
                    char** resp_buffer,
                    size_t* resp_length)
{
    UNUSED(param_lenth);
    return SUCCESS;
}