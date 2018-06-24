# AesCryptor
一个用到sgx的aes加密解密服务测试程序
## 功能
enclave1和enclave2完成LocalATtestation后,enclave1对enclave2的加密解密功能进行10轮测试.

每轮测试项:
- setkey: enclave1随机生成128bit的AES密钥和12字节的iv,发送给enclave2,返回SUCCESS则密钥设置功能测试通过.
- decrypt:enclave1随机生成128byte的明文p,加密得到密文c,将密文c发给enclave2,将传回的明文p'和p比对,相同则decrypt测试通过.
- encrypt: enclave1随机生成128byte的明文p,加密得到密文c,将明文p发给enclave2,将传回的密文c'和c比对,相同则encrypt测试通过.
## 实现流程
三个测试的实现都是按照SampleCode中enclave_to_enclave_call机制.
- step 1: 初始化, 首先app.c创建两个enclave (sgx_create_enclave)
- step 2: attestation
    - enclave 1向Intel ECDH key exchange library申请创建一个与enclave 2的dh_session,这个过程是通过```ATTESTATION_STATUS create_session(sgx_enclave_id_t src_enclave_id,                         sgx_enclave_id_t dest_enclave_id,dh_session_t *session_info)```函数完成的,函数内部进行了两个enclave的LocalAttestation,具体过程可以参考Intel® Software Guard Extensions (Intel® SGX) SDK for Linux* OS手册的LocalAttestation部分. (LocalATtestation时候,enclave 1和enclave 2都在session_request的时候把对应的dh_session放在了自己的map中,注意enclave1_to_2的session和enclave2_to_1的session是不同的,它们是根据dest_enclave_id来查询map)
    - enclave 1准备进行一个enclave_to_enclave_call调用enclave 2的foo1函数,或者准备进行message_exchange,两者方式类似,以enclave_to_enclave_call为例
        - 调用marshal_input_parameters_e2_foo1处理一下要传递的变量,把要传递的变量放入一个数据结构,变量主要包括enclave 2中foo1函数的索引(通过函数指针调用foo1,索引在func_table中定义)和foo1用到的参数
        - enclave 1调用send_request_receive_response,调用时会带上dh_session信息, 这个函数会用dh_session的AEK对所有要传输的数据进行AES加密,然后进行一个Ocall: send_request_ocall, ocall根据目标enclave id找到enclave2,调用Enclave2_generate_response,即执行enclave 2中的generate_response函数(用不同prefix的方式来调用不同enclave的函数)
        - enclave 2中的generate_response会根据src_enclave_id从全局map中查到dh_session,然后用session的AEK进行解密,获得enclave 1传来的数据,根据msg_type进行不同处理:MESSAGE_EXCHANGE则将收到的secret data加密后,用类似的方法传回去;ENCLAVE_TO_ENCLAVE_CALL则调用enclave_to_enclave_call_dispatcher,解析fn函数指针调用相应函数

## 总结
通过这个实验比较深入的了解了SGX的原理和使用.

头回用c语言开发比较复杂的应用,在指针和typedef两个方面踩了一些坑, 但是对c语言指针的使用有了初步的理解:
- 很多时候用char \**还是char *是和内存有关的,如果想让一个char *s指向一串字符
	- 这个s还没有分配空间,就可以用foo(char \**s), *s = (char *)malloc(sizeof(xxx))
	- 如果用*s = temp_buff, 那么就不能犯free(temp_buff)的错误
	- foo(char *s), s=(char *)malloc(sizeof(xxx))看上去总像是对的,对比一下第一条就知道这个错误了
- ``` typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE]```, 从sgx_aes_gcm_128bit_tag_t看不出是个数组, 一不小心就用'='去赋值了