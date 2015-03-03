#include "OTExtensionMaliciousSenderInterface.h"

maliciousot::OtExtensionMaliciousSenderInterface::OtExtensionMaliciousSenderInterface(const char* address, 
										      int port,
										      int num_of_threads,
										      int num_base_ots, 
										      int num_ots) : 
    OtExtensionMaliciousCommonInterface(1,
					num_base_ots, 
					num_ots) {
    m_connection_manager = new ConnectionManagerServer(0, num_of_threads, address, port);
}

void maliciousot::OtExtensionMaliciousSenderInterface::init_ot_sender() {
    int nSndVals = 2;
    int wdsize = 1 << (CEIL_LOG2(m_num_base_ots));
    int nblocks = CEIL_DIVIDE(m_num_ots, NUMOTBLOCKS * wdsize);
    int s2ots = nblocks * m_num_base_ots;
    
    // key seed matrix used for the 1-step base OTs
    m_receiver_key_seeds_matrix = (BYTE*) malloc(AES_KEY_BYTES * m_num_base_ots * nSndVals);
    // key seeds for the 2-nd step base OTs
    m_sender_key_seeds = (BYTE*) malloc(AES_KEY_BYTES * s2ots);//m_security_level.symbits);
  
    // Server listen
    m_connection_manager->setup_connection();
    
    // 1st step: precompute base ot
    precompute_base_ots_sender();
    

    CBitVector seedcbitvec;
    CBitVector U(s2ots, m_receiver_seed, m_counter);
    CBitVector URev(s2ots);

    seedcbitvec.AttachBuf(m_sender_key_seeds, AES_KEY_BYTES * s2ots);

    XORMasking* masking_function = new XORMasking(AES_KEY_BITS);

    assert(nblocks <= NUMOTBLOCKS);
    
    // 2nd step: OT extension step to obtain the base-OTs for the next step
    m_receiver = new Mal_OTExtensionReceiver(nSndVals, m_security_level.symbits, 
					     m_connection_manager->get_sockets_data(),
					     m_receiver_key_seeds_matrix, 
					     m_receiver_seed, m_num_base_ots, s2ots);

    m_receiver->receive(s2ots, AES_KEY_BITS, U, seedcbitvec, R_OT, 1, masking_function);
    delete masking_function;

    for(int i = 0; i < s2ots; i++) {
	URev.SetBit(i, U.GetBitNoMask(i));
    }
    
    m_sender = new Mal_OTExtensionSender(nSndVals, m_security_level.symbits, 
					 m_connection_manager->get_sockets_data(),
					 URev, m_sender_key_seeds, m_num_base_ots, 
					 m_num_checks, s2ots, m_sender_seed);
}

/**
 * PrecomputeBaseOTsSender
 */
BOOL maliciousot::OtExtensionMaliciousSenderInterface::precompute_base_ots_sender() {
    int nSndVals = 2;
    // Execute NP receiver routine and obtain the key 
    BYTE* pBuf = new BYTE[SHA1_BYTES * m_num_base_ots * nSndVals];

    //=================================================	
    m_baseot_handler->Sender(nSndVals, m_num_base_ots, m_connection_manager->get_socket(0), pBuf);
	
    BYTE* pBufIdx = pBuf;
    for(int i=0; i<m_num_base_ots * nSndVals; i++) {
	memcpy(m_receiver_key_seeds_matrix + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
	pBufIdx += SHA1_BYTES;
    }
	
    delete [] pBuf;	

    return true;
}

/**
 * ObliviouslySend
 */
BOOL maliciousot::OtExtensionMaliciousSenderInterface::obliviously_send(CBitVector& X1, 
									CBitVector& X2, 
									int num_ots, 
									int bitlength, 
									BYTE version,
									MaskingFunction * masking_function) {
    bool success = FALSE;
    int nSndVals = 2; //Perform 1-out-of-2 OT
    
    // Execute OT sender routine
    success = m_sender->send(num_ots, bitlength, X1, X2, version, 
			     m_connection_manager->get_num_of_threads(), 
			     masking_function);
    
    return success;
}

maliciousot::OtExtensionMaliciousSenderInterface::~OtExtensionMaliciousSenderInterface() {
    delete m_connection_manager;
    delete m_sender;
    delete m_receiver;
}
