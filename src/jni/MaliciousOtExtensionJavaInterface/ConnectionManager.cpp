#include "ConnectionManager.h"

const char * maliciousot::ConnectionManager::DEFAULT_ADDRESS = "localhost";

using std::cerr;
using std::endl;

/*******************************************************************************
 *  Base class for server and client
 ******************************************************************************/
maliciousot::ConnectionManager::ConnectionManager(int role, int num_of_threads, const char * address, int port) : 
    m_sockets(num_of_threads+1) { //Number of threads that will be used in OT extension
    m_num_of_threads = num_of_threads;
    m_address = address;
    m_port = (USHORT) port;
    m_pid = role;

    cerr << "ConnectionManager(" << role << "," << num_of_threads << "," << address << "," << port  << ")" << endl;
}

maliciousot::ConnectionManager::ConnectionManager(int role) : ConnectionManager(role,
								   1,  // num of threads
								   DEFAULT_ADDRESS, // address
								   DEFAULT_PORT) { // port
    // default ctor sets default settings
}

/**
 * closes all the open sockets
 */
void maliciousot::ConnectionManager::cleanup() {
  for(int i = 0; i < m_num_of_threads; i++) {
      m_sockets[i].Close();
  }
}

maliciousot::ConnectionManager::~ConnectionManager() {
    cleanup();
}

/*******************************************************************************
 *  server class
 ******************************************************************************/
/**
 * ConnectionManagerServer ctors
 */
maliciousot::ConnectionManagerServer::ConnectionManagerServer(int role, 
						 int num_of_threads, 
						 const char * address, 
						 int port) : ConnectionManager(role,
									       num_of_threads,
									       address,
									       port) {}

maliciousot::ConnectionManagerServer::ConnectionManagerServer(int role) : ConnectionManager(role) {}

/**
 * listens and accepts connections on the server
 */
BOOL maliciousot::ConnectionManagerServer::setup_connection() {
    
    int num_connections = m_num_of_threads+1;

    cerr << "ConnectionManagerServer->setup_connection() started." << endl;
    
    // try to bind() and then listen
    if ((!m_sockets[0].Socket()) || 
	(!m_sockets[0].Bind(m_port, m_address)) ||
	(!m_sockets[0].Listen()) ) {
	goto listen_failure;
    }
    
    for(int i = 0; i<num_connections; i++) { //twice the actual number, due to double sockets for OT
	CSocket sock;
      
	// try: CSocket sock = accept()
	if(!m_sockets[0].Accept(sock)) {
	    cerr << "Error in accept" << endl;
	    goto listen_failure;
	}

	// cerr << "Server: accept succeded i = " << i << endl;
    
	// receive the other side thread id (the first thing that is sent on the socket)
	UINT threadID;
	sock.Receive(&threadID, sizeof(int));

	// cerr << "Server: received threadID = " << threadID << endl;
    
	// ??
	if(threadID >= num_connections) {
	    // cerr << "Server: threadID >= num_connections, num_connections = " << num_connections << endl;
	    sock.Close();
	    i--;
	    continue;
	}

	// locate the socket appropriately
	// cerr << "Server: attaching socket to threadID = " << threadID << endl;
	m_sockets[threadID].AttachFrom(sock);
	sock.Detach();
    }

    cerr << "ConnectionManagerServer->setup_connection() ended." << endl;
    
    return TRUE;

 listen_failure:
    cerr << "Listen failed" << endl;
    return FALSE;
}

/*******************************************************************************
 *  client class
 ******************************************************************************/

/**
 * ConnectionManagerClient ctors
 */
maliciousot::ConnectionManagerClient::ConnectionManagerClient(int role, 
						 int num_of_threads, 
						 const char * address, 
						 int port) : ConnectionManager(role,
									       num_of_threads,
									       address,
									       port) {}

maliciousot::ConnectionManagerClient::ConnectionManagerClient(int role) : ConnectionManager(role) {}

/**
 * initiates a connection (via socket) for each thread on the client
 */
BOOL maliciousot::ConnectionManagerClient::setup_connection() {
    BOOL bFail = FALSE;
    LONG lTO = CONNECT_TIMEO_MILISEC;
    int num_connections = m_num_of_threads+1;
    
    cerr << "ConnectionManagerClient->setup_connection() started." << endl;

    // try to initiate connection for socket k
    for(int k = num_connections-1; k >= 0 ; k--) {
	// cerr << "Client: started k = " << k << endl;
	// iterate on retries
	for(int i=0; i<RETRY_CONNECT; i++) {
	    if(!m_sockets[k].Socket()) {
		printf("Socket failure: ");
		goto connect_failure;
	    }
			
	    if(m_sockets[k].Connect(m_address, m_port, lTO)) {
		// cerr << "Client:" << k << "connected to (" << m_address << "," << m_port << ")" << endl;

		// send the thread id when connected
		m_sockets[k].Send(&k, sizeof(int));

		// cerr << "Client: sent k = " << k << endl;

		if(k == 0) {
		    //cerr << "connected" << endl;
		    cerr << "ConnectionManagerClient->setup_connection() ended." << endl;
		    return TRUE;
		} else {
		    // socket k is connected, breaking the "retries" loop
		    // and moving on to the next socket.
		    // cerr << "breaking the retries loop" << endl;
		    break;
		}

		// TODO: weird: seems to me that this code will never execute!
		// SleepMiliSec(10);
		// m_sockets[k].Close();
	    }

	    // unable to connect!
      
	    // if all allowed retries failed, server is unavailable
	    if(i+1 == RETRY_CONNECT) {
		goto server_not_available;
	    }

	    // else, waiting 20 milliseconds before retry
	    cerr << "sleeping 20 milliseconds" << endl;
	    SleepMiliSec(20);
	}
    }
 server_not_available:
    printf("Server not available: ");
 connect_failure:
    cerr << " (" << !m_pid << ") connection failed" << endl;
    return FALSE;
}
