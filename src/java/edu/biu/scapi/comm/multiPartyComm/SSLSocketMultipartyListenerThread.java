package edu.biu.scapi.comm.multiPartyComm;

import java.io.IOException;
import java.net.Socket;
import java.nio.channels.ClosedChannelException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.PlainTCPSocketChannel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.generals.Logging;

/**
 * This class listen to incoming connections from the other parties and set the received sockets to the right channels.
 * It uses the SSLServerSocket class and defining some parameters of the SSL protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class SSLSocketMultipartyListenerThread extends SocketMultipartyListenerThread{

	private SSLServerSocketFactory ssf; //Used to create the ssl server socket.
	
	/**
	* A constructor that opens the SSL server socket.
	* @param channelsPerParty The channels that should be set with receive socket for each other party in the protocol.
	* @param me The data of the current application.
	* @param ssf Used to create the ssl server socket.
	*/
	SSLSocketMultipartyListenerThread(Map<SocketPartyData, PlainTCPSocketChannel[]> channelsPerParty, SocketPartyData me, SSLServerSocketFactory ssf) {
		this.ssf = ssf;
		doConstruct(channelsPerParty, me);
	}
	
	/**
	 * created the {@link SSLServerSocket} using the {@link SSLServerSocketFactory} given in the constructor.
	 */
	@Override
	protected void createServerSocket(SocketPartyData me) {
		//prepare the listener.
		try {

			//Create the server socket.
			listener = ssf.createServerSocket(me.getPort(), 0, me.getIpAddress());

		} catch (IOException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	/**
	* This function is the main function of the SSLSocketMultipartyListenerThread. 
	* Mainly, we listen and accept valid connections as long as the flag bStopped is false or until we have 
	* got as much connections as we should.<p>
	*/
	public void run() {
		//Prepare a map to hold the number of connected channels for each party.
		Map<PartyData, Integer> partiesChannelsCount = new HashMap<PartyData, Integer>();
				
		//Set the state of all channels to connecting.
		int count = setConnectingState(partiesChannelsCount);
		
		int i=0;
		//Loop for listening to incoming connections and make sure that this thread should not stopped.
		while (i < count && !bStopped) {
		
			Socket socket = null;
			try {
				Logging.getLogger().log(Level.INFO, "Trying to listen "+ listener.getLocalPort());
				
				//Use the server socket to listen to incoming connections.
				socket = listener.accept();
			
			}	catch (ClosedChannelException e) {
				// TODO: handle exception
				Logging.getLogger().log(Level.WARNING, e.toString());
			} 	catch (IOException e) {
			
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		
			//If there was no connection request wait a second and try again.
			if(socket==null){
				try {
					Thread.sleep (1000);
				} catch (InterruptedException e) {
				
					Logging.getLogger().log(Level.INFO, e.toString());
				}
			//If there was an incoming request set the SSL parameters, check that it valid and set the accepted socket to the right channel.
			} else{
				//Set the enables protocol to TLS 1.2.
				String [] protocols = new String[1];
				protocols[0] = "TLSv1.2";
				((SSLSocket)socket).setEnabledProtocols(protocols);
				
				//Set the enables cipher suits to .
				String [] cipherSuits = new String[2];
				cipherSuits[0] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
				cipherSuits[1] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
				((SSLSocket)socket).setEnabledCipherSuites(cipherSuits);
				
				//Configure the socket to use server mode when handshaking and to check client authentication.
				((SSLSocket)socket).setUseClientMode(false);
				((SSLSocket)socket).setNeedClientAuth(true);
				
				//check that it valid and set the accepted socket to the right channel.
				i = setSocket(partiesChannelsCount, i, socket);
			}
		}
	
		Logging.getLogger().log(Level.INFO, "End of listening thread run");
		
		//After accepting all connections, close the thread.
		try {
			listener.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
