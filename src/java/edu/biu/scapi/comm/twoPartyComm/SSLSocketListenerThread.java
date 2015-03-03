/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

package edu.biu.scapi.comm.twoPartyComm;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.channels.ClosedChannelException;
import java.util.logging.Level;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import edu.biu.scapi.generals.Logging;

/**
 * This class listen to incoming connections from the other party and set the received sockets to the channels.
 * It uses the SSLServerSocket class and defining some parameters of the SSL protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class SSLSocketListenerThread extends SocketListenerThread {
	
	private SSLServerSocketFactory ssf; //Used to create the ssl server socket.
	
	/**
	* A constructor that opens the server socket.
	* @param channels the channels that should be set with receive socket.
	* @param me the data of the current application.
	* @param partyAdd The address to listen on.
	* @param ssf Used to create the ssl server socket.
	*/
	SSLSocketListenerThread(PlainTCPSocketChannel[] channels, SocketPartyData me, InetAddress partyAdd, SSLServerSocketFactory ssf) {
		this.ssf = ssf;
		doConstruct(channels, me, partyAdd);
	}
	
	/**
	 * created the {@link SSLServerSocket} using the {@link SSLServerSocketFactory} given in the constructor.
	 */
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
	* This function is the main function of the SSLSocketListenerThread. 
	* Mainly, we listen and accept valid connections as long as the flag bStopped is false or until we have 
	* got as much connections as we should.<p>
	*/
	public void run() {
		
		//Set the state of all channels to connecting.
		int size = channels.length;
		for (int i=0; i<size; i++){
		
			channels[i].setState(PlainTCPSocketChannel.State.CONNECTING);
		}
		
		int i=0;
		//Loop for listening to incoming connections and make sure that this thread should not stopped.
		while (i < size && !bStopped) {
		
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
			//If there was an incoming request, check it.
			} else{
				//Get the ip of the client socket.
				InetAddress inetAddr = socket.getInetAddress();
				
				//if the accepted address is not a valid address. I.e. different from the other party's address. 
				if(!inetAddr.equals(partyAddr)){//an unauthorized ip tried to connect
				
					//Close the socket.
					try {
						socket.close();
					} catch (IOException e) {
					
						Logging.getLogger().log(Level.WARNING, e.toString());
					}
					
				//If the accepted address is valid, set it as the receive socket of the channel.
				//The send socket is set in the SocketCommunicationSetup.connect function. 
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
					
					((SSLSocketChannel)channels[i]).setReceiveSocket(socket);
					
					//Increment the index of incoming connections.
					i++;
				}
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
