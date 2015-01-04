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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

/**
 * This class implements a communication between two parties using SSL sockets.<p>
 * It derives the SocketCommunicationSetup class since the implementation is equal except the channel type.
 * This class creates an {@link SSLSocketChannel} while the SocketCommunicationSetup creates a {@link PlainTCPSocketChannel}.<p>
 * 
 * In order to create an sslSocket you should have an {@link SSLContext} which should be loaded with the key store and trust store. 
 * The keyStore contains the certificate that should be sent to the other party, in SCAPI the default name is "scapiKeystore".
 * The trustStore contains the certificate that should be received from the other party, in SCAPI the default name as "scapiCacerts".
 * This loading is done once in the constructor of this class and is passed to the {@link SSLSocketListenerThread} and to each {@link SSLSocketChannel}. This factory is used to send the certificate of this application.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLSocketCommunicationSetup extends SocketCommunicationSetup{
	
	private SSLContext sc;	//Loaded with the keyStore and trustStore and used to get the SSLSocketFactory and SSLServerSocketFactory from.
	
	/**
	 * Constructor that gets the data of both parties and the password to the keyStore and trustStore.
	 * @param me The data of the current application.
	 * @param party The data of the other application.
	 * @param storePass The password to the keyStore and trustStore
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLSocketCommunicationSetup(PartyData me, PartyData party, String storePass) throws DuplicatePartyException, SSLException, IOException {
		//Call the other constructor with scapi's default key store names.
		this(me, party, "scapiKeystore.jks", "scapiCacerts.jks", storePass);
		
	}
	
	/**
	 * Constructor that gets the data of both parties, the keystore and truststore files names and the password to them.
	 * @param me The data of the current application.
	 * @param party The data of the other application.
	 * @param keyStoreName Name of the keystore file of this party.
	 * @param trustStoreName Name of the truststore file of this party.
	 * @param storePass The password to the keyStore and trustStore
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLSocketCommunicationSetup(PartyData me, PartyData party, String keyStoreName, String trustStoreName, String storePass) throws DuplicatePartyException, SSLException, IOException{
		super(me, party);
		
		//Creating the SSL Context to get the socket factories from.
		try {
			
			//Loading the trust store containing the certificate that should be received from the other party.
			KeyStore trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream(trustStoreName), storePass.toCharArray());
	        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	        tmf.init(trustStore);
	         
	        //Loading the key store containing the certificate that should be sent to the other party.
	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        keyStore.load(new FileInputStream(keyStoreName), storePass.toCharArray());
	        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	        kmf.init(keyStore, storePass.toCharArray());
	         
	        //Create the SSL context and initialize it with the created key store and trust store.
	        sc = SSLContext.getInstance("TLSv1.2");
	        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
		
		} catch (UnrecoverableKeyException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());    
			throw new SSLException(e.getCause());
		} catch (KeyStoreException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());    
			throw new SSLException(e.getCause());
		} catch (CertificateException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());    
			throw new SSLException(e.getCause());
		} catch (NoSuchAlgorithmException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());    
			throw new SSLException(e.getCause());
		} catch (KeyManagementException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString());    
			throw new SSLException(e.getCause());
		} 
		
		//Create the connector object that creates and connects the channels.
		connector = new TwoPartySocketConnector(me, other, sc.getSocketFactory());
	}
	
	@Override
	protected void createListener(PlainTCPSocketChannel[] channels) {
		listeningThread = new SSLSocketListenerThread(channels, me, other.getIpAddress(), sc.getServerSocketFactory());
	}
	

}
