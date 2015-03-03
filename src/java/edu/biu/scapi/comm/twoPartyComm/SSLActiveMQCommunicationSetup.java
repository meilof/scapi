package edu.biu.scapi.comm.twoPartyComm;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import org.apache.activemq.ActiveMQSslConnectionFactory;

import edu.biu.scapi.comm.twoPartyComm.ActiveMQCommunicationSetup.ActiveMQDestroyer;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

/**
 * This implementation uses ssl protocol in the JMS queue communication using the ActiveMQ implementation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLActiveMQCommunicationSetup extends QueueCommunicationSetup{
	
	/**
	 * Sets the parties parameters and create the communication using the given url.<p>
	 * The key store and trust store used in the ssl protocol should be names "scapiKeystore" and "scapiCacerts" 
	 * and the password for both of them is the given storePass.<p> 
	 * 
	 * In case you use this constructor, Nagles algorithm is disabled; for cryptographic protocols this is 
	 * typically much better.
	 *  
	 * @param url The url of the ActiveMQ broker.
	 * @param me Data of the current application.
	 * @param party Data of the other application.
	 * @param storePass The password for the key store and trust store.
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String storePass) throws DuplicatePartyException, SSLException, IOException {
		
		//Call the other constructor without enabling Nagle algorithm. This is much better for cryptographic algorithms.
		this(url, me, party, storePass, false);
	}
	
	/**
	 * Sets the parties parameters and create the communication using the given url.<p>
	 * The key store and trust store used in the ssl protocol should be names "scapiKeystore" and "scapiCacerts" 
	 * and the password for both of them is the given storePass.<p> 
	 * 
	 * In case you use this constructor, Nagles algorithm is disabled; for cryptographic protocols this is 
	 * typically much better.
	 *  
	 * @param url The url of the ActiveMQ broker.
	 * @param me Data of the current application.
	 * @param party Data of the other application.
	 * @param keyStoreName Name of the keystore file of this party.
	 * @param trustStoreName Name of the truststore file of this party.
	 * @param storePass The password for the key store and trust store.
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization. 
	 */
	public SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String keyStoreName, String trustStoreName, String storePass) throws DuplicatePartyException, SSLException, IOException {
		
		//Call the other constructor without enabling Nagle algorithm. This is much better for cryptographic algorithms.
		this(url, me, party, keyStoreName, trustStoreName, storePass, false);
	}
	
	/**
	 * Sets the parties parameters and create the communication using the given url.<p>
	 * 
	 * The created connection uses the TLSv1.2 protocol, the enabled cipherSuits are TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 
	 * and TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 and requires client authentication.
	 * 
	 * The key store and trust store used in the ssl protocol should be names "scapiKeystore" and "scapiCacerts" 
	 * and the password for both of them is the given storePass.
	 * 
	 * Note that using this function you can choose to use or not to use the Nagle algorithm.
	 * 
	 * @param url The url of the ActiveMQ broker.
	 * @param me Data of the current application.
	 * @param party Data of the other application.
	 * @param storePass The password for the key store and trust store.
	 * @param enableNagle Indicates if to use Nagle's algorithm or not. For cryptographic algorithms it is much better to disable Nagle's algorithm.
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String storePass, boolean enableNagle) throws DuplicatePartyException, SSLException, IOException {
		this(url, me, party, "scapiKeystore.jks", "scapiCacerts.jks", storePass, enableNagle);
	}
	
	/**
	 * Sets the parties parameters and create the communication using the given url.<p>
	 * 
	 * The created connection uses the TLSv1.2 protocol, the enabled cipherSuits are TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 
	 * and TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 and requires client authentication.
	 * 
	 * The key store and trust store used in the ssl protocol should be names "scapiKeystore" and "scapiCacerts" 
	 * and the password for both of them is the given storePass.
	 * 
	 * Note that using this function you can choose to use or not to use the Nagle algorithm.
	 * 
	 * @param url The url of the ActiveMQ broker.
	 * @param me Data of the current application.
	 * @param party Data of the other application.
	 * @param keyStoreName Name of the keystore file of this party.
	 * @param trustStoreName Name of the truststore file of this party.
	 * @param storePass The password for the key store and trust store.
	 * @param enableNagle Indicates if to use Nagle's algorithm or not. For cryptographic algorithms it is much better to disable Nagle's algorithm.
	 * @throws DuplicatePartyException In case both parties are the same.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String keyStoreName, String trustStoreName, String storePass, boolean enableNagle) throws DuplicatePartyException, SSLException, IOException {
	
		try {
			// Create an ActiveMQConnectionFactory with the given URL. 
			String uri = "failover:ssl://"+url;
			//Enable/disable nagle's algorithm (by defining tcpNoDelay) using the given enableNagle.
			uri += "?tcpNoDelay="+!enableNagle;
			//Add the enabled protocols.
			uri += ";enabledProtocols=TLSv1.2";
			//Add the enabled ciphersuits.
			uri += ";enabledCipherSuites=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
			//Configure the socket to use client mode when handshaking.
			uri += ";needClientAuth=true";
			
			//Create an ActiveMQSslConnectionFactory with all the above requirements.
			ActiveMQSslConnectionFactory  factory = new ActiveMQSslConnectionFactory(uri);
			
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
	         
	        //Set the factory with key and trust managers.
	        factory.setKeyAndTrustManagers(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
	        
	        //Call the constructor of QueueCommunicationSetup with the created factory and the ActiveMQDestroyer objects 
	        //in order to communicate using the ActiveMQ implementation.
			doConstruct(factory, new ActiveMQDestroyer(), me, party);
		
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
		} 
	}

}
