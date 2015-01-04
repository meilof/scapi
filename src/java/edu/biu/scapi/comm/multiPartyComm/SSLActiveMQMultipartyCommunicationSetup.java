package edu.biu.scapi.comm.multiPartyComm;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import javax.net.ssl.SSLException;

import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SSLActiveMQCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;
import edu.biu.scapi.exceptions.DuplicatePartyException;

/**
 * This implementation uses ssl protocol in the multiparty JMS queue communication using the ActiveMQ implementation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLActiveMQMultipartyCommunicationSetup extends ActiveMQMultipartyCommunicationSetup{

	/**
	 * A constructor that create an {@link SSLActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * It uses the default key store and trust store.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties List of parties to communicate with. The first party in the list represents the current application.
	 * @param storePass The password for the key store and trust store.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String storePass) throws DuplicatePartyException, SSLException, IOException {
		//Calls the SSLActiveMQMultipartyCommunicationSetup(url, parties, storePass, enableNagle) with Nagle's algorithm disabled.
		this(url, parties, storePass, false);
	}
	
	/**
	 * A constructor that create an {@link SSLActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * It uses the default key store and trust store.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties List of parties to communicate with. The first party in the list represents the current application.
	 * @param storePass The password for the key store and trust store.
	 * @param enableNagle Indicates if to use Nagle's algorithm or not. For cryptographic algorithms it is much better to disable Nagle's algorithm.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String storePass, boolean enableNagle) throws DuplicatePartyException, SSLException, IOException {
		//Calls the SSLActiveMQMultipartyCommunicationSetup(url, parties, keyStoreName, trustStoreName, storePass, enableNagle) with the default key store and trust store.
		this(url, parties, "scapiKeystore.jks", "scapiCacerts.jks", storePass, enableNagle);
	}
	
	/**
	 * A constructor that create an {@link SSLActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties List of parties to communicate with. The first party in the list represents the current application.
	 * @param keyStoreName Name of the keystore file of this party.
	 * @param trustStoreName Name of the truststore file of this party.
	 * @param storePass The password for the key store and trust store.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String keyStoreName, String trustStoreName, String storePass) throws DuplicatePartyException, SSLException, IOException {
		//Calls the SSLActiveMQMultipartyCommunicationSetup(url, parties, keyStoreName, trustStoreName, storePass, enableNagle) with Nagle's algorithm disabled.
		this(url, parties, keyStoreName, trustStoreName, storePass, false);
	}
	
	/**
	 * A constructor that create an {@link SSLActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties List of parties to communicate with. The first party in the list represents the current application.
	 * @param keyStoreName Name of the keystore file of this party.
	 * @param trustStoreName Name of the truststore file of this party.
	 * @param storePass The password for the key store and trust store.
	 * @param enableNagle Indicates if to use Nagle's algorithm or not. For cryptographic algorithms it is much better to disable Nagle's algorithm.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 * @throws IOException In case there is a problem with the key store or trust store file.
	 * @throws SSLException In case there is a problem during the SSL protocol initialization.
	 */
	public SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String keyStoreName, String trustStoreName, String storePass, boolean enableNagle) throws DuplicatePartyException, SSLException, IOException {
		int size = parties.size() - 1;
		
		//Prepare the map to hold the TwoPartyCommunicationSetup objects.
		twoPartyCommunications = new HashMap<PartyData, TwoPartyCommunicationSetup>();
		
		//For each party in the list except me, create an SSLActiveMQCommunicationSetup instance.
		for (int i=1; i<=size; i++){
			twoPartyCommunications.put(parties.get(i), new SSLActiveMQCommunicationSetup(url, parties.get(0), parties.get(i), keyStoreName, trustStoreName, storePass, enableNagle));
		}
	}

}
