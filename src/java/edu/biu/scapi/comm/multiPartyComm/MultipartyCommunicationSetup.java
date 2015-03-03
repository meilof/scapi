package edu.biu.scapi.comm.multiPartyComm;

import java.util.Map;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;

/** 
 * The MultipartyCommunicationSetup interface manages the common functionality of all multiparty communications. <p>
 * There are several ways to communicate between parties - using sockets, queues, etc. Each concrete way should implements this 
 * interface and the functions in it.<p>
 * This interface should be used in the general case of communication between multiple parties. In case of two parties there is a simpler interface 
 * that can be used, called {@link TwoPartyCommunicationSetup}.<p>
 * 
 * The Communications Layer package is a tool used by a client that is interested in setting up connections 
 * between itself and other party. As such, this layer does not initiate any independent tasks, but the opposite. Given two parties, 
 * it attempts to set connections to them according to parameters given by the calling application. If succeeds, it returns these 
 * connections so that the calling client can send and receive data over them.<p>
 * Note that multiple connections can be created between each pair of parties; the user can ask to set any number of connections between him and every other party.
 * 
 * An application written for running a multiparty protocol can be the client of the Communications Layer. An example of a possible usage follows:<p>
 * <ul>
 * <li>Instantiate an object of type MultipartyCommunicationSetup.</li>
 * <li>Call the prepareForCommunication method of that object with list of parties to connect to and other setup parameters. </li>
 * <li>Get from prepareForCommunication a container holding all ready connections.</li>
 * <li>Start the multiparty protocol.</li> 
 * <li>Call the send and receive methods of the ready connections as needed by the protocol.</li>
 * </ul>
 * The application may be interested in putting each channel in a different thread but it is up to the application to do so and not 
 * the responsibility of the Communications Layer. This provides more flexibility of use.
 * 
 * MultipartyCommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. 
 * This interface supplies a mechanism for notifying classes that a timeout has arrived. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface MultipartyCommunicationSetup {
	
	/**
	 * An application that wants to use the communication layer will call this function in order to prepare for 
	 * communication after providing the required parameters. <p>
	 * The constructor of the concrete classes should receive the data of the parties participate in the communication.
	 * After that, this function initiates the creation of the final actual connections between the parties. <p>
	 * 
	 * This function gets a map that contains number of connection that should be established between the current party (application) and 
	 * any other party in the protocol. The key for the map is the PartyData object contains the data of the other party and the value in the 
	 * map can be two different things:
	 * 1. Integer - the number of connections that should be established between the current party and the party in the key.
	 * 2. String[] - the names of the connections that should be established between the current party and the party in the key.
	 * 
	 * Each connection has a unique name, that we call ID. This name used to distinguish between the created connections
	 * in order to make it easier and more convenient to understand what is the usage of each connection.<p>
	 * If this function succeeds, the application may use the send and receive functions of the created channels to 
	 * pass messages.<p> 
	 * In this function, Nagle's algorithm is disabled; for cryptographic protocols this is typically much better. 
	 * In order to use the Nagle algorithm, call the enableNagle() function.
	 * 
	 * @param connectionsPerParty indicates the amount of connections or the names of connections that should be created between the current application 
	 * and any other party in the protocol
	 * @param timeOut the maximum amount of time we allow for the connection stage.
	 * @return a map contains the connected channels. The key to the map is the PartyData of a the parties on the protocol and the value is 
	 * the created connections to this party.
	 * @throws TimeoutException in case a timeout has occurred before all channels have been connected.
	 */
	public Map<PartyData, Map<String, Channel>> prepareForCommunication(Map<PartyData, Object> connectionsPerParty, long timeOut) throws TimeoutException;
	
	
	/**
	 * Enables to use Nagle algrithm in the communication. <p>
	 * By default Nagle algorithm is disabled since it is much better for cryptographic algorithms.
	 */
	public void enableNagle();
		
	
	/**
	 * There are several implementations that should close the communication object. 
	 */
	public void close();
	
}
