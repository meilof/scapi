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

import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

/**
 * This class implements a communication between two parties using TCP sockets.<p>
 * Each created channel contains two sockets; one is used to send messages and one to receive messages.<p>
 * This class encapsulates the stage of connecting to other parties. In actuality, the connection to other parties is 
 * performed in a few steps, which are not visible to the outside user.
 * These steps are:<p>
 * <ul> 
 * <li>for each requested channel,</li>
 * <li>Create an actual TCP socket with the other party. This socket is used to send messages</li>
 * <li>Create a server socket that listen to the other party's call. When received, the created socket is used to receive messages from the other party.</li>
 * <li>run a protocol that checks if all the necessary connections were set between my party and other party.</li>
 * <li>In the end return to the calling application a set of connected and ready channels to be used throughout a cryptographic protocol.</li>
 * </ul>
 * From this point onwards, the application can send and receive messages in each connection as required by the protocol.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SocketCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver{

	protected boolean bTimedOut = false; 							//Indicated whether or not to end the communication.
	private Watchdog watchdog;										//Used to measure times.
	private boolean enableNagle = false;							//Indicated whether or not to use Nagle optimization algorithm.
	protected TwoPartySocketConnector connector;					//Used to create and connect the channels to the other party.
	protected SocketListenerThread listeningThread;					//Listen to calls from the other party.
	private int connectionsNumber;									//Holds the number of created connections. 
	protected SocketPartyData me;									//The data of the current application.
	protected SocketPartyData other;								//The data of the other application to communicate with.
	
	/**
	 * A constructor that set the given parties.
	 * @param me The data of the current application.
	 * @param party The data of the other application to communicate with.
	 * @throws DuplicatePartyException 
	 */
	public SocketCommunicationSetup(PartyData me, PartyData party) throws DuplicatePartyException{
		//Both parties should be instances of SocketPArty.
		if (!(me instanceof SocketPartyData) || !(party instanceof SocketPartyData)){
			throw new IllegalArgumentException("both parties should be instances of SocketParty");
		}
		this.me = (SocketPartyData) me;
		this.other = (SocketPartyData) party;
		
		//Compare the two given parties. If they are the same, throw exception.
		int partyCompare = this.me.compareTo(other);
		if(partyCompare == 0){
			throw new DuplicatePartyException("Another party with the same ip address and port");
		}
		connectionsNumber = 0;
		
		//Create the connector object that creates and connect the channels.
		connector = new TwoPartySocketConnector(me, other);
	}
	
	/**  
	 * Initiates the creation of the actual sockets connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * @throws TimeoutException in case a timeout has occurred before all channels have been connected.
	 */
	@Override
	public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut) throws TimeoutException {		
		
		//Start the watch dog with the given timeout.
		watchdog = new Watchdog(timeOut);
		//Add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		watchdog.start();
		
		//Establish the connections.
		establishConnections(connectionsIds);
		
		//Verify that all connections have been connected.
		connector.verifyConnectingStatus();
		
		//If we already know that all the connections were established we can stop the watchdog.
		watchdog.stop();
			
		//In case of timeout, throw a TimeoutException
		if (bTimedOut){
			throw new TimeoutException("timeout has occurred");
		}
		
		//Set Nagle algorithm.
		if (enableNagle)
			connector.enableNagle();
		
		//Update the number of the created connections.
		connectionsNumber += connector.getConnectionsCount();
		
		//Return the map of channels held in the established connection object.
		Map<String, Channel> connections = connector.getConnections();
		
		connector.reset();
		
		return connections;
		
	}
	
	@Override
	public Map<String, Channel> prepareForCommunication(int connectionsNum, long timeOut) throws TimeoutException {
		//Prepare the connections Ids using the default implementation, meaning the connections are numbered 
		//according to their index. i.e the first connection's name is "1", the second is "2" and so on.
		String[] names = new String[connectionsNum];
		for (int i=0; i<connectionsNum; i++){
			names[i] = Integer.toString(connectionsNumber++);
		}
		
		//Call the other prepareForCommunication function with the created ids.
		return prepareForCommunication(names, timeOut);
	}

	/**
	 * This function does the actual creation of the communication between the parties.<p>
	 * A connected channel between two parties has two sockets. One is used by P1 to send messages and p2 receives them,
	 * while the other used by P2 to send messages and P1 receives them.
	 * 
	 * The function does the following steps:
	 * 1. Calls the connector.createChannels function that creates a channel for each connection.
	 * 2. Start a listening thread that accepts calls from the other party.
	 * 3. Calls the connector.connect function that calls each channel's connect function in order to connect each channel to the other party.
	 * @param connectionsIds The names of the requested connections. 
	 *
	 */
	private void establishConnections(String[] connectionsIds) {
		
		//Calls the connector to create the channels.
		PlainTCPSocketChannel[] channels = connector.createChannels(connectionsIds, false);
		
		if (!bTimedOut){
			//Create a listening thread with the created channels.
			//The listening thread receives calls from the other party and set the creates sockets as the receiveSocket of the channels.
			createListener(channels);
			listeningThread.start();
		}
		
		//Calls the connector to connect each channel.
		connector.connect(channels);
		
	}

	protected void createListener(PlainTCPSocketChannel[] channels) {
		listeningThread = new SocketListenerThread(channels, me, other.getIpAddress());
	}

	@Override
	public void enableNagle(){
		//Set to true the boolean indicates whether or not to use the Nagle optimization algorithm. 
		//For Cryptographic algorithms is better to have it disabled.
		this.enableNagle  = true;
	}
	
	/**
	 * This function is called by the infrastructure of the Watchdog if the previously set timeout has passed. (Do not call this function).
	 */
	public void timeoutOccured(Watchdog w) {

		Logging.getLogger().log(Level.INFO, "Timeout occured");
		
		//Timeout has passed, set the flag.
		bTimedOut = true;
	
		//Further stop the listening thread if it still runs. Similarly, it sets the flag of the listening thread to stopped.
		if(listeningThread != null)
			listeningThread.stopConnecting();
		
		if(connector != null){
			connector.stopConnecting();
		}
		
		
	}

	/**
	 * This implementation has nothing to close besides the sockets (which are being closed by the channel instances).
	 */
	public void close() {}

}
