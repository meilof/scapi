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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.generals.Logging;

/**
 * A communication setup class that uses the JMS API for sending and receiving messages.<p>
 * This implementation uses the JMS API for sending and receiving messages.
 * 
 * JMS enables distributed communication that is loosely coupled. A component sends a message to a destination, 
 * and the recipient can retrieve the message from the destination. However, the sender and the receiver do not 
 * have to be available at the same time in order to communicate. In fact, the sender does not need to know 
 * anything about the receiver; nor does the receiver need to know anything about the sender. The sender and 
 * the receiver only need to know which message format and which destination to use. In this respect, messaging 
 * differs from tightly coupled technologies, like Remote Method Invocation (RMI), which require an application to 
 * know a remote application’s methods. Moreover, the JMS API knows how to automatically recover from communication 
 * failures; in case a connection falls during the communication, it is automatically reconnected. 
 * In addition, messages cannot get lost in the communication. A queue is therefore a far more robust method of communication.
 * 
 * In SCAPI’s implementation, the server manages two queues between each pair of parties P1 and P2; 
 * one of them is used for P1 to send messages and for P2 to receive them, and the other is used for P2 to send 
 * messages and for P1 to receive them.
 * 
 * This class work on any concrete implementation, by getting the concrete ConnectionFactory in the constructor.
 * Along with the factory, the constructor should accept a concrete instance of DestroyDestinationUtil that
 * deletes the queues created by the connection of the given factory. 
 * For example, if the factory is ActiveMQConnectionFactory than the util instance should be ActiveMQDestroyer.
 * 
 * Note that in JMS the parameters of the connection are given in the uri of the factory. For that reason, after the factory
 * has been created there is no possibility to change the communication parameters. 
 * For example, enableNagle function throws an exception since the enabling/disabling of Nagle's algorithm was already
 * determined in the factory uri.
 * It is up to the user to give the parameters he wants in the factory uri. 
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class QueueCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver{
	private ConnectionFactory connectionFactory;
	private Connection connection;			// The JMS object used to create the producers and consumers.
	private int connectionsNumber;
	private boolean bTimedOut = false; 		//Indicated whether or not to end the communication.
	private Watchdog watchdog;				//Used to measure times.
	QueuePartyData me;						//The data of the current application.
	QueuePartyData other;					//The data of the other application to communicate with.
	DestroyDestinationUtil destroyer;
	
	protected QueueCommunicationSetup(){}
	
	/**
	 * A constructor that set the given parties and start a connection.
	 * @param factory The class used to create the connection. 
	 * We get it from the user in order to be able to work with all types of connections.
	 * @param destroyer The class that delete the created destinations. Should match to the given factory.
	 * @param me The data of the current application.
	 * @param party The data of the other application to communicate with.
	 * @throws DuplicatePartyException 
	 */
	public QueueCommunicationSetup(ConnectionFactory factory, DestroyDestinationUtil destroyer, PartyData me, PartyData party) throws DuplicatePartyException{
		doConstruct(factory, destroyer, me, party); 
		
		
	}

	protected void doConstruct(ConnectionFactory factory, DestroyDestinationUtil destroyer, PartyData me, PartyData party)
			throws DuplicatePartyException {
		//Check that the party is the right object.
		if (!(me instanceof QueuePartyData) && !(party instanceof QueuePartyData)){
			throw new IllegalArgumentException("each party in the list must be an instance of JMSParty");
		}
		this.me = ((QueuePartyData) me);
		this.other = (QueuePartyData) party;
		
		if (this.me.getId() == other.getId()){
			throw new DuplicatePartyException("each party should have a unique Id");
		}
		
		// Create a ConnectionFactory with the given URL, and enable/disable nagle's algorithm (by defining tcpNoDelay) using the given enableNagle.
		//ActiveMQConnectionFactory connectionFactory = new ActiveMQConnectionFactory("failover:tcp://"+url+"?socket.tcpNoDelay="+!enableNagle);
		this.connectionFactory = factory;
		this.destroyer = destroyer;
		
		// Create and start a Connection.
		try {
			connection = connectionFactory.createConnection();
			connection.start();
			
		} catch (JMSException e) {
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
		connectionsNumber = 0;
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
	
	
	@Override
	public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut) throws TimeoutException{
		//Start the watch dog with the given timeout.
		watchdog = new Watchdog(timeOut);
		//Add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		watchdog.start();
				
		//Create a map to hold each created channel.
		Map<String, Channel> connectedChannels = new HashMap<String, Channel>();
		
		//For each connection between the two parties, create a Queue channel.
		int size = connectionsIds.length;
		for (int i=0; i<size && !bTimedOut; i++){
			QueueChannel channel = new QueueChannel(me, other, connection, connectionsIds[i], destroyer);
			//put the created channel in the map.
			connectedChannels.put(connectionsIds[i], channel);	
		}
		
		watchdog.stop();
		
		if (bTimedOut){
			Object[] channels = connectedChannels.values().toArray();
			int len = channels.length;
			for (int i=0; i<len; i++){
				((Channel) channels[i]).close();
			}
			throw new TimeoutException("timeout has occurred");
		}
		
		return connectedChannels;
	}
	
	@Override
	public void close(){
		try {
			//Close the JMS connection.
			connection.close();
		} catch (JMSException e) {
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
	}

	/**
	 * In Queue communication enabling Nagle algorithm can be done in construction time only, when 
	 * creating the factory object used to create the connection.
	 */
	public void enableNagle(){
		throw new ScapiRuntimeException("In Queue communication enabling Nagle algorithm can be done in construction time only");
	}
	
	@Override
	public void timeoutOccured(Watchdog arg0) {
		Logging.getLogger().log(Level.INFO, "Timeout occured");
		
		//Timeout has passed, set the flag.
		bTimedOut = true;
		
		
	}

}
