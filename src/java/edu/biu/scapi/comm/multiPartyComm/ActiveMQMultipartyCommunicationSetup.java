package edu.biu.scapi.comm.multiPartyComm;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.ActiveMQCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.TwoPartyCommunicationSetup;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.exceptions.ScapiRuntimeException;

/**
 * This class implements the multiparty communication uses the ActiveMQ implementation of JMS.<p>
 * This implementation creates a Two Party communication between the current application and any other party in the protocol.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ActiveMQMultipartyCommunicationSetup implements MultipartyCommunicationSetup{
	//A map that contains a TwoParty communication between the current application and any other party in the protocol. 
	//The key to the map is the party that needs to be connected and the value is the two-party communication object.
	protected Map<PartyData, TwoPartyCommunicationSetup> twoPartyCommunications;
	
	protected ActiveMQMultipartyCommunicationSetup(){}
	
	/**
	 * A constructor that create an {@link ActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties  List of parties to communicate with. The first party in the list represents the current application.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 */
	public ActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties) throws DuplicatePartyException{
		//Call the other constructor with Nagle's algorithm disabled.
		this(url, parties, false);
	}
	
	/**
	 * A constructor that create an {@link ActiveMQCommunicationSetup} object between the current application and any other party in the protocol.
	 * @param url The url of the ActiveMQ broker.
	 * @param parties  List of parties to communicate with. The first party in the list represents the current application.
	 * @param enableNagle Indicates if to use Nagle's algorithm or not. For cryptographic algorithms it is much better to disable Nagle's algorithm.
	 * @throws DuplicatePartyException In case there are two identical parties.
	 */
	public ActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, boolean enableNagle) throws DuplicatePartyException{
		int size = parties.size() - 1;
		//Prepare the map to hold the TwoPartyCommunicationSetup objects.
		twoPartyCommunications = new HashMap<PartyData, TwoPartyCommunicationSetup>();
		
		//For each party in the list except me, create an ActiveMQCommunicationSetup instance.
		for (int i=1; i<=size; i++){
			twoPartyCommunications.put(parties.get(i), new ActiveMQCommunicationSetup(url, parties.get(0), parties.get(i), enableNagle));
		}
	}
	
	@Override
	public Map<PartyData, Map<String, Channel>> prepareForCommunication(Map<PartyData, Object> connectionsPerParty, long timeOut) throws TimeoutException{
		//Prepare a map to hold the created channels of every party.
		Map<PartyData, Map<String, Channel>> createdChannels = new HashMap<PartyData, Map<String, Channel>>();
		
		Iterator<PartyData> keys = twoPartyCommunications.keySet().iterator();
		
		Map<String, Channel> partyChannels;
		
		//Get the TwoPartyCommunicationSetup of each party and call each prepareforCommunication function.
		while (keys.hasNext()){
			//Get the next party.
			PartyData key = keys.next();
			
			//get the TwoPartyCommunication object between me and the party.
			TwoPartyCommunicationSetup commSetup = twoPartyCommunications.get(key);
			
			//In case the user gave the names of the requested channels, call the prepareForCommunication(connectionsNames, timeOut).
			if (connectionsPerParty.values().toArray()[0] instanceof String[]){
				
				String[] connectionsNames = (String[]) connectionsPerParty.get(key);
				partyChannels = commSetup.prepareForCommunication(connectionsNames, timeOut);
			
			//In case the user gave the number of the requested channels, call the prepareForCommunication(connectionsNum, timeOut).
			} else{
				
				int connectionsNum = (Integer) connectionsPerParty.get(key);
				partyChannels = commSetup.prepareForCommunication(connectionsNum, timeOut);
				
			}
			//Put the connected channels in the map.
			createdChannels.put(key, partyChannels);
		}
		
		return createdChannels;
	}
	
	/**
	 * In Queue communication enabling Nagle algorithm can be done in construction time only, when 
	 * creating the factory object used to create the connection.
	 */
	public void enableNagle(){
		throw new ScapiRuntimeException("In Queue communication enabling Nagle algorithm can be done in construction time only");
	}
	
	/**
	 * Close every {@link TwoPartyCommunicationSetup} object.
	 */
	public void close(){
		Iterator<PartyData> keys = twoPartyCommunications.keySet().iterator();
		
		//Get each TwoPartyCommunicationSetup object and close it.
		while (keys.hasNext()){
			PartyData key = keys.next();
			twoPartyCommunications.get(key).close();
		}
	}
	
}
