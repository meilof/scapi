package edu.biu.scapi.circuits.fastGarbledCircuit;

/**
 * A class that hold the values used to create the circuit. <p>
 * These values are:<P>
 * 1. Both keys of the input and the output wires.<p>
 * 2. The translation table of the circuit.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class FastCircuitCreationValues {
	private byte[] allInputWireValues;
	private byte[] allOutputWireValues;
	private byte[] translationTable;
	
	/**
	 * Sets the given arguments.
	 * @param allInputWireValues Both keys for all input wires.
	 * @param allOutputWireValues Both keys for all output wires.
	 * @param translationTable Signal bits of all output wires.
	 */
	public FastCircuitCreationValues(byte[] allInputWireValues, byte[] allOutputWireValues, byte[] translationTable) {
		this.allInputWireValues = allInputWireValues;
		this.allOutputWireValues = allOutputWireValues;
		this.translationTable = translationTable;
	}

	public byte[] getAllInputWireValues() {
		return allInputWireValues;
	}
	
	public byte[] getAllOutputWireValues() {
		return allOutputWireValues;
	}

	public byte[] getTranslationTable() {
		return translationTable;
	}
}
