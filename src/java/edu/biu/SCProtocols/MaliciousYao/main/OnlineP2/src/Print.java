import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;


public class Print {
	public static void main(String[] args) throws IOException {
		FileWriter output = new FileWriter("BWAPartyOneInputs.txt", false);
		for (int i=3145728-1048576;i<3145728; i++){
			output.append(i + "\n");
		}
		output.close();
	}
}
