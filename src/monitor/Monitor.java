package monitor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import ca.uqac.lif.cep.Connector;
import ca.uqac.lif.cep.Pullable;
import ca.uqac.lif.cep.Pullable.NextStatus;
import ca.uqac.lif.cep.UtilityMethods;
import ca.uqac.lif.cep.fsm.FunctionTransition;
import ca.uqac.lif.cep.fsm.MooreMachine;
import ca.uqac.lif.cep.functions.ApplyFunction;
import ca.uqac.lif.cep.functions.Constant;
import ca.uqac.lif.cep.functions.FunctionTree;
import ca.uqac.lif.cep.functions.StreamVariable;
import ca.uqac.lif.cep.tmf.QueueSource;
import ca.uqac.lif.cep.util.Equals;
import ca.uqac.lif.cep.util.NthElement;
import ca.uqac.lif.cep.util.Strings.SplitString;

public class Monitor {

	public static void main(String[] args) {
		String s = System.getProperty("user.dir") + "/logs"; // getting path to logs folder
		QueueSource queue = new QueueSource().loop(false);
		int count = 0;
		try { // attempting to open logs file
			BufferedReader rdr = new BufferedReader(new FileReader(s + "/nonmal_no_obf_filtered.txt")); // create bufferedreader to read each line
			String line = rdr.readLine();
			while (line != null){ // while not eof
				queue.addEvent(line); // add line as event to queuesource.
				line = rdr.readLine();
				count++;
			}
			System.out.println("[*] Done reading in logs file");
			rdr.close();
			
		} catch (IOException e) {
			System.out.println("[!] Could not locate or open logs file!");
			e.printStackTrace();
		}
		 
			
		System.out.println("[*] Setting up stream processing components..");
		NthElement elem = new NthElement(3); // get the 4th element, the key defined by auditd
		SplitString splt = new SplitString(" "); // break line on space character
		FunctionTree tree = new FunctionTree(elem, splt); // split, then get 4th element
		ApplyFunction getKey = new ApplyFunction(tree); // applying function tree
		
		MooreMachine moore = new MooreMachine(1,1); // moore machine setup
		final int q1 = 0, q3 = 1, q4 = 2, q0 = 3, q2 = 4; // naming the states
		moore.addTransition(q1, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("read_event")), q1)); // q1 ->[read] q1
		moore.addTransition(q1, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("write_event")), q1)); // q1 ->[write] q1
		moore.addTransition(q1, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("socket_event")), q1)); // q1 ->[socket] q1
		moore.addTransition(q1, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("persistence_event")), q3)); // q1 ->[persistence] q3
		moore.addTransition(q3, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("write_event")), q1)); // q3 ->[write] q1
		moore.addTransition(q3, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("read_event")), q1)); // q3 ->[read] q1
		moore.addTransition(q3, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("persistence_event")), q3)); // q3 ->[persistence] q3
		moore.addTransition(q3, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("socket_event")), q4)); // q3 -> [socket] q4
		moore.addTransition(q4, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("write_event")), q1)); // q4 ->[write] q1
		moore.addTransition(q4, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("persistence_event")), q3)); // q4 ->[persistence] q3
		moore.addTransition(q4, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("socket_event")), q1)); // q4 ->[socket] q1
		moore.addTransition(q4, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("read_event")), q0)); // q4 ->[read] q0
		moore.addTransition(q0, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("persistence_event")), q3)); // q0 ->[persistence] q3
		moore.addTransition(q0, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("write_event")), q2)); // q0 ->[write] q2
		moore.addTransition(q0, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("socket_event")), q1)); // q0 ->[socket] q1
		moore.addTransition(q0, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant("read_event")), q1)); // q0 ->[read] q1
		moore.addTransition(q2, new FunctionTransition(
				new FunctionTree(Equals.instance,
						StreamVariable.X, new Constant(true)), q2)); // q2 ->[*] q2 (sink state)
		
		// choosing what to emit at each state
		moore.addSymbol(q1, new Constant("Monitor State: q1, Verdict: OK"));
		moore.addSymbol(q3, new Constant("Monitor State: q3, Verdict: OK"));
		moore.addSymbol(q4, new Constant("Monitor State: q4, Verdict: OK"));
		moore.addSymbol(q0, new Constant("Monitor State: q0, Verdict: Dangerous"));
		moore.addSymbol(q2, new Constant("Monitor State: q2, Verdict: Malicious Trace Detected!"));
	
		// connecting and pulling the machine output
		Connector.connect(queue, getKey, moore);
		moore.start();
		System.out.println("[*] Stream processing components setup complete");
		
		System.out.println("[*] Evaluating monitor results: ");
		Pullable verdict = moore.getPullableOutput();
		for (int i = 0; i < count+1; i++) {
			Object vrd = verdict.pullSoft();
			if (vrd != null) {
				System.out.println("[*] Monitor Output: " + vrd);
			}
		}
		
		System.out.println("[*] Monitor Finished ");
	}
		
		
}

