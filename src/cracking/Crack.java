package cracking;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Crack {
	static boolean I_DID_NOT_STUDY_ALGORITHMS = true;
	private Collection<String> hashes;
	
	static public ArrayList<String> read_file_into_array(String file_name) {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file_name));
			ArrayList<String> hashes = new ArrayList<>();
			
			while(reader.ready()) {
				hashes.add(reader.readLine());
			}
			reader.close();
			
			return hashes;
		
		} catch(FileNotFoundException e) {
			return null;
		} catch(IOException e) {
			return null;
		}
	}

	static public HashSet<String> read_file_into_hash_set(String file_name) {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file_name));
			HashSet<String> hashes = new HashSet<>();
			
			while(reader.ready()) {
				hashes.add(reader.readLine());
			}
			reader.close();
			
			return hashes;
		
		} catch(FileNotFoundException e) {
			return null;
		} catch(IOException e) {
			return null;
		}
	}
	
	{
		if(I_DID_NOT_STUDY_ALGORITHMS) {
			hashes = read_file_into_array("Resources/hashwords_long");
		} else {
			hashes = read_file_into_hash_set("Resources/hashwords_long");
		}
	
		ArrayList<ArrayList<String>> passwordsBruteForce = multi_thread_brute_force_attack(4, hashes);
	
		ArrayList<String> passwordsDictionary = 
				dictionary_attack(read_file_into_array("Resources/common_passwords_cain"), hashes);
		// also do this for your dictionary_attack
	}
	
	static public String hashWord(String word) {
		try {
		MessageDigest hash_generator = java.security.MessageDigest.getInstance("MD5");

		// build MD5 hash of a permutation
		hash_generator.update(word.getBytes());
		byte[] digest = hash_generator.digest();

		StringBuffer hashword_hex_code = new StringBuffer();
		for (byte b : digest)
		{
	 	   hashword_hex_code.append(String.format("%02x", b & 0xff));
		}
		return hashword_hex_code.toString();  
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	        // use hashword_hex_code to compare to already encrypted/hashed words
	}

	/**
     * 
     * This method compares (hashes of) all permutations of up to "Max_Length" characters vs
     * the given list of hashes (the password file)
     * 
     * @param hashes
     *            - hashes that you are seeing if you can find matches to
     * @param max_length
     *            - how many characters the passwords can be (in length)
     * @return the list of found passwords and their corresponding md5 hashes (e.g., [ "cat :
     *         d077f244def8a70e5ea758bd8352fcd8AB3293292CEF2342ACD32342" ])
     */
    public static ArrayList<String> brute_force_attack( Collection<String> hashes, int max_length ) {
    	ArrayList<String> successes = new ArrayList<>();
    	StringBuilder passwordTry = new StringBuilder();
    	brute_force_attack(hashes, successes, passwordTry, 0, max_length);
    	return successes;
    }

    // recommended but not required recursive helper
	static public void brute_force_attack(
                            Collection<String> hashes, ArrayList<String> successes, StringBuilder so_far,
                            int depth, int max_length ) {
		/*
		 * for every letter try at this depth
		 * 		Hash the word
		 * 		Check against our hashes
		 */
		for(int characterNum = 48; characterNum <= 122; characterNum++) {
			if(characterNum == 58) {
				characterNum = 97;
			}
			char character = (char)characterNum;
			
			//Delete to just before the character we want to try
			so_far.setLength(depth);
			so_far.append(character);
			
			String hashedPermutation = hashWord(so_far.toString());
			for(String hash : hashes) {
				if(hash.equals(hashedPermutation)) {
					successes.add(so_far.toString() + " : " + hash);
				}
			}
			
			if(depth < max_length) {
	    		//Recurse
	    		brute_force_attack(hashes, successes, so_far, depth + 1, max_length);
	    	}
		}
		
    }

	/**
     * compare all words in the given list (dictionary) to the password collection we wish to crack
     *
     * @param dictionary
     *            - The list of likely passwords
     * @param hashes
     *            - Collection of the hashwords we are trying to break
     * @return the list of found passwords and their corresponding md5 hashes (e.g., "cat :
     *         d077f244def8a70e5ea758bd8352fcd8AB3293292CEF2342ACD32342")
     */
    static public ArrayList<String> dictionary_attack( ArrayList<String> dictionary, Collection<String> hashes ) {
    	ArrayList<String> passwords = new ArrayList<>();
    	for(String word : dictionary) {
    		
    		String hashedWord = hashWord(word);
    		
    		for(String hash : hashes) {
    			if(hash.equals(hashedWord)) {
    				passwords.add(word + " : " + hash);
    			}
    		}
    	}
    	return passwords;
    }

	/**
	 * Begin a brute for attack on the password hashfile
	 * 
	 * Use up to 8 threads
	 * 
	 * compute all permutations of strings and compare them to a list of already
	 * hashed passwords to see if there is a match
	 * 
	 * @param max_permutation_length
	 *            - how long of passwords to attempt (suggest 6 or less)
	 * @return a list of successfully cracked passwords
	 */
	public static ArrayList<ArrayList<String>> multi_thread_brute_force_attack(int max_permutation_length,
			Collection<String> hashes) {
		long start_time = System.nanoTime();
		System.out.println("starting computation");

		ArrayList<Thread> threads = new ArrayList<>();

		int count = 0;
		int AVAILABLE_THREADS = 8;

		ExecutorService thread_pool = Executors.newFixedThreadPool(AVAILABLE_THREADS);
		ArrayList<ArrayList<String>> successes = new ArrayList<ArrayList<String>>();

		for (int i = 0; i < 26; i++) {
			successes.add(new ArrayList<>());
		}

		for (int i = 0; i < 26; i++) {
			int temp = i;

			thread_pool.execute(new Runnable() {

				@Override
				public void run() {
					System.out.println("working on permutation " + temp);
					brute_force_attack(hashes, successes.get(temp), new StringBuilder("" + (char) ('a' + temp + 1)), 1,
							max_permutation_length);
				}
			});
			
		}

		try {
			thread_pool.shutdown();
			thread_pool.awaitTermination(1, TimeUnit.DAYS);
		} catch (Exception e) {
			e.printStackTrace();
		}

		long total_time = System.nanoTime() - start_time;
		System.out.println("done: ( " + (total_time / 1000000000.0) + " seconds )");

		return null;

	}

}
