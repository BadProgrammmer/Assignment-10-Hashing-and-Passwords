package hash_tables;

/**
 * @author germain
 *
 * some helper methods dealing with prime numbers.  These methods can be "brute force"
 */
public class Primes
{
	

	/**
	 * @param value
	 *            - to check if prime
	 * @return - return true if value is prime
	 */
	public static boolean is_prime( int value )
	{
		for(int i = 2; i <= Math.sqrt(value); i++) {
			if(value % i == 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * next_prime
	 * 
	 * Note: static function
	 * 
	 * @param value
	 *            - the starting point to search for a prime
	 * @return - the value if prime, otherwise the next prime after value
	 */
	public static int next_prime( int value )
	{
		value++;
		while(!is_prime(value)) {
			value++;
		}
		return value;
	}


}
