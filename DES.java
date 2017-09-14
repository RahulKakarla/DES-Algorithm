package project;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class DES {
	static int i=0;
	static int[] rightKey = new int[28];
	static int[] leftKey = new int[28];
	static int[] xor = new int[48];
	static int[] decxor = new int[48];
	int[] newR=new int[32];
	int[] newdecL=new int[32];
	int Right[] = new int[32];
	int Left[] = new int[32];
	int decRight[] = new int[32];
	int decLeft[] = new int[32];
	boolean isDecrypt=false;
	boolean isEncrypt=true;
	int round=0;

	// S-boxes (i.e. Substitution boxes)
	private static final byte[][] S = { {
		14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
		0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
		4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
		15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
	}, {
		15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
		3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
		0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
		13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
	}, {
		10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
		13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
		13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
		1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
	}, {
		7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
		13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
		10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
		3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
	}, {
		2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
		14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
		4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
		11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
	}, {
		12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
		10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
		9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
		4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
	}, {
		4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
		13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
		1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
		6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
	}, {
		13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
		1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
		7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
		2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
	} };


	private static final byte[] initialper = { 
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9,  1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7
	}; 

	private static final byte[] PC1 = {
			57, 49, 41, 33, 25, 17, 9,
			1,  58, 50, 42, 34, 26, 18,
			10, 2,  59, 51, 43, 35, 27,
			19, 11, 3,  60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			7,  62, 54, 46, 38, 30, 22,
			14, 6,  61, 53, 45, 37, 29,
			21, 13, 5,  28, 20, 12, 4
	};

	static final byte[] EBIT = {
			32, 1,  2,  3,  4,  5,
			4,  5,  6,  7,  8,  9,
			8,  9,  10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1
	};

	private static final byte[] PC2 = {
			14, 17, 11, 24, 1,  5,
			3,  28, 15, 6,  21, 10,
			23, 19, 12, 4,  26, 8,
			16, 7,  27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32
	};

	private static final byte[] rotations = {
			1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};

	private static final byte[] P = {
			16, 7,  20, 21,
			29, 12, 28, 17,
			1,  15, 23, 26,
			5,  18, 31, 10,
			2,  8,  24, 14,
			32, 27, 3,  9,
			19, 13, 30, 6,
			22, 11, 4,  25
	};
	private static final byte[] FP = {
			40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25
	};

	private static int[][] storedkey = new int[16][48];
	public int[]  inptobin(String in) {
		int inputBits[] = new int[64];
		int i=0;
		while(i<16) {
			int parseinp = Integer.parseInt(in.charAt(i)+ "", 16);
			String bin = Integer.toBinaryString(parseinp);

			while(bin.length() < 4) {
				bin = "0" + bin;
			}
			for(int j=0 ; j < 4 ; j++) {
				inputBits[(4*i)+j] = Integer.parseInt(bin.charAt(j) + "");
			}
			i++;
		}
		return inputBits;
	}

	public void expand(int[] inputdata, int inputkey[] ) {
		System.out.println("============Encryption============");
		int rawdata[] = new int[inputdata.length];
		//performing initial permutation
		for(int i=0 ; i < inputdata.length ; i++) {
			rawdata[i] = inputdata[initialper[i]-1];
		}
		//creating right part and left part of data
				System.arraycopy(rawdata, 0, Left, 0, 32);
				System.arraycopy(rawdata, 32, Right, 0, 32);
		//converting 64 bit key  to 56 bit 
		for(i=0 ; i < 28 ; i++) {
			leftKey[i] = inputkey[PC1[i]-1];
		}
		for( ; i < 56 ; i++) {
			rightKey[i-28] = inputkey[PC1[i]-1];
		}
		//16 rounds for encryption starts here
		for(round=0 ; round < 16 ; round++) {
			key(Right,round);

		}
	}

	public void key(int input[], int k) {
		int rotationTimes = (int) rotations[k];
		int keyleft[] = new int[28];
		int keyright[] = new int[28];
		int shiftefkey[] = new int[56];
		//copying right part to key
		int keyused[] = new int[leftKey.length];
		System.arraycopy(leftKey, 0, keyused, 0, leftKey.length);
		//shifting keys according to round
		for(int i=0 ; i < rotationTimes ; i++) {
			int temp = keyused[0];
			for(int j=0 ; j < leftKey.length-1 ; j++) {
				keyused[j] = keyused[j+1];
			}
			keyused[leftKey.length-1] = temp;
		}
		keyleft=keyused;
		//copying left part to key
		System.arraycopy(rightKey, 0, keyused, 0, rightKey.length);
		//shifting keys according to rounds
		for(int i=0 ; i < rotationTimes ; i++) {
			int temp = keyused[0];
			for(int j=0 ; j < rightKey.length-1 ; j++) {
				keyused[j] = keyused[j+1];
			}
			keyused[rightKey.length-1] = temp;

		}
		keyright=keyused;
		//copying right and left to same array 
		System.arraycopy(keyleft, 0, shiftefkey, 0, 28);
		System.arraycopy(keyright, 0, shiftefkey, 28, 28);

		//compressing key to 48 bits
		int compressedkey[] = new int[48];
		for(int i=0 ; i < compressedkey.length ; i++) {
			compressedkey[i] = shiftefkey[PC2[i]-1];
		}
		//storing keys 
		storedkey[k] = compressedkey;
		leftKey = keyleft;
		rightKey = keyright;
		xor(input,compressedkey);

	}

	public void xor(int[] expandedrig, int compDbox[] ) {	
		//expanding right 32-bit to 48 bit using E-bit selection table
		int expandedR[] = new int[48];
		for(int i=0 ; i < 48 ; i++) {
			expandedR[i] = expandedrig[EBIT[i]-1];
		}
		//xor with 48-bit key
		for(int i=0 ; i < compDbox.length ; i++) {
			xor[i] = compDbox[i]^expandedR[i];
		}
		sblock(xor);
	}

	public void sblock(int xorbits[]) {
		int output[] = new int[32];
		for(int i=0 ; i < 8 ; i++) {
			int srow[] = new int [2];
			//first bit and last bit of the xor bits which determine the row
			//6 determines the no of input data
			srow[0] = xorbits[6*i];
			srow[1] = xorbits[(6*i)+5];
			String sfullRow = srow[0] + "" + srow[1];
			int scolumn[] = new int[4];
			//middle 4-bits determine the column
			scolumn[0] = xorbits[(6*i)+1];
			scolumn[1] = xorbits[(6*i)+2];
			scolumn[2] = xorbits[(6*i)+3];
			scolumn[3] = xorbits[(6*i)+4];
			String sfullColumn = scolumn[0] +""+ scolumn[1] +""+ scolumn[2] +""+ scolumn[3];
			//parsing the string s -box values to integer
			int iRow = Integer.parseInt(sfullRow, 2);
			int iColumn = Integer.parseInt(sfullColumn, 2);
			int x = S[i][(iRow*16) + iColumn];
			//converting decimal to binary
			String s = Integer.toBinaryString(x);
			while(s.length() < 4) {
				s = "0" + s;
			}
			// The binary bits are appended to the output
			for(int j=0 ; j < 4 ; j++) {
				output[(i*4) + j] = Integer.parseInt(s.charAt(j) + "");
			}
		}
		// P table is applied to the output and this is the final output of one
		// S-box round:
		int finalOutput[] = new int[32];
		for(int i=0 ; i < 32 ; i++) {
			finalOutput[i] = output[P[i]-1];
		}


		newLRbits(finalOutput);

	}

	public void newLRbits(int[] sblockbits) {
		int[] newL=new int[32];
		//performing xor on s-block bits and left bits of input
		for(int i=0 ; i < Left.length ; i++) {
			newL[i] = sblockbits[i]^Left[i];
		}
		//swapping right and left bits
		Left = Right;
		Right = newL;
		System.out.print("Round"+"  "+ round  + "\nL = ");
		for(int i1=0 ; i1 < Left.length ; i1+=4) {
			String output1 = new String();
			for(int j=0 ; j < 4 ; j++) {
				output1 += Left[i1+j];
			}
			System.out.print(Integer.toHexString(Integer.parseInt(output1, 2)));
		}
		System.out.println();
		System.out.print("R = ");
		for(int i1=0 ; i1 < Right.length ; i1+=4) {
			String output1 = new String();
			for(int j=0 ; j < 4 ; j++) {
				output1 += Right[i1+j];
			}
			System.out.print(Integer.toHexString(Integer.parseInt(output1, 2)));
		}
		System.out.println();
		if(round==14){
			newR=Right;

		}
		if(round==15){
			//printing encrypted output
			int encoutput[] = new int[64];
			System.arraycopy(Right, 0, encoutput, 0, 32);
			System.arraycopy(Left, 0, encoutput, 32, 32);
			int encfinalOutput[] = new int[64];
			for(i=0 ; i < 64 ; i++) {
				encfinalOutput[i] = encoutput[FP[i]-1];
			}
			String hex = new String();
			for(i=0 ; i < 16 ; i++) {
				String bin = new String();
				for(int j=0 ; j < 4 ; j++) {
					bin += encfinalOutput[(4*i)+j];
				}
				int decimal = Integer.parseInt(bin, 2);
				hex += Integer.toHexString(decimal);
			}
			System.out.println("encrypted data"+" "+hex.toUpperCase());
			newdecL=Right;
			decrypt(newR,newdecL);
		}
	}
	public void decrypt(int[] decRight,int[] decLeft){
		//http://crypto.stackexchange.com/questions/9674/how-does-des-decryption-work-is-it-the-same-as-encryption-or-the-reverse
		System.out.println(" ");
		System.out.println("==========Decryption==========");
		for(int o=0;o<16;o++){
			int output[] = new int[32];
			int[] newL=new int[32];
			//key from array from last position
			int key[]=storedkey[15-o];
			int expandedR[] = new int[48];
			for(int i=0 ; i < 48 ; i++) {
				expandedR[i] = decRight[EBIT[i]-1];
			}
			for(int i=0 ; i < key.length ; i++) {
				decxor[i] = key[i]^expandedR[i];
			}

			//reversing through s-box
			for(int i=0 ; i < 8 ; i++) {
				int srow[] = new int [2];
				srow[0] = decxor[6*i];
				srow[1] = decxor[(6*i)+5];
				String sfullRow = srow[0] + "" + srow[1];
				int scolumn[] = new int[4];
				scolumn[0] = decxor[(6*i)+1];
				scolumn[1] = decxor[(6*i)+2];
				scolumn[2] = decxor[(6*i)+3];
				scolumn[3] = decxor[(6*i)+4];
				String sfullColumn = scolumn[0] +""+ scolumn[1] +""+ scolumn[2] +""+ scolumn[3];
				int iRow = Integer.parseInt(sfullRow, 2);
				int iColumn = Integer.parseInt(sfullColumn, 2);
				int x = S[i][(iRow*16) + iColumn];
				String s = Integer.toBinaryString(x);
				while(s.length() < 4) {
					s = "0" + s;
				}
				// The binary bits are appended to the output
				for(int j=0 ; j < 4 ; j++) {
					output[(i*4) + j] = Integer.parseInt(s.charAt(j) + "");
				}
			}
			// P table is applied to the output and this is the final output of one
			// S-box round:
			int finalOutput[] = new int[32];
			for(int i=0 ; i < 32 ; i++) {
				finalOutput[i] = output[P[i]-1];
			}

			for(int i=0 ; i < decLeft.length ; i++) {
				newL[i] = finalOutput[i]^decLeft[i];
			}
			//swapping right and left bits
			decLeft = decRight;
			decRight = newL;
			System.out.println("Round"+ " " + o);
			System.out.print("L = ");
			for(int i1=0 ; i1 < decLeft.length ; i1+=4) {
				String output1 = new String();
				for(int j=0 ; j < 4 ; j++) {
					output1 += decLeft[i1+j];
				}
				System.out.print(Integer.toHexString(Integer.parseInt(output1, 2)));
			}
			System.out.println();
			System.out.print("R = ");
			for(int i1=0 ; i1 < decRight.length ; i1+=4) {
				String output1 = new String();
				for(int j=0 ; j < 4 ; j++) {
					output1 += decRight[i1+j];
				}
				System.out.print(Integer.toHexString(Integer.parseInt(output1, 2)));
			}
			System.out.println();

		}

		int decoutput[] = new int[64];
		System.arraycopy(decRight, 0, decoutput, 0, 32);
		System.arraycopy(decLeft, 0, decoutput, 32, 32);
		int decfinalOutput[] = new int[64];
		for(i=0 ; i < 64 ; i++) {
			decfinalOutput[i] = decoutput[FP[i]-1];
		}
		String hex = new String();
		for(i=0 ; i < 16 ; i++) {
			String bin = new String();
			for(int j=0 ; j < 4 ; j++) {
				bin += decfinalOutput[(4*i)+j];
			}
			int decimal = Integer.parseInt(bin, 2);
			hex += Integer.toHexString(decimal);
		}
		System.out.print("Decrypted text: "+" " + hex.toUpperCase());
	}

	public static void  main(String args[]) {
		//reading the input
		System.out.println("enter 16 length charecter string with hexadecimal input [0-9,A-E,a-e] (ABC1457865EFA146)");
		BufferedReader userin = new BufferedReader(new InputStreamReader(System.in));
		String input;
		int inputdata[]= new int[64];
		try {
			input = userin.readLine();
			//calling function to convert to binary
			inputdata = new DES().inptobin(input);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//reading key from input
		System.out.println("enter 16 length charecter  hexadecimal key [0-9,A-E,a-e] (BDE1450265EFA153)");
		BufferedReader userkey = new BufferedReader(new InputStreamReader(System.in));
		String key;
		int inputkey[]= new int[64];
		try {
			key = userkey.readLine();
			//calling function to convert key to binary
			inputkey = new DES().inptobin(key);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		DES des = new DES();
		//calling function to initial permutation
		des.expand(inputdata, inputkey);
	}
}
