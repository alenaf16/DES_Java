import java.io.UnsupportedEncodingException;
import java.util.BitSet;
import java.util.Collections;
import java.util.Vector;

public class DES_encrypt{
	
	DES_encrypt(){
		
	}
	//начальная перестановка IP
	int[] IP_Table = new int[]{			
			58,50,42,34,26,18,10,2, 
	        60,52,44,36,28,20,12,4, 
	        62,54,46,38,30,22,14,6, 
	        64,56,48,40,32,24,16,8, 
	        57,49,41,33,25,17,9,1, 
	        59,51,43,35,27,19,11,3, 
	        61,53,45,37,29,21,13,5, 
	        63,55,47,39,31,23,15,7 
	};
	
	//конечная перестановка (IP^(-1))
	int[] reverse_IP_Table = new int[]{		
			40,8,48,16,56,24,64,32, 
		    39,7,47,15,55,23,63,31, 
		    38,6,46,14,54,22,62,30, 
		    37,5,45,13,53,21,61,29, 
		    36,4,44,12,52,20,60,28, 
		    35,3,43,11,51,19,59,27, 
		    34,2,42,10,50,18,58,26, 
		    33,1,41,9,49,17,57,25 
	};
	
	//P-бокс расширения в i-м раунде
	int[] exp_Pbox_Table = new int[]{		
			32,1,2,3,4,5,
			4,5,6,7,8,9,
			8,9,10,11,12,13,
			12,13,14,15,16,17, 
	        16,17,18,19,20,21,
	        20,21,22,23,24,25,
	        24,25,26,27,28,29,
	        28,29,30,31,32,1 
	};
	
 //	Sbox_Table[номер кейса][номер строки][номер столбца]
	int[][][] Sbox_Table = new int [][][]{
		//S1
		{												
			{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
	        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
	        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0}, 
	        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} 
	    }, 
		//S2
	    { 																
	        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10}, 
	        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5}, 
	        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15}, 
	        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} 
	    }, 
	    //S3
	    { 												
	        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8}, 
	        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1}, 
	        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7}, 
	        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} 
	    }, 
	    //S4
	    { 												
	        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15}, 
	        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9}, 
	        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4}, 
	        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} 
	    },
	    //S5
	    { 												
	        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9}, 
	        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6}, 
	        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14}, 
	        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} 
	    }, 
	    //S6
	    { 												
	        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11}, 
	        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8}, 
	        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6}, 
	        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} 
	    }, 
	    //S7
	    { 												
	        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1}, 
	        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6}, 
	        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2}, 
	        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} 
	    }, 
	    //S8
	    { 												
	        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7}, 
	        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2}, 
	        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8}, 
	        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} 
	    }
	};
	
	//прямой P-бокс в i-ом раунде
	int[] straight_Pbox = new int[]{					
			16,7,20,21,29,12,28,17, 
	        1,15,23,26,5,18,31,10, 
	        2,8,24,14,32,27,3,9, 
	        19,13,30,6,22,11,4,25
	};
	
	//удаление битов + перестановка
	int[] parity_Bits_Table = new int[]{				
			57,49,41,33,25,17,9, 						
	        1,58,50,42,34,26,18, 
	        10,2,59,51,43,35,27, 
	        19,11,3,60,52,44,36,           
	        63,55,47,39,31,23,15, 
	        7,62,54,46,38,30,22, 
	        14,6,61,53,45,37,29, 
	        21,13,5,28,20,12,4 
	};
	
	//величины циклических сдвигов влево
	int[] shift_Table = new int[]{						 
			1, 1, 2, 2, 2, 2, 2, 2,  
	        1, 2, 2, 2, 2, 2, 2, 1
	};
	
	//перестановка сжатия ключа
	int[] key_Compr_Table = new int[]{					
			14,17,11,24,1,5,3,28,
			15,6,21,10,23,19,12,4,
			26,8,16,7,27,20,13,2, 
	        41,52,31,37,47,55,30,40,
	        51,45,33,48,44,49,39,56,
	        34,53,46,42,50,36,29,32
	}; 
	
	//циклический сдвиг влево на shifts
	public BitSet shift_Left (BitSet bits, int size, int shifts){ 		
		for(int i = 0; i < shifts; i++){ 
	    	BitSet s = new BitSet(size);
	        for(int j = 1; j < 28; j++){ 
	            s.set(j-1, bits.get(j)); 
	        } 
	        s.set(size - 1, bits.get(0)); 
	        bits = s;  
	    } 
	    return bits; 
	} 
	
	//перестановка по таблице
	public BitSet permutation(BitSet bits, int[] arr, int n){			
	    BitSet per = new BitSet(); 
	    for(int i=0; i<n ; i++){ 
	        per.set(i, bits.get(arr[i]-1)); 
	    } 
	    return per; 
	} 
	
	//перевод из двоичной системы в десятичную
	public int binToDec(BitSet bs){
		int temp = 0;

	      for (int j = 0; j < bs.length(); j++)
	        if (bs.get(j))
	          temp |= 1 << j;
	      return temp;
	}
	
	//перевод из десятичной системы в двоичную
	public BitSet decToBin(int numb){
		BitSet gs = BitSet.valueOf(new long[]{numb});
    	return gs;
	}
	
	//генерация ключей
	Vector<BitSet> key_Generation(BitSet key) throws UnsupportedEncodingException{
		
		key = permutation(key, parity_Bits_Table, 56);
		
		BitSet left_Key = new BitSet();
		for (int i = 0; i < 28; i++){
			left_Key.set(i, key.get(i));
		}
		
		BitSet right_Key = new BitSet();
		for (int i = 28; i < 56; i++){
			right_Key.set(Math.abs(28 - i), key.get(i));
		}
		
		Vector<BitSet> round_Keys = new Vector<BitSet>();
		
		for(int i=0; i<16; i++){
			left_Key = shift_Left(left_Key, 28, shift_Table[i]); 
	        right_Key = shift_Left(right_Key, 28, shift_Table[i]);
	        
	        BitSet combine = new BitSet();
	        
	        for (int k = 0; k < 28; k++){
	        	combine.set(k, left_Key.get(k));
	        }
	       
	        for (int j = 28; j < 56; j++){
	        	combine.set(j, right_Key.get(Math.abs(28 - j)));
	        }
	        
	        BitSet r_Key = permutation(combine, key_Compr_Table, 48);
	        
	        round_Keys.add(r_Key);
		}
		
		return round_Keys;
	}

	//шифрование блока данных
	BitSet encrypt_data (BitSet plain_Text, Vector<BitSet> round_Keys){
	
		plain_Text = permutation(plain_Text, IP_Table, 64);
		
		BitSet left = new BitSet();
		for (int i = 0; i < 32; i++){
			left.set(i, plain_Text.get(i));
		}
		BitSet right = new BitSet();
		for (int i = 32; i < 64; i++){
			right.set(Math.abs(32 - i), plain_Text.get(i));
		}
		
		//16 раундов
		for(int j=0; j<16; j++){
			BitSet right_Expanded= permutation(right, exp_Pbox_Table, 48);
			
			BitSet xor_Result = (BitSet)right_Expanded.clone();
			
			xor_Result.xor(round_Keys.get(j));
			
			BitSet op = new BitSet();
			
			// 8 S-кейсов
			for(int i = 0; i < 8; i++){  

				//6-битовые части
				BitSet part = new BitSet();
				for (int k = 0; k < 6; k++){
					part.set(k, xor_Result.get(6*i + k));
				}
				BitSet two_bits = new BitSet();
				two_bits.set(0, part.get(0));
				two_bits.set(1, part.get(5));
				
				//номер строки S-бокса
				int strOfBox = binToDec(two_bits);
				
				BitSet four_bits = new BitSet();
				for (int k = 1; k < 5; k++){
					four_bits.set(k - 1, part.get(k));
				}
				//номер столбца S-бокса
				int colOfBox = binToDec(four_bits);
				
				//шифрообозначение 6-битовой части в S-боксе(десятичное)
				int valueDec = Sbox_Table[i][strOfBox][colOfBox];
				
				//шифрообозначение 6-битовой части в S-боксе(двоичное)
				BitSet valueBin = decToBin(valueDec);
				
				for (int k = 0; k < 4; k++){
					op.set(4*i + k, valueBin.get(k));
				}
	        } 
			
			op = permutation(op, straight_Pbox, 32);
			
			left.xor(op);
			
			if(j != 15){ 
	            BitSet tmp = left;
	            left = right;
	            right = tmp;
	        } 
			
		}
		BitSet comb = (BitSet)left.clone();
		for (int j = 32; j < 64; j++){
        	comb.set(j, right.get(Math.abs(32 - j)));
        }
		
		BitSet cipher= permutation(comb, reverse_IP_Table, 64); 
	    return cipher;
	}
	
	//расшифрование данных
	BitSet decrypt_data (BitSet cipher_Text, Vector<BitSet> round_Keys){
		Vector<BitSet> reverse_Keys = new Vector<BitSet>();
		reverse_Keys = round_Keys;
		Collections.reverse (reverse_Keys);
		BitSet plain_Text = encrypt_data(cipher_Text, reverse_Keys);
		return plain_Text;
	}
	
	//вывод 
	public void print_BitSet (BitSet bs) throws UnsupportedEncodingException {
		byte[] byte_mas = bs.toByteArray();
		String str = new String (byte_mas, "UTF-8");
		System.out.println(str);
	}
}