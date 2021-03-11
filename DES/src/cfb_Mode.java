import java.io.File;
import java.io.IOException;
import java.util.BitSet;
import java.io.RandomAccessFile;
import java.security.SecureRandom;//для генерации вектора IV

public class cfb_Mode {
	
	//шифрование файла в режиме CFB
	public void CFB_Encrypt(File fIn, BitSet key_bits) throws IOException{
		DES_encrypt en = new DES_encrypt();
		
		if (!fIn.exists()){
			System.out.println ("File not found!");
		}
		
		RandomAccessFile rafIn = new RandomAccessFile(fIn, "rw");
		
		if (rafIn.length()%2 != 0){
			rafIn.setLength(rafIn.length() + 1);
		}
		//генерация случайной синхропосылки
				SecureRandom rand = new SecureRandom();
				byte[] iv_Bytes = new byte[8];
				rand.nextBytes(iv_Bytes);
				BitSet IV = BitSet.valueOf(iv_Bytes);
				System.out.print("Initialization Vector: ");
				en.print_BitSet(IV);
				
		BitSet shift_Register = new BitSet(64);
		shift_Register = IV;
	
		System.out.println("RAF LENGTH " + rafIn.length() + "\n");
		
		while (rafIn.getFilePointer() < rafIn.length() - 1){
			
			//блок, содержащий результат применения encrypt_data
			BitSet encr_Result = new BitSet(64);
			encr_Result = en.encrypt_data (shift_Register, en.key_Generation(key_bits));
			
			BitSet left_Part = new BitSet(16);
			for (int i = 0; i < 16; i++){
				left_Part.set(i, encr_Result.get(i));
			}
			
			//блок открытого текста 
			byte[] plain_Part = new byte[2];
			
			rafIn.readFully(plain_Part);
		
			BitSet plain_Bits = new BitSet(16);
			plain_Bits = BitSet.valueOf(plain_Part);
			
			//блок зашифрованного текста
			BitSet cipher_Part = new BitSet(16);
			
			for (int i = 0; i < 16; i++){
				cipher_Part.set(i, plain_Bits.get(i));
			}
			
			//в cipher_Part результат xor
			cipher_Part.xor(left_Part);
			
			byte[] cipher_Bytes = cipher_Part.toByteArray();
			
			rafIn.seek(rafIn.getFilePointer() - 2);
			rafIn.write(cipher_Bytes);
		
			//сдвигаем влево регистр сдвигов на размер зашифрованного блока
			shift_Register = en.shift_Left(shift_Register, 64, 16);
				 
			//добавляем в конец регистра сдвигов зашифрованный блок
			for (int i = 48; i < 64; i++){
				shift_Register.set(i, cipher_Part.get(Math.abs(48 - i)));
			}
		}
		
		//запись вектора IV в конец файла
		rafIn.write(iv_Bytes);
		
		System.out.println("Encryption completed. \n");
		rafIn.close();
	}
	
	//расшифрование файла в режиме
	public void CFB_Decrypt(File fIn, BitSet key_bits) throws IOException{
			DES_encrypt en = new DES_encrypt();
		
			if (!fIn.exists()){
				System.out.println ("File not found!");
			}
			RandomAccessFile rafIn = new RandomAccessFile(fIn, "rw");
			
			if (rafIn.length()%2 != 0){
				rafIn.setLength(rafIn.length() + 1);
			}
		
			//считывание вектора IV c конца файла
			rafIn.seek(rafIn.length() - 8);
			byte[] iv_Bytes = new byte[8];
			rafIn.readFully(iv_Bytes);
			BitSet IV = BitSet.valueOf(iv_Bytes);
			//возвращение указателя в начало
			rafIn.seek(0);
			
			BitSet shift_Register = new BitSet(64);
			shift_Register = IV;
			
			while (rafIn.getFilePointer() < rafIn.length() - 9){
				
				byte[] cipher_Part = new byte[2];
				
				rafIn.readFully(cipher_Part);
			
				BitSet cipher_Bits = new BitSet(16);
				cipher_Bits = BitSet.valueOf(cipher_Part);
				
				BitSet encr_Result = new BitSet(64);
				encr_Result = en.encrypt_data (shift_Register, en.key_Generation(key_bits));
			
				BitSet left_Part = new BitSet(16);
				for (int i = 0; i < 16; i++){
					left_Part.set(i, encr_Result.get(i));
				}
				
				BitSet plain_Bits = new BitSet(16);
				
				for (int i = 0; i < 16; i++){
					plain_Bits.set(i, cipher_Bits.get(i));
				}
				
				plain_Bits.xor(left_Part);
				
				byte[] plain_Bytes = plain_Bits.toByteArray();
				
				rafIn.seek(rafIn.getFilePointer()-2);
				rafIn.write(plain_Bytes);
				
				shift_Register = en.shift_Left(shift_Register, 64, 16);
				
				//добавляем в конец регистра сдвигов считанный блок
				for(int i = 48; i < 64; i++){
				shift_Register.set(i, cipher_Bits.get(Math.abs(48 - i)));
				}
			}
			System.out.println("\nDecryption completed. \n");
			rafIn.close();
	}
	
	public static void main(String[] args) throws IOException {
		
		cfb_Mode cfb = new cfb_Mode();
		
		String file_Path = args[0];
		String key_str = args[1];
		
		//действие (encrypt/derypt)
		String action = args[2];
		
		BitSet key_bits = new BitSet(64);
		key_bits = BitSet.valueOf(key_str.getBytes());
		
		File fPlain = new File (file_Path);

		if (action.equals("encrypt")) cfb.CFB_Encrypt (fPlain, key_bits);
		else if (action.equals("decrypt")) cfb.CFB_Decrypt (fPlain,  key_bits);
		else System.out.println("Action error!");
	}
}
