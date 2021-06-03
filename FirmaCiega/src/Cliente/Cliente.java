package Cliente;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Hashtable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.util.Scanner;

public class Cliente {
	
	public static void main(String[] args) {
		
		//Creamos y inicializamos las variables necesarias
		final String host = "localhost";
		final int port = 8080;
		final int N;
		DataInputStream in;
		DataOutputStream out;
		SecureRandom random = new SecureRandom();
		String rutaFichero1 = "fichero1.txt";
		String rutaFichero2 = "fichero2.txt";
		boolean engano = false;
		HashMap<Integer, byte[]> tablaDocumentosEncriptados = new HashMap<Integer, byte[]>();
		HashMap<Integer, byte[]> tablaDocumentos = new HashMap<Integer, byte[]>();
		
		
		try {
			
			//Iniciamos la conexion
			Socket socket = new Socket(host, port);
			in = new DataInputStream(socket.getInputStream());
			out = new DataOutputStream(socket.getOutputStream());
			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1PAdding");

			//Generacion par de claves
			KeyPair kpa = generarClaves(random);
			PublicKey pubKey = kpa.getPublic();
			PrivateKey privKey = kpa.getPrivate();
			rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
			
			//Implementacion cliente Firma Ciega
			byte[] documento;
			byte[] documentoAleatorio;
			byte[] factorDeOpacidad;
			int tamano;
			int aleatorio;
			Scanner teclado = new Scanner(System.in);
			int opcion = -1;
			
			//Recibiendo el numero de documentos a enviar (lo determina el servidor)
			N = in.readInt();
			
			int[] vectorAleatorios = new int[N];
			while(opcion != 0 && opcion != 1) {
				System.out.println("---------------------------------------");
				System.out.println("Protocolo de firma ciega");
				System.out.println("---------------------------------------");
				System.out.println("Opcion 0 --> Intentar engañar al servidor.");
				System.out.println("Opcion 1 --> No intentar engañar al servidor.");
				System.out.println("Inserte opcion (0-1): ");
				opcion = teclado.nextInt();
				if (opcion == 0) {
					engano = true;
				}else if(opcion == 1) {
					engano = false;
				} else {
					System.out.println("Opcion no valida.");
				}
			}
			
			//Enviando N veces el mismo archivo
			if (!engano) {			
				documento = Files.readAllBytes(Paths.get(rutaFichero1));
				for (int i = 0; i < N; i++) {	
					aleatorio = random.nextInt(200);
					vectorAleatorios[i] = aleatorio;
					documentoAleatorio = String.format(documento + ";" + aleatorio).getBytes();
					tablaDocumentos.put(aleatorio, documentoAleatorio);
					factorDeOpacidad = rsaCipher.doFinal(documentoAleatorio);
					tablaDocumentosEncriptados.put(aleatorio, factorDeOpacidad);
					tamano = factorDeOpacidad.length;
					out.writeInt(tamano);
					out.write(factorDeOpacidad);
				}
			//Enviando 1 archivo diferente y N-1 veces el mismo archivo
			}else {
				documento = Files.readAllBytes(Paths.get(rutaFichero2));
				aleatorio = random.nextInt(200);
				vectorAleatorios[0] = aleatorio;
				documentoAleatorio = String.format(documento + ";" + aleatorio).getBytes();
				tablaDocumentos.put(aleatorio, documentoAleatorio);
				factorDeOpacidad = rsaCipher.doFinal(documentoAleatorio);
				tablaDocumentosEncriptados.put(aleatorio, factorDeOpacidad);
				tamano = factorDeOpacidad.length;
				out.writeInt(tamano);
				out.write(factorDeOpacidad);
				documento = Files.readAllBytes(Paths.get(rutaFichero1));
				for (int i = 1; i < N; i++) {
					aleatorio = random.nextInt(200);
					vectorAleatorios[i] = aleatorio;
					documentoAleatorio = String.format(documento + ";" + aleatorio).getBytes();
					tablaDocumentos.put(aleatorio, documentoAleatorio);
					factorDeOpacidad = rsaCipher.doFinal(documentoAleatorio);
					tablaDocumentosEncriptados.put(aleatorio, factorDeOpacidad);
					tamano = factorDeOpacidad.length;
					out.writeInt(tamano);
					out.write(factorDeOpacidad);
				}
			}
			
			
			//Recibiendo del firmante el indice del documento a firmar y enviando N-1 documentos (todos menos el que tiene el indice)
			int indice = in.readInt();
			for (int j = 0; j < N; j++) {
				
				if (j != indice) {
					tamano = tablaDocumentos.get(vectorAleatorios[j]).length;
					out.writeInt(tamano);
					out.write(tablaDocumentos.get(vectorAleatorios[j]));
				}
			}
			
			//Leyendo la firma y la llave publica del firmante
			String rutaFirmaServidor = in.readUTF();
			byte[] firma = Files.readAllBytes(Paths.get(rutaFirmaServidor));
			String rutaLlavePublica = in.readUTF();
			byte[] keyBytes = Files.readAllBytes(Paths.get(rutaLlavePublica));
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			try {
				PublicKey llavePublica = kf.generatePublic(spec);
				
				//Validando la firma recibida del firmante
				if(validarFirma(firma, llavePublica, tablaDocumentosEncriptados.get(vectorAleatorios[indice])))
					System.out.println("Firma correcta");
				else
					System.out.println("Firma incorrecta");
				
			} catch (InvalidKeySpecException | SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			//Cerrando la conexion
			socket.close();
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Estas intentando engañar al servidor.");
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static KeyPair generarClaves(SecureRandom random) {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024, random);
			KeyPair kpa = kpg.genKeyPair();
			return kpa;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;		
	}
	public static boolean validarFirma(byte[] firma, PublicKey LlavePublica, byte[] documento) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException{
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(LlavePublica);
		signature.update(documento);
		return signature.verify(firma);
		
	}


}
