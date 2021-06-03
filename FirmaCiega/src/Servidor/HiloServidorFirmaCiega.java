package Servidor;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

public class HiloServidorFirmaCiega implements Runnable {
	//Creamos y inicializamos las variables necesarias
	Socket socket;
	DataInputStream in;
	DataOutputStream out;
	final int N = 10;
	String rutaLlavePublica = "LlavePublicaServidor";
	String rutaFirmaServidor = "FirmaServidor";
	HashMap<Integer, byte[]> documentosEncriptados = new HashMap<Integer, byte[]>();
	HashMap<Integer, String> documentos = new HashMap<Integer, String>();
	SecureRandom random = new SecureRandom();

	public HiloServidorFirmaCiega(Socket s) {
		this.socket = s;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
		try {			
			in = new DataInputStream(socket.getInputStream());
			out = new DataOutputStream(socket.getOutputStream());
			
			//Solicitando N documentos al cliente
			out.writeInt(N);
			
			//Recibiendo los N documentos del cliente
			for (int i = 0; i < N; i++) {
				int tamano = in.readInt();
				byte[] documento = in.readNBytes(tamano);
				documentosEncriptados.put(i, documento);
			}
			
			//Eleccion del indice
			int indice = (int)(Math.random()*N);
			out.writeInt(indice);
			
			//Recibiendo N-1 documentos (todos menos el que tiene el indice)
			for (int j = 0; j < N-1; j++) {
				int tamano = in.readInt();
				byte[] documentoBytes = in.readNBytes(tamano);
				String str = new String(documentoBytes);
				documentos.put(j, str);
			}

			
			
			//Comprobacion de documentos
			String[] datos = documentos.get(0).split(";");
			String documento = datos[0];
			try {
				for (int i=1 ; i<N-1; i++) {
					String[] aux = documentos.get(i).split(";");
					String documentoComparar = aux[0];
					if(!documento.equals(documentoComparar)) {
						throw new EnganoServidorException();
					}
				}
				
				//Generando las claves del Servidor
				KeyPair kpa = generarClaves(random);
				PublicKey pubKey = kpa.getPublic();
				PrivateKey privKey = kpa.getPrivate();
				
				//Firmando el documento
				byte[] firma = firmarDocumento(privKey, documentosEncriptados.get(indice));
				
				//Guardando la firma en un fichero y enviandole la ruta al cliente
				escribirFicheroBytes(rutaFirmaServidor, firma);
				out.writeUTF(rutaFirmaServidor);
				
				//Guardando la llave publica en un fichero y enviandole la ruta al cliente
				escribirFicheroBytes(rutaLlavePublica, pubKey.getEncoded());
				out.writeUTF(rutaLlavePublica);
				
			}catch (EnganoServidorException e) {
				e.showMessage();
			}
			


		} catch(Exception e) {
			e.printStackTrace();
		}
		try {
			//Cerrando conexion
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//[B@5d0b1bef
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
	public static byte[] firmarDocumento(PrivateKey privKey, byte[] documento) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		Signature dsa = Signature.getInstance("SHA1withRSA"); 
		dsa.initSign(privKey);
		dsa.update(documento);
		byte[] firma = dsa.sign();
		return firma;
	}
	public static void escribirFicheroBytes(String ruta, byte[] contenido) throws IOException {
		FileOutputStream fos = new FileOutputStream(ruta);				
		fos.write(contenido);
		fos.close();
	}
}

