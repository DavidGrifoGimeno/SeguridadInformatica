package Servidor;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Servidor {
	
	public static void main(String[] args) {
		
		ServerSocket servidor = null;
		Socket socket = null;
		final int port = 8080;
		
		try {
			
			servidor = new ServerSocket(port);
			System.out.println("Servidor 'Firma Ciega' iniciado");
			System.out.println("Esperando conexión");
			
			while(true) {
				
				socket = servidor.accept();
				System.out.println("Conexión aceptada");
				
				//Creamos el hilo
				Thread elHilo = new Thread(new HiloServidorFirmaCiega(socket));
				elHilo.start();
				
				System.out.println("Esperando conexión");
				
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
