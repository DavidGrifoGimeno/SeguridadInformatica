package Servidor;

public class EnganoServidorException extends Exception{
	public void showMessage() {
		System.out.println("Estan intentando engañar al servidor");
	}
}
