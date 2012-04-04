package org.okkam.webid;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.util.BigIntegers;

import sun.security.x509.CertException;
import sun.security.x509.GeneralName;

/**
 * Servlet implementation class WebID
 */
public class WebID extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public WebID() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		 X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
		boolean succed = false ;
		if(certificates !=null ){
			System.out.println("Certeficate found");
		 try {
			 for(int i = 0; i <certificates.length;i++){				 
				 PublicKey pkey = certificates[i].getPublicKey();
				 
				 RSAPublicKey ob = (RSAPublicKey)certificates[i].getPublicKey();
				 BigInteger modulus = ob.getModulus();
				 BigInteger exponent = ob.getPublicExponent();
				System.out.println("Modules = "+ modulus.toString(16));
				System.out.println("Exponent = "+ exponent.toString(10));
				for(Object sanObject : certificates[i].getSubjectAlternativeNames()) {
					if(sanObject instanceof List && ((List)sanObject).size() >= 2) {				
						List sanObjectList = (List)sanObject;
						System.out.println(sanObjectList.get(0));
						System.out.println(sanObjectList.get(1));
						succed = true ;
					}
				}
		 }
			 
		//	List sanObjectList = (List)certificates[0].getSubjectAlternativeNames();
		//	System.out.println(sanObjectList.get(1).toString());
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		}
		if(succed){
			request.getRequestDispatcher("index.jsp").forward(request, response);
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		 X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
		 try {
			List sanObjectList = (List)certificates[0].getSubjectAlternativeNames();
			System.out.println(sanObjectList.get(1).toString());
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
	}

}
