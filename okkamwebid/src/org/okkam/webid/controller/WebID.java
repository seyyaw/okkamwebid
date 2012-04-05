package org.okkam.webid.controller;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.okkam.webid.model.GetWebID;
import org.okkam.webid.model.VerifyWebID;

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
		boolean found = false ;
		Vector webID = null;
		Vector modulus = null;
		Vector exponent = null;
		if(certificates !=null ){
			System.out.println("Certeficate found");
			GetWebID webIDComponents = new GetWebID(certificates);
			webID = webIDComponents.getWebID();
			modulus = webIDComponents.getModules();
			exponent = webIDComponents.getExponent();
			
			if (webID != null && webID.size() > 0)
				found = true;
		}
		//if there is webID in the certeficate
		if(found){
			VerifyWebID verifyWebID = new VerifyWebID();
			String userListFileName = getServletContext().getRealPath("/resources/allowedUsers.ttl") ;
			boolean allowed = verifyWebID.isAllowed(webID.firstElement().toString(), userListFileName );
			boolean authenticated = false;
			if(allowed)
			authenticated = verifyWebID.isAuthenticated(webID.firstElement().toString(),
					modulus.firstElement().toString(), exponent.firstElement().toString(),
					webID.firstElement().toString().substring(0,webID.firstElement().toString().indexOf("#")));
			
		/*	boolean isAuthenticated = verifyWebID.isAuthenticated("http://www.sharesemantics.com/people/luigi/foaf.rdf#me",
					"d19c22eb83b11c87a2805f555cd94f3c76c3065b32b5fb3db56661b8d80d6b1b047d1bc6ad3da2f5e990a39f8dc1e49b9b93459a33abdcc9842ebb2c721faaa0daee080a6a4585c5178663fe5114e585e56078b61d680f6d47a08d18796be2bc66c28265f6d7d5d0e1d5b1f1ddb5d96c55c808f98302838c6ceba3be814235bf4f04b554010feb8ec19c39e3f1e50f40db2b0679f19a86d9606cee9331aa92b7a0f7eaf72cd31b4e524afe6ac2cd7fbaeac2827041cc7b21e3da790f5b3ba07be9da4342e0ac3622b201495b54cbc0253a0bb90d3f26aa4ac3960529e0745f53d506c91d7883785c653c833dcdfea3c47d7e60fbc0a55a5506fab31538d52675"
					, "65537",
					"http://www.sharesemantics.com/people/luigi/foaf.rdf");
*/			if(authenticated)
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
