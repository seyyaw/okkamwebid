package org.okkam.webid.model;

import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.x509.GeneralName;

public class GetWebID {
	protected Vector modulus;
	protected Vector exponent;
	protected Vector webID;

	public GetWebID(X509Certificate[] cert) {
		super();
		this.modulus = new Vector();
		this.exponent = new Vector();
		this.webID = new Vector();
		extract(cert); //extract webid related components from certificate and populate them
	}

	public Vector getModules() {

		return modulus;
	}

	public Vector getExponent() {

		return exponent;
	}
	
	public Vector getWebID() {
		return webID;
	}
	/**
	 * extracts the public key, exponents and webid (if available) from the client certificate.
	 * 
	 * @param certificates
	 */
	public void extract(X509Certificate[] certificates) {
		for (int i = 0; i < certificates.length; i++) {
			RSAPublicKey ob = (RSAPublicKey) certificates[i].getPublicKey();
			BigInteger modulus = ob.getModulus();
			BigInteger exponent = ob.getPublicExponent();
			try {
				if (certificates[i].getSubjectAlternativeNames() != null)
					try {
						for (Object sanObject : certificates[i]
								.getSubjectAlternativeNames()) {
							if (sanObject instanceof List
									&& ((List) sanObject).size() >= 2) {
								List sanObjectList = (List) sanObject;
								if (sanObjectList.get(0).equals(
										GeneralName.uniformResourceIdentifier)) {
									this.modulus.addElement(modulus.toString(16));
									this.exponent.addElement(exponent.toString(10));
									this.webID.addElement(sanObjectList.get(1));
									System.out.println("Modulus = " + modulus.toString(16));
									System.out.println("Exponent = " + exponent.toString(10));
									System.out.println("Web ID = "
											+ sanObjectList.get(1));
								}

							}
						}
					} catch (CertificateParsingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
			} catch (CertificateParsingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}
