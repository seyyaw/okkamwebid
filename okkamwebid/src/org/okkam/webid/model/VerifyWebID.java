package org.okkam.webid.model;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import com.hp.hpl.jena.query.Query;
import com.hp.hpl.jena.query.QueryExecution;
import com.hp.hpl.jena.query.QueryExecutionFactory;
import com.hp.hpl.jena.query.QueryFactory;
import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.ModelFactory;
import com.hp.hpl.jena.rdf.model.Property;
import com.hp.hpl.jena.rdf.model.RDFNode;
import com.hp.hpl.jena.rdf.model.Resource;
import com.hp.hpl.jena.rdf.model.Statement;
import com.hp.hpl.jena.rdf.model.StmtIterator;
import com.hp.hpl.jena.util.FileManager;

public class VerifyWebID {
	Model model;
	public boolean isAllowed(String webID, String fileName){
		boolean allowed = false;
		//ServletContext sc = getServletContext();
		InputStream in = FileManager.get().open(fileName);
		if (in == null) {		    
			System.out.println("File Not Found");
		}
		else {
		// Create the input model. Models different from the default one import also the 
		// rdf and rdf-schema axioms. The input model usually comes with blank nodes. 
			model = ModelFactory.createDefaultModel();	
		// read the RDF/TURTLE file
			model.read(in, null, "TURTLE");
			
		}
		if(model != null){
			Resource sub = model.createResource(webID);
			Property prop = model.createProperty("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
			RDFNode pred = model.createResource("http://xmlns.com/foaf/0.1#Person");
			StmtIterator it = model.listStatements(sub, prop , pred) ;
/*			String prefix = "PREFIX foaf: <http://xmlns.com/foaf/0.1/> " +
					"PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> ";
			String queryString = prefix + '\n'
				+ "ask { " +webID+" ?x foaf:Person. } ";
			
			System.out.println(queryString);
			
			Query query = QueryFactory.create(queryString) ;
			QueryExecution qexec = QueryExecutionFactory.create(query, model) ;
			allowed = qexec.execAsk() ;
			qexec.close() ;*/
			if(it.hasNext()){
				allowed = true;
			}
		}
		
		return allowed;
	}
	/**
	 * authenticate a user tried to loggin with a certificate based on the FOAF+SSL webID method
	 * 
	 * @param webID the webID extracted from the certeficate
	 * @param modulus modulus of the public key
	 * @param exponent exponent of the public key
	 * @param fileName // file name (for test purpose) SPARQL end point of the rdf store
	 * @return
	 */
	public boolean isAuthenticated(String webID, String modulus, String exponent, String fileName ){
	

		System.setProperty("http.proxyHost", "proxy.unitn.it");
		System.setProperty("http.proxyPort", "3128");
		
		boolean allowed = false;
		//ServletContext sc = getServletContext();
		FileManager fm = new FileManager();
		//fm.addLocatorURL();
		InputStream in = fm.get().open(fileName);
		//InputStream in  = FileManager.get().open("http://www.sharesemantics.com/people/luigi/foaf.rdf");
		if (in == null) {		    
			System.out.println("File Not Found");
		}
		else {
			model = ModelFactory.createDefaultModel();	
		// read the RDF/TURTLE file
			model.read(in, null, "RDF/XML");
			//model.write(System.out,"TTL");
			
		}
		if(model != null){
			//Resource sub = model.createResource("http://www.w3.org/ns/auth/cert#key");
			Property prop = model.createProperty("http://www.w3.org/ns/auth/cert#key");
			//RDFNode pred = model.createResource("http://xmlns.com/foaf/0.1/Person");
			StmtIterator it = model.listStatements() ;
			
			Property propexponent = model.createProperty("http://www.w3.org/ns/auth/cert#exponent");
			Property propemodulus = model.createProperty("http://www.w3.org/ns/auth/cert#modulus");
			
			String modulustemp = null;
			String exponenttemp = null;
			boolean modulusfound = false,exponentfound = false;
			while (it.hasNext()){
				Statement statment = it.next();
				Resource subject = statment.getSubject();
				Property predicate = statment.getPredicate();
				RDFNode object = statment.getObject();
				if(propemodulus.equals(predicate)){
					modulustemp = object.toString();
					modulusfound = true;
					if(exponentfound) break;	
				}
				
				if(propexponent.equals(predicate)){
					exponenttemp = object.toString();
					exponentfound = true;
					if(modulusfound) break;	
				}
				
			}
				modulustemp = modulustemp.toString().substring(0,modulustemp.toString().indexOf("^")).trim();
				exponenttemp = exponenttemp.toString().substring(0,exponenttemp.toString().indexOf("^")).trim();
			if(modulustemp.equals(modulus.trim())&&exponenttemp.equals(exponent.trim())){
				allowed = true;
			}
			
				
			
/*						String prefix = "PREFIX : <http://www.w3.org/ns/auth/cert#>" +
								"PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> ";
						String queryString = prefix + '\n'
							+ "ask { <http://www.sharesemantics.com/people/luigi/foaf.rdf#me> :key [" +
									" :modulus d19c22eb83b11c87a2805f555cd94f3c76c3065b32b5fb3db56661b8d80d6b1b047d1bc6ad3da2f5e990a39f8dc1e49b9b93459a33abdcc9842ebb2c721faaa0daee080a6a4585c5178663fe5114e585e56078b61d680f6d47a08d18796be2bc66c28265f6d7d5d0e1d5b1f1ddb5d96c55c808f98302838c6ceba3be814235bf4f04b554010feb8ec19c39e3f1e50f40db2b0679f19a86d9606cee9331aa92b7a0f7eaf72cd31b4e524afe6ac2cd7fbaeac2827041cc7b21e3da790f5b3ba07be9da4342e0ac3622b201495b54cbc0253a0bb90d3f26aa4ac3960529e0745f53d506c91d7883785c653c833dcdfea3c47d7e60fbc0a55a5506fab31538d52675" +
									" :exponent 65537" +
									"] ." +
									"}";
						
						System.out.println(queryString);
						
						Query query = QueryFactory.create(queryString) ;
						QueryExecution qexec = QueryExecutionFactory.create(query, model) ;
						allowed = qexec.execAsk() ;
						qexec.close() ;
			*/
			
		}
		
		return allowed;
	}
}
