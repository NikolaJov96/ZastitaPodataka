package implementation;

import code.GuiException;
import gui.Constants;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;
import sun.security.provider.DSAPublicKey;
import sun.security.provider.DSAPublicKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	private static Provider BCProvider = new BouncyCastleProvider();
	
	private KeyStore keyStore;
	private static String keyStorePath = "key_store";
	private static char[] keyStorePass = "pass123".toCharArray();
	
	private String selectedKeyPair = null;
	private PKCS10CertificationRequest loadedCSR = null;
	
	static { Security.addProvider(BCProvider); }

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}

	@Override
	public boolean canSign(String keypair_name) {
		X509Certificate cert;
		try {
			cert = (X509Certificate) keyStore.getCertificate(keypair_name);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		if (cert.getKeyUsage()[5]) { return true; } 
		else { return false; }
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePass);
		    PublicKey publicKey = cert.getPublicKey();
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
					cert.getSubjectX500Principal(), publicKey);
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm);
			ContentSigner signer = csBuilder.build(privateKey);
			PKCS10CertificationRequest csr = p10Builder.build(signer);
			PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
			FileWriter fw = new FileWriter(file);
			JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
			pemWriter.writeObject(pemObject);
			pemWriter.close();
			fw.close();
			return true;
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
            if (encoding == 0) { // DER
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(cert.getEncoded());
                fos.close();
            } else if (encoding == 1) { // PEM
                FileWriter fileWriter = new FileWriter(file);
                JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(fileWriter);
                if (format == 0) { // HEAD-ONLY
                    jcaPEMWriter.writeObject(cert);
                } else if (format == 1) { // ENTIRE CHAIN
                    Certificate[] chain = keyStore.getCertificateChain(keypair_name);
                    for (int j = 0; j < chain.length; j++) {
                        jcaPEMWriter.writeObject(chain[j]);
                    }
                }
                jcaPEMWriter.close();
            }
            return true;
        } catch (KeyStoreException | IOException | CertificateEncodingException e) {
            e.printStackTrace();
            return false;
        }
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(null, keyStorePass);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePass);
            Certificate[] certs = keyStore.getCertificateChain(keypair_name);
            System.out.println(certs.length);
            for (Certificate cert : certs) {
            	System.out.println(cert);
            }
            ks.setKeyEntry(keypair_name, privateKey, keyStorePass, certs);
            FileOutputStream fos = new FileOutputStream(file);
            ks.store(fos, password.toCharArray());
            fos.close();
            return true;
        } catch (IOException | KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
	}
    
	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
            return cert.getPublicKey().getAlgorithm();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        }
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
            if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
                java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
                return String.valueOf(rsaPublicKey.getModulus().bitLength());
            } else if (cert.getPublicKey().getAlgorithm().equals("EC")) {
                ECPrivateKeyImpl ecPrivateKey = (ECPrivateKeyImpl) keyStore.getKey(keypair_name, keyStorePass);
                ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
                String[][] curves_by_set = new String[][]{
                	{"prime256v1"}, 
                	{"secp256k1", "secp256r1", "secp384r1", "secp521r1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1"}, 
                	{"P-256", "P-384", "P-521", "B-283", "B-409", "B-571"}
                };
                for (int i = 0; i < 3; i++) {
                    for (int j = 0; j < curves_by_set[i].length; j++) {
                        if (ecParameterSpec.toString().substring(0, curves_by_set[i][j].length()).equals(ECNamedCurveTable.getParameterSpec(curves_by_set[i][j]).getName())) {
                        	return curves_by_set[i][j];
                        }
                    }
                }
            } else if (cert.getPublicKey().getAlgorithm().equals("DSA")) {
                DSAPublicKey dsaPublicKey = (DSAPublicKey) cert.getPublicKey();
                return String.valueOf(dsaPublicKey.getParams().getP().bitLength());
            }
            return null;
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			String ret = cert.getSubjectX500Principal().toString().replaceAll(", ", ",") + 
					",SA=" + getCertPublicKeyAlgorithm(keypair_name);
			return ret;
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return "";
		}
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			X509Certificate keyStoreCert = (X509Certificate) keyStore.getCertificate(keypair_name);

            FileInputStream fis = new FileInputStream(file);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<X509Certificate> colelction = (Collection<X509Certificate>) factory.generateCertificates(fis);
            ArrayList<java.security.cert.Certificate> certs = new ArrayList<>();

            for (X509Certificate cert : colelction){ certs.add(cert); }
            java.security.cert.Certificate[] chain = new java.security.cert.Certificate[certs.size()];
            for(int i = 0; i<chain.length; i++){
                chain[i] = certs.get(i);
            }
            X509Certificate caReply = (X509Certificate) chain[0];
            String sub1 = caReply.getSubjectX500Principal().getName().replace(", ", ",");
            String sub2 = keyStoreCert.getSubjectX500Principal().getName().replace(", ", ",");
            if (sub1.equals(sub2)) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePass);
                keyStore.deleteEntry(keypair_name);
                keyStore.setKeyEntry(keypair_name, privateKey, keyStorePass, chain);
                dumpKeyStore();
                loadKeypair(keypair_name);
                return true;
            } else {
            	access.reportError("Wrong certificate!");
            	return false;
            }
		} catch (IOException | CertificateException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public String importCSR(String file) {
		try {
			FileReader fr = new FileReader(file);
			PemReader pemReader = new PemReader(fr);
			PemObject pemObject = pemReader.readPemObject();
			pemReader.close();
			fr.close();
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(pemObject.getContent());
			loadedCSR = csr;
			String ret = csr.getSubject().toString() + ",SA=";
			DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();
			String alg = finder.getAlgorithmName(csr.getSignatureAlgorithm());
			if (alg.endsWith("DSA")) { ret = ret + "DSA"; }
			else if (alg.endsWith("RSA")) { ret = ret + "RSA"; }
			else { ret = ret + "EC"; }
			System.out.println(ret);
			return ret;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) {
		try {
            CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");
            FileInputStream fis = new FileInputStream(file);
            X509Certificate cert = (X509Certificate)certFact.generateCertificate(fis);
            keyStore.setCertificateEntry(keypair_name, cert);
            dumpKeyStore();
            return true;
        } catch (CertificateException | KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return false;
        }
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fis = new FileInputStream(file);
            ks.load(fis, password.toCharArray());
            fis.close();
            Enumeration<String> aliases = ks.aliases();
            if (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
                Certificate[] certs = ks.getCertificateChain(alias);
                keyStore.setKeyEntry(keypair_name, privateKey, password.toCharArray(), certs);
            }
            dumpKeyStore();
            return true;
        } catch (IOException | KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
            return false;
        }
	}

	@Override
	public int loadKeypair(String keypair_name) {
		try {
            selectedKeyPair = keypair_name;
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(selectedKeyPair);
            System.out.println(cert);
            Integer keySize;
            getSubjectInfo(keypair_name);
            if (cert.getPublicKey() instanceof BCDSAPublicKey) {
                keySize = ((BCDSAPublicKey) cert.getPublicKey()).getY().bitLength();
            } else if (cert.getPublicKey() instanceof DSAPublicKeyImpl) {
                keySize = ((DSAPublicKeyImpl) cert.getPublicKey()).getY().bitLength();
            } else if (cert.getPublicKey() instanceof RSAPublicKeyImpl) {
                keySize = ((RSAPublicKeyImpl)cert.getPublicKey()).getPublicExponent().bitLength();
            } else if (cert.getPublicKey() instanceof BCRSAPublicKey) {
                keySize = ((BCRSAPublicKey)cert.getPublicKey()).getPublicExponent().bitLength();
            } else {
                return -1;
            }
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            X500Name subject = holder.getSubject();
            X500Name issuer = holder.getIssuer();
            access.setPublicKeyParameter(String.valueOf(keySize));
            access.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            access.setSerialNumber(String.valueOf(holder.getSerialNumber()));
            access.setSubject(subject.toString());
            access.setSubjectSignatureAlgorithm(cert.getSigAlgName());
            access.setIssuer(issuer.toString());
            access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
            access.setNotBefore(holder.getNotBefore());
            access.setNotAfter(holder.getNotAfter());
            if (cert.getVersion() == 3) { access.setVersion(Constants.V3); }
            else { access.setVersion(Constants.V1); }
            Set<String> criticals = cert.getCriticalExtensionOIDs();
            access.setCritical(Constants.KU, criticals.contains("2.5.29.15"));
            access.setKeyUsage(cert.getKeyUsage());
            if (cert.getExtendedKeyUsage() != null) {
	            boolean [] extKeyUsage = new boolean [7];
	            for (String key : cert.getExtendedKeyUsage()) {
	            	if (key.equals(KeyPurposeId.anyExtendedKeyUsage.toString())) { extKeyUsage[0] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_serverAuth.toString())) { extKeyUsage[1] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_clientAuth.toString())) { extKeyUsage[2] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_codeSigning.toString())) { extKeyUsage[3] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_emailProtection.toString())) { extKeyUsage[4] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_timeStamping.toString())) { extKeyUsage[5] = true; }
	            	if (key.equals(KeyPurposeId.id_kp_OCSPSigning.toString())) { extKeyUsage[6] = true; }
	            };
	            access.setCritical(Constants.EKU, criticals.contains("2.5.29.37"));
				access.setExtendedKeyUsage(extKeyUsage);
            }
			access.setCritical(Constants.SAN, criticals.contains("2.5.29.17"));
			StringBuilder sb = new StringBuilder();
			if (cert.getSubjectAlternativeNames() != null) {
				for (List<?> pair : cert.getSubjectAlternativeNames()) {
					sb.append(pair.get(1)).append(",");
				}
				sb.setLength(sb.length() - 1);
			}
			access.setAlternativeName(5, sb.toString());
			if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
				System.out.println("return 0");
                return 0;
			} else if (keyStore.isKeyEntry(keypair_name)) {
                System.out.println("return 1");
                return 1;
            } else {
                System.out.println("return 2");
                return 2;
            }
        } catch (KeyStoreException | CertificateEncodingException | CertificateParsingException e) {
            e.printStackTrace();
            return -1;
        }
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			if (keyStore == null) {
	            try {
                    keyStore  = KeyStore.getInstance("PKCS12", "BC");
                    FileInputStream fis = null;
                    try {
                        fis = new FileInputStream(keyStorePath);
                        keyStore.load(fis, keyStorePass);
                    } catch (FileNotFoundException e) {
                        System.out.println("Creating new keyStore");
                        keyStore.load(null, keyStorePass);
                        dumpKeyStore();
                    }
                    if (fis != null) { fis.close(); }
	            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | NoSuchProviderException e) {
	                e.printStackTrace();
	            }
	        }
            return keyStore.aliases();
        } catch (KeyStoreException e) {
        	e.printStackTrace();
        	return null;
        }
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
            keyStore.deleteEntry(keypair_name);
            dumpKeyStore();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
		selectedKeyPair = null;
        return true;
	}

	@Override
	public void resetLocalKeystore() {
		try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                keyStore.deleteEntry(alias);
            }
            dumpKeyStore();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
		}
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
		try {
			if (!access.getPublicKeyDigestAlgorithm().endsWith("DSA")) {
				access.reportError("Only DSA is supported!");
				return false;
			}
			KeyPair keyPair = generateKeypair(Integer.parseInt(access.getPublicKeyParameter()));
			SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		    ContentSigner contentSigner = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).build(keyPair.getPrivate());
			X509v3CertificateBuilder certBuilder = pullCertificate(keyInfo, null);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCProvider).getCertificate(certBuilder.build(contentSigner));
	        keyStore.setKeyEntry(keypair_name, keyPair.getPrivate(), keyStorePass, new Certificate[]{ cert });
	        dumpKeyStore();
		    return true;
	    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SecurityException | SignatureException | KeyStoreException | CertificateException | OperatorCreationException e) {
	        e.printStackTrace();
	        return false;
	    }
	}

	private X509v3CertificateBuilder pullCertificate(SubjectPublicKeyInfo keyInfo, X509Certificate issuerCert) 
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, 
			SecurityException, SignatureException, CertIOException {
    	StringBuilder sb = new StringBuilder();
    	String param = access.getSubjectCountry();
        if (param.length() > 0) { sb.append("C=").append(param).append(","); }
        param = access.getSubjectState();
        if (param.length() > 0) { sb.append("ST=").append(param).append(","); }
        param = access.getSubjectLocality();
        if (param.length() > 0) { sb.append("L=").append(param).append(","); }
        param = access.getSubjectOrganization();
        if (param.length() > 0) { sb.append("O=").append(param).append(","); }
        param = access.getSubjectOrganizationUnit();
        if (param.length() > 0) { sb.append("OU=").append(param).append(","); }
        param = access.getSubjectCommonName();
        if (param.length() > 0) { sb.append("CN=").append(param).append(","); }
        sb.setLength(sb.length() - 1);
        X500Principal principal = new X500Principal(sb.toString());
        X500Name subjectName = new X500Name(principal.getName());
        X500Name issuerName = subjectName;
        if (issuerCert != null) {
        	issuerName = new X500Name(issuerCert.getIssuerX500Principal().getName());
        }

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
        		issuerName, new BigInteger(access.getSerialNumber()), 
        		access.getNotBefore(), access.getNotAfter(), 
        		subjectName, keyInfo);
		
		int usedKeys = 0;
		if (access.getKeyUsage()[0]) { usedKeys |= KeyUsage.digitalSignature; }
		if (access.getKeyUsage()[1]) { usedKeys |= KeyUsage.nonRepudiation; }
		if (access.getKeyUsage()[2]) { usedKeys |= KeyUsage.keyEncipherment; }
		if (access.getKeyUsage()[3]) { usedKeys |= KeyUsage.dataEncipherment; }
		if (access.getKeyUsage()[4]) { usedKeys |= KeyUsage.keyAgreement; }
		if (access.getKeyUsage()[5]) { usedKeys |= KeyUsage.keyCertSign; }
		if (access.getKeyUsage()[6]) { usedKeys |= KeyUsage.cRLSign; }
		if (access.getKeyUsage()[7]) { usedKeys |= KeyUsage.encipherOnly; }
		if (access.getKeyUsage()[8]) { usedKeys |= KeyUsage.decipherOnly; }
		certBuilder.addExtension(Extension.keyUsage, access.isCritical(Constants.KU), new KeyUsage(usedKeys));
        
        ArrayList<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
		if (access.getExtendedKeyUsage()[0]) { keyPurposeIds.add(KeyPurposeId.anyExtendedKeyUsage); }
		if (access.getExtendedKeyUsage()[1]) { keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth); }
		if (access.getExtendedKeyUsage()[2]) { keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);  }
		if (access.getExtendedKeyUsage()[3]) { keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning); }
		if (access.getExtendedKeyUsage()[4]) { keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection); }
		if (access.getExtendedKeyUsage()[5]) { keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping); }
		if (access.getExtendedKeyUsage()[6]) { keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning); }
		certBuilder.addExtension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU), 
				new ExtendedKeyUsage(keyPurposeIds.toArray(new KeyPurposeId[keyPurposeIds.size()])));
		
		for (int id = 0; id < 10; id++) {
			String [] altNames = access.getAlternativeName(id);
			if (altNames.length > 0) {
				ArrayList<GeneralName> genNames = new ArrayList<>();
				for (int i = 0; i < altNames.length; i++) {
					genNames.add(new GeneralName(GeneralName.rfc822Name, altNames[i]));
				}
				certBuilder.addExtension(Extension.subjectAlternativeName, access.isCritical(Constants.SAN),
	            		new GeneralNames(genNames.toArray(new GeneralName[genNames.size()])));
	            break;
			}
		}
		
		return certBuilder;
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {
		try {
			X509Certificate issuerCert = (X509Certificate) keyStore.getCertificate(keypair_name);
			SubjectPublicKeyInfo keyInfo = loadedCSR.getSubjectPublicKeyInfo(); 
					// generateKeypair(Integer.parseInt(access.getPublicKeyParameter()));
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePass);
		    ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(privateKey);
		    X509v3CertificateBuilder certBuilder = pullCertificate(keyInfo, issuerCert);
		    X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCProvider).getCertificate(certBuilder.build(contentSigner));
		    
		    java.security.cert.Certificate[] oldChain = keyStore.getCertificateChain(keypair_name);
		    java.security.cert.Certificate[] chain = new java.security.cert.Certificate[oldChain.length + 1];
		    chain[0] = cert;
		    for (int i = 1; i < chain.length; i++) {
		    	chain[i] = oldChain[i - 1];
		    }
		    ArrayList<JcaX509CertificateHolder> holders = new ArrayList<JcaX509CertificateHolder>();
            for(int i = 0; i < chain.length; i++){
                JcaX509CertificateHolder holder = new JcaX509CertificateHolder((X509Certificate) chain[i]);
                holders.add(holder);
            }
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(cert.getEncoded());
            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            CollectionStore<JcaX509CertificateHolder> genStore = new CollectionStore<JcaX509CertificateHolder>(holders);
            cmsSignedDataGenerator.addCertificates(genStore);
            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData, true);

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(cmsSignedData.getEncoded());
            fos.flush();
            fos.close();
			return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SecurityException | 
        		KeyStoreException | CertificateException | OperatorCreationException | InvalidKeyException | SignatureException | IOException | UnrecoverableKeyException | CMSException e) {
            e.printStackTrace();
            return false;
        }
	}
	
	private void dumpKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileOutputStream fos = new FileOutputStream(keyStorePath);
        keyStore.store(fos, keyStorePass);
        fos.close();
	}

	private KeyPair generateKeypair(Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyGen = null;
		if (access.getPublicKeyDigestAlgorithm().endsWith("RSA")) {
			keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		} else {
			keyGen = KeyPairGenerator.getInstance("DSA", "BC");
		}
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        return keyPair;
	}

}
