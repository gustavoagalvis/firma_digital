using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.IO;


namespace FirmaDigital
{
    class SignXadesXml
    {
        public X509Certificate2 FindCertificate(int position)
        {
            int iteration = 0;
            foreach (StoreLocation storeLocation in (StoreLocation[])
                Enum.GetValues(typeof(StoreLocation)))
            {
                foreach (StoreName storeName in (StoreName[])
                    Enum.GetValues(typeof(StoreName)))
                {
                    X509Store store = new X509Store(storeName, storeLocation);

                    try
                    {
                        store.Open(OpenFlags.OpenExistingOnly);

                        foreach (X509Certificate2 x509 in store.Certificates)
                        {
                            if (x509.PrivateKey != null)
                            {
                                if (iteration == position)
                                    return x509;
                                else
                                    iteration++;
                            }
                                
                        }

                    }
                    catch (CryptographicException)
                    {
                        
                    }
                }
            }

            X509Certificate2 cert = null;
            return cert;
        }

        public X509Certificate2 LoadCertificate(string certPath, string certPass)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(certPath, certPass, X509KeyStorageFlags.PersistKeySet);
            foreach (X509Certificate2 cert in collection)
            {
                Console.WriteLine("Subject is: '{0}'", cert.Subject);
                Console.WriteLine("Issuer is:  '{0}'", cert.Issuer);

                return cert;
            }
            return null;
        }

            public string SignXadesEpes(string xmlFileToSign, string certPath, string certPass)
        {
            string error = "false";
            try
            {
                X509Certificate2 certificado = new X509Certificate2();
                certificado = LoadCertificate(certPath, certPass);
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                string fullPath = Path.GetFullPath(xmlFileToSign);
                xmlDoc.Load(@fullPath);
                xmlDoc = SignXmlDocument(xmlDoc, certificado);
                xmlDoc.Save(xmlFileToSign);

            }
            catch (Exception ex) { 
                error = ex.ToString(); 
            }

            return error;
        }

        public string VerifySignXadesEpes(string xmlFileToVerify, string certPath, string certPass)
        {
            string error = "false";
            try
            {
                X509Certificate2 certificado = new X509Certificate2();
                certificado = LoadCertificate(certPath, certPass);

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                string fullPath = Path.GetFullPath(xmlFileToVerify);
                xmlDoc.Load(@fullPath);
                bool check = VerifySign(xmlDoc, certificado);
                if (check)
                    Console.WriteLine("Verificación exitosa");
                else
                    Console.WriteLine("Verificación fallida");
            }
            catch (Exception ex)
            {
                error = ex.ToString();
            }
            return error;
        }
        private XmlDocument SignXmlDocument(XmlDocument xmlDoc, X509Certificate2 certificate)
        {
            
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (certificate == null)
                throw new ArgumentException("certificate");
           
            SignedXml signedXml = new SignedXml(xmlDoc);
           // signedXml.Signature.Id = "SignatureId";
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            string URI = "http://uri.etsi.org/01903/v1.3.2#";
            XmlElement qualifyingPropertiesRoot = xmlDoc.CreateElement("xades", "QualifyingProperties", URI);
            qualifyingPropertiesRoot.SetAttribute("Target", "#SignatureId", URI);

            XmlElement signaturePropertiesRoot = xmlDoc.CreateElement("xades", "SignedProperties", URI);
            signaturePropertiesRoot.SetAttribute("Id", "SignedPropertiesId", URI);

            XmlElement SignedSignatureProperties = xmlDoc.CreateElement("xades", "SignedSignatureProperties", URI);

            XmlElement timestamp = xmlDoc.CreateElement("xades", "SigningTime", URI);
            timestamp.InnerText = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); //2011-09-05T09:11:24.268Z
            SignedSignatureProperties.AppendChild(timestamp);

            XmlElement SigningCertificate = xmlDoc.CreateElement("xades", "SigningCertificate", URI);
            XmlElement Cert = xmlDoc.CreateElement("xades", "Cert", URI);
            XmlElement CertDigest = xmlDoc.CreateElement("xades", "CertDigest", URI);
            SHA1 cryptoServiceProvider = new SHA1CryptoServiceProvider();
            byte[] sha1 = cryptoServiceProvider.ComputeHash(certificate.RawData);

            XmlElement DigestMethod = xmlDoc.CreateElement("ds", "DigestMethod", URI);

            DigestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA1Url);
            XmlElement DigestValue = xmlDoc.CreateElement("ds", "DigestValue", URI);
            DigestValue.InnerText = Convert.ToBase64String(sha1);
            CertDigest.AppendChild(DigestMethod);
            CertDigest.AppendChild(DigestValue);
            Cert.AppendChild(CertDigest);

            XmlElement IssuerSerial = xmlDoc.CreateElement("xades", "IssuerSerial", URI);
            XmlElement X509IssuerName = xmlDoc.CreateElement("ds", "X509IssuerName", "http://www.w3.org/2000/09/xmldsig#");
            X509IssuerName.InnerText = certificate.IssuerName.Name;
            XmlElement X509SerialNumber = xmlDoc.CreateElement("ds", "X509SerialNumber", "http://www.w3.org/2000/09/xmldsig#");
            X509SerialNumber.InnerText = certificate.SerialNumber;
            IssuerSerial.AppendChild(X509IssuerName);
            IssuerSerial.AppendChild(X509SerialNumber);
            Cert.AppendChild(IssuerSerial);

            SigningCertificate.AppendChild(Cert);
            SignedSignatureProperties.AppendChild(SigningCertificate);

            signaturePropertiesRoot.AppendChild(SignedSignatureProperties);
            qualifyingPropertiesRoot.AppendChild(signaturePropertiesRoot);

            XmlElement SignaturePolicyIdentifier = xmlDoc.CreateElement("xades", "SignaturePolicyIdentifier", URI);
            SignedSignatureProperties.AppendChild(SignaturePolicyIdentifier);

            XmlElement SignaturePolicyId = xmlDoc.CreateElement("xades", "SignaturePolicyId", URI);
            SignaturePolicyIdentifier.AppendChild(SignaturePolicyId);

            XmlElement SigPolicyId = xmlDoc.CreateElement("xades", "SigPolicyId", URI);
            SignaturePolicyId.AppendChild(SigPolicyId);

            XmlElement Identifier = xmlDoc.CreateElement("xades", "Identifier", URI);
            Identifier.InnerText = "https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf";
            SigPolicyId.AppendChild(Identifier);

            XmlElement SigPolicyHash = xmlDoc.CreateElement("xades", "SigPolicyHash", URI);
            SignaturePolicyId.AppendChild(SigPolicyHash);
           
            DigestMethod = xmlDoc.CreateElement("ds", "DigestMethod", URI);
            DigestMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            DigestValue = xmlDoc.CreateElement("ds", "DigestValue", URI);
            byte[] shaCertificate = { 0xf1, 0x48, 0x03, 0x50, 0x5c, 0x33, 0x64, 0x29, 0x07, 0x84, 0x43, 0xca, 0x79, 0x6e, 0x59, 0xcc, 0xac, 0xf5, 0x85, 0x4c };
            DigestValue.InnerText = Convert.ToBase64String(shaCertificate);
            SigPolicyHash.AppendChild(DigestMethod);
            SigPolicyHash.AppendChild(DigestValue);

            XmlElement SignedDataObjectProperties = xmlDoc.CreateElement("xades", "SignedDataObjectProperties", URI);
            XmlElement DataObjectFormat = xmlDoc.CreateElement("xades", "DataObjectFormat", URI);
            DataObjectFormat.SetAttribute("ObjectReference", "#r-id-1");
            signaturePropertiesRoot.AppendChild(SignedDataObjectProperties);
            SignedDataObjectProperties.AppendChild(DataObjectFormat);
            XmlElement MimeType = xmlDoc.CreateElement("xades", "MimeType", URI);
            MimeType.InnerText = "application/octet-stream";
            DataObjectFormat.AppendChild(MimeType);

            DataObject dataObject = new DataObject
            {
                Data = qualifyingPropertiesRoot.SelectNodes("."),
            };

            signedXml.AddObject(dataObject);

            signedXml.SigningKey = certificate.PrivateKey;

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoX509Data);
            signedXml.KeyInfo = keyInfo;

            //Reference 1
            Reference reference2 = new Reference();
            reference2.Id = "R1";
            reference2.Type = "http://uri.etsi.org/01903#SignedProperties";
            reference2.Uri = "";
            XmlDsigXPathTransform XPathTransform = CreateXPathTransform("ValorPath", xmlDoc);
            reference2.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            reference2.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference2);

            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            bool checkSign = signedXml.CheckSignature();
            
            return xmlDoc;

        }



        private bool VerifySign(XmlDocument xmlDoc, X509Certificate2 certificate)
        {
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (certificate == null)
                throw new ArgumentException("certificate");

            
            SignedXml signedXml = new SignedXml(xmlDoc);
            XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verificacion fallida: Etiqueta Signature no encontrada en el documento.");
            }

            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verificacion fallida: Mas de una etiqueta Signature encontrada en el documento.");
            }

            XmlNodeList certificates = xmlDoc.GetElementsByTagName("X509Certificate");
            string innerTextCert = certificates[0].InnerText;
            X509Certificate2 dcert2 = new X509Certificate2(Convert.FromBase64String(innerTextCert));
            
            signedXml.LoadXml((XmlElement)nodeList[0]);
            X509Certificate2 serviceCertificate = null;
            
            foreach (KeyInfoClause clause in signedXml.KeyInfo)
            {
                if (clause is KeyInfoX509Data)
                {
                    if (((KeyInfoX509Data)clause).Certificates.Count > 0)
                    {
                        serviceCertificate = (X509Certificate2)((KeyInfoX509Data)clause).Certificates[0];
                    }
                }
            }
            
            bool checkSign = signedXml.CheckSignature(dcert2, true);
            bool checkSign1 = signedXml.CheckSignature(certificate.PublicKey.Key);
            bool checkSign2 = signedXml.CheckSignature(serviceCertificate, true);
            
            return checkSign;
            
        }

        private static XmlDsigXPathTransform CreateXPathTransform(string XPathString, XmlDocument doc)
        {
            XmlElement xPathElem = doc.CreateElement("XPath");
            xPathElem.InnerText = XPathString;
            XmlDsigXPathTransform xForm = new XmlDsigXPathTransform();
            xForm.LoadInnerXml(xPathElem.SelectNodes("."));
            return xForm;
        }
    }
}
