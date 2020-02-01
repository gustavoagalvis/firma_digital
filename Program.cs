using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace FirmaDigital
{
    class Program
    {


        static void Main(string[] args)
        {
            //string certPath = @"C:\Users\Administrador\source\repos\Firma_Factura\FirmaDigital\signExample\certificados\8221519_www.example.com.pfx";
            string certPath = @"C:\Users\Administrador\source\repos\Firma_Factura\FirmaDigital\signExample\certificados\CertificadoAudiSoft20200125.pfx";

            string certPass = "";
            string xmlToSign = @"C:\Users\Administrador\source\repos\Firma_Factura\FirmaDigital\signExample\firmas\firma.xml";
            CallSigner(xmlToSign, certPath, certPass);
            CallVerifier(xmlToSign, certPath, certPass);
        }


        static void CallSigner(string xmlToSign, string certPath, string certPass)
        {
            Console.WriteLine("Comienzo de firma digital");
            if (xmlToSign != null)
            {
                SignXadesXml signX = new SignXadesXml();
                string error = signX.SignXadesEpes(xmlToSign, certPath, certPass);

                if (error.Equals("false"))
                    Console.WriteLine("Firma exitosa");
                else
                    Console.WriteLine("Se presento el siguiente error en la firma:" + error);
            }
            Console.WriteLine("Fin de firma digital");
        }

        static void CallVerifier(string xmlToVerify, string certPath, string certPass)
        {
            Console.WriteLine("Comienzo de verificación digital");
            if (xmlToVerify != null)
            {
                SignXadesXml signX = new SignXadesXml();
                string error = signX.VerifySignXadesEpes(xmlToVerify, certPath, certPass);

                if (error.Equals("false"))
                    Console.WriteLine("Verificación exitosa");
                else
                    Console.WriteLine("Se presento el siguiente error en la verificación:" + error);
            }
            Console.WriteLine("Fin de la verificación digital");
        }
    }
}

