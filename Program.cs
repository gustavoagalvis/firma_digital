using System;

namespace FirmaDigital
{
    class Program
    {
        static void Main(string[] args)
        {
            
            Console.WriteLine("Ingrese la ruta de archivo a firmar y/o verificar:");
            string path = Console.ReadLine();

            CallSigner(path);
            CallVerifier(path);
        }

        static void CallSigner(string path)
        {
            Console.WriteLine("Comienzo de firma digital");
            if (path != null)
            {
                SignXadesXml signX = new SignXadesXml();
                string error = signX.SignXadesEpes(path);

                if (error.Equals("false"))
                    Console.WriteLine("Firma exitosa");
                else
                    Console.WriteLine("Se presento el siguiente error en la firma:" + error);
            }
            Console.WriteLine("Fin de firma digital");
        }

        static void CallVerifier(string path)
        {
            Console.WriteLine("Comienzo de verificación digital");
            if (path != null)
            {
                SignXadesXml signX = new SignXadesXml();
                string error = signX.VerifySignXadesEpes(path);

                if (error.Equals("false"))
                    Console.WriteLine("Verificación exitosa");
                else
                    Console.WriteLine("Se presento el siguiente error en la verificación:" + error);
            }
            Console.WriteLine("Fin de la verificación digital");
        }
    }
}
