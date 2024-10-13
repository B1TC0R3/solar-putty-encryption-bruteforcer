using Newtonsoft.Json;
using System.Security.Cryptography;
using Formatting = Newtonsoft.Json.Formatting;

namespace SolarPuttyEncryptionBruteforcer
{
    class Program
    {
        static void Main(string[] args)
        {
            string password;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n\t~= SPEBF by B1TC0R3 =~\n");
            Console.ResetColor();

            if (args.Length != 2)
            {
                Console.WriteLine("Usage: .\\spebf.exe C:\\session.dat C:\\wordlist.txt");
                Environment.Exit(0);
            }

            Console.Write("[+] Attempting to recover password for ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(args[0]);
            Console.ResetColor();

            foreach (var line in File.ReadLines(args[1]))
            {
                password = line.Replace("\n", "");

                if (password.Length == 0)
                    continue;

                try
                {
                    if (DoImport(args[0], password))
                    {
                        Console.Write("[+] Password: ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(password + "\n");
                        Console.ResetColor();
                        Environment.Exit(0);
                    }

                }
                catch { }

            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[-] Failed to find password.");
            Console.ResetColor();
        }
        static bool DoImport(string dialogFileName, string password)
        {
            using FileStream fileStream = new(dialogFileName, FileMode.Open);
            using StreamReader streamReader = new(fileStream);
            string data = streamReader.ReadToEnd();

            var decryption_result = Decrypt(password, data);

            if (decryption_result == string.Empty)
                return false;

           var json = JsonConvert.DeserializeObject(decryption_result);
           var cleaned_json = JsonConvert.SerializeObject(json, Formatting.Indented);
           Console.WriteLine("\n" + cleaned_json + "\n");

           return true;
        }

        public static string Decrypt(string passPhrase, string cipherText)
        {
            string result = "";

            byte[] raw_data = Convert.FromBase64String(cipherText);
            byte[] salt = raw_data.Take(24).ToArray();
            byte[] rgbIV = raw_data.Skip(24).Take(24).ToArray();
            byte[] payload = raw_data.Skip(48).Take(raw_data.Length - 48).ToArray();

            using Rfc2898DeriveBytes rfc2898DeriveBytes = new(passPhrase, salt, 1000);
            byte[] bytes = rfc2898DeriveBytes.GetBytes(24);

            using TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new();
            tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
            tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;

            using ICryptoTransform transform = tripleDESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV);
            using MemoryStream memoryStream = new(payload);
            using CryptoStream cryptoStream = new(memoryStream, transform, CryptoStreamMode.Read);

            for (int current = 0; current != -1; current = cryptoStream.ReadByte())
            {
                result += (char)current;
            }

            memoryStream.Close();
            cryptoStream.Close();

            return result;
        }
    }
}