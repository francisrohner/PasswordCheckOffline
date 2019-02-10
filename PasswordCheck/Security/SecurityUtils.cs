//Courtesy of NetMage via StackOverflow: https://stackoverflow.com/a/46821287

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordCheck.Security
{
    
    static class SecurityUtils
    {
        public static HashAlgorithm MD4Singleton;
        static SecurityUtils()
        {
            MD4Singleton = MD4.Create();
        }
        private static byte[] GetMD4Bytes(string s)
        {
            return MD4Singleton.ComputeHash(Encoding.Unicode.GetBytes(s));
        }

        private static string AsHexString(byte[] bytes)
        {
            //return String.Join("", bytes.Select(h => h.ToString("X2")));
            return string.Concat(bytes.Select(b => b.ToString("X2")));
        }

        public static string HashNLTM(string input)
        {   
            byte[] md4 = SecurityUtils.GetMD4Bytes(input);            
            return AsHexString(md4);
        }
        public static string HashSHA1(string input)
        {
            byte[] hash = new SHA1Managed().ComputeHash(Encoding.UTF8.GetBytes(input));
            //return string.Concat(hash.Select(b => b.ToString("X2")));
            return AsHexString(hash);
        }
    }
}
