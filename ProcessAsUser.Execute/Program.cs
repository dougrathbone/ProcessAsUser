using System;
using System.Diagnostics;
using System.Security;

namespace ProcessAsUser.Execute
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Executing process");

            var startInfo = new ProcessStartInfo
            {
                UserName = "childUser",
                Password = generateSecureString("test123"),
                Domain = Environment.MachineName,
                CreateNoWindow = true,
                UseShellExecute = true,
                FileName = "calc.exe"
            };

            var svc = new ProcessAsUser.Core.ProcessAsUser();
            svc.StartProcess(startInfo);
        }

        private static SecureString generateSecureString(string password)
        {
            var secure = new SecureString();
            foreach (var c in password.ToCharArray())
            {
                secure.AppendChar(c);
            }
            return secure;
        }
    }
}
