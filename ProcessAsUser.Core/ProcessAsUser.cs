using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProcessAsUser.Core
{
        public class ProcessAsUser
        {
            static ProcessAsUser()
            {
                UserToken = IntPtr.Zero;
            }

            private static IntPtr UserToken { get; set; }

            public int StartProcess(ProcessStartInfo processStartInfo)
            {
                UserToken = IntPtr.Zero;

                LogInOtherUser(processStartInfo);

                var startUpInfo = new Native.STARTUPINFO();

                if (processStartInfo.RedirectStandardError || processStartInfo.RedirectStandardInput ||
                    processStartInfo.RedirectStandardOutput)
                {
                    //startUpInfo.dwFlags = Native.STARTF_USESTDHANDLES;
                }
                //// create pipe for standard out

                //CreatePipe(out standardOutputReadPipeHandle, out startUpInfo.hStdOutput, false);
                //CreatePipe(out standardErrorReadPipeHandle, out startUpInfo.hStdError, false); 

                int creationFlags = 0;
                if (processStartInfo.CreateNoWindow) creationFlags |= Native.CREATE_NO_WINDOW;
                creationFlags |= Native.CREATE_UNICODE_ENVIRONMENT;

                //startUpInfo.dwFlags = Native.STARTF_USESHOWWINDOW;

                var processInfo = new Native.PROCESS_INFORMATION();
                var cmdLine = BuildCommandLine(processStartInfo.FileName, processStartInfo.Arguments).ToString();
                Console.WriteLine("Executing:");
                bool processStarted = Native.CreateProcessAsUser(
                        UserToken, // user token
                        null,//processStartInfo.FileName, // application name
                        @"C:\code\runsforever.exe", // commandline
                        null, // process attributes
                        null, // thread attributes
                        false, // inherrit handle
                        creationFlags, // creation flags
                        IntPtr.Zero, // environment
                        processStartInfo.WorkingDirectory + "\\", // current directory
                        startUpInfo,
                        processInfo
                    );

                if (!processStarted)
                {
                    Exception e = new Win32Exception(Marshal.GetLastWin32Error());
                    Console.WriteLine("Failed to start process. Process is not started.");
                    Console.WriteLine(e);
                    Console.ReadLine();
                    return 0;
                }

                int processId = (int)processInfo.dwProcessId;
                Native.CloseHandle(processInfo.hProcess);
                Native.CloseHandle(processInfo.hThread);
                ProcessId = processId;
                Console.WriteLine("Kicked off process - process id: {0}", ProcessId);
                return ProcessId;
            }

            public int ProcessId;

            private static StringBuilder BuildCommandLine(string executableFileName, string arguments)
            {
                var commandLine = new StringBuilder();
                string fileName = executableFileName.Trim();
                bool fileNameIsQuoted = (fileName.StartsWith("\"", StringComparison.Ordinal) && fileName.EndsWith("\"", StringComparison.Ordinal));
                if (!fileNameIsQuoted)
                {
                    commandLine.Append("\"");
                }

                commandLine.Append(fileName);

                if (!fileNameIsQuoted)
                {
                    commandLine.Append("\"");
                }

                if (!String.IsNullOrEmpty(arguments))
                {
                    commandLine.Append(" ");
                    commandLine.Append(arguments);
                }

                return commandLine;
            }

            private static void LogInOtherUser(ProcessStartInfo processStartInfo)
            {
                if (UserToken == IntPtr.Zero)
                {
                    var tempUserToken = IntPtr.Zero;
                    var password = SecureStringToString(processStartInfo.Password);
                    bool loginResult = Native.LogonUser(processStartInfo.UserName, 
                        processStartInfo.Domain, password,
                        Native.LOGON32_LOGON_BATCH, 
                        Native.LOGON32_PROVIDER_DEFAULT,
                        ref tempUserToken);

                    if (loginResult)
                    {
                        Console.WriteLine("Successfully gained user token.");
                        UserToken = tempUserToken;
                    }
                    else
                    {
                        Console.WriteLine("Failed to login build user. Error:");
                        Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()));
                        Native.CloseHandle(tempUserToken);
                    }
                }
            }

            private static String SecureStringToString(SecureString value)
            {
                var stringPointer = Marshal.SecureStringToBSTR(value);
                try
                {
                    return Marshal.PtrToStringBSTR(stringPointer);
                }
                finally
                {
                    Marshal.FreeBSTR(stringPointer);
                }
            }

            public static void ReleaseUserToken()
            {
                Native.CloseHandle(UserToken);
            }

            [ResourceExposure(ResourceScope.Process)]
            [ResourceConsumption(ResourceScope.Process)]
            private static void CreatePipeWithSecurityAttributes(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, Native.SECURITY_ATTRIBUTES lpPipeAttributes, int nSize)
            {
                bool ret = Native.CreatePipe(out hReadPipe, out hWritePipe, lpPipeAttributes, nSize);
                if (!ret || hReadPipe.IsInvalid || hWritePipe.IsInvalid)
                {
                    throw new Win32Exception();
                }
            }

            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            private void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs)
            {
                var securityAttributesParent = new Native.SECURITY_ATTRIBUTES();
                securityAttributesParent.bInheritHandle = true;

                SafeFileHandle hTmp = null;
                try
                {

                    CreatePipeWithSecurityAttributes(out hTmp,
                                                          out childHandle,
                                                          securityAttributesParent,
                                                          0);

                    // Duplicate the parent handle to be non-inheritable so that the child process 
                    // doesn't have access. This is done for correctness sake, exact reason is unclear.
                    // One potential theory is that child process can do something brain dead like 
                    // closing the parent end of the pipe and there by getting into a blocking situation 
                    // as parent will not be draining the pipe at the other end anymore.
                    if (!Native.DuplicateHandle(new HandleRef(this, Native.GetCurrentProcess()),
                                                                       hTmp,
                                                                       new HandleRef(this, Native.GetCurrentProcess()),
                                                                       out parentHandle,
                                                                       0,
                                                                       false,
                                                                       Native.DUPLICATE_SAME_ACCESS))
                    {
                        throw new Win32Exception();
                    }
                }
                finally
                {
                    if (hTmp != null && !hTmp.IsInvalid)
                    {
                        hTmp.Close();
                    }
                }
            }
        }

        internal class Native
        {
            internal const int LOGON32_LOGON_INTERACTIVE = 2;
            internal const int LOGON32_LOGON_BATCH = 4;
            internal const int LOGON32_PROVIDER_DEFAULT = 0;

            public const int DUPLICATE_SAME_ACCESS = 2;

            public const int STARTF_USESTDHANDLES = 0x00000100;
            public const int STARTF_USESHOWWINDOW = 0x00000001;
            public const int CREATE_NO_WINDOW = 0x08000000;
            public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;

            [StructLayout(LayoutKind.Sequential)]
            internal class PROCESS_INFORMATION
            {     
                public IntPtr hProcess = IntPtr.Zero;
                public IntPtr hThread = IntPtr.Zero;
                public uint dwProcessId = 0;
                public uint dwThreadId = 0;
            }


            [StructLayout(LayoutKind.Sequential)]
            internal class STARTUPINFO
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public int dwX = 0;
                public int dwY = 0;
                public int dwXSize = 0;
                public int dwYSize = 0;
                public int dwXCountChars = 0;
                public int dwYCountChars = 0;
                public int dwFillAttribute = 0;
                public int dwFlags = 0;
                public short wShowWindow = 0;
                public short cbReserved2 = 0;
                public IntPtr lpReserved2 = IntPtr.Zero;
                public IntPtr hStdInput = IntPtr.Zero;
                public IntPtr hStdOutput = IntPtr.Zero;
                public IntPtr hStdError = IntPtr.Zero;

                public STARTUPINFO()
                {
                    cb = Marshal.SizeOf(this);
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal class SECURITY_ATTRIBUTES
            {
                public SECURITY_ATTRIBUTES()
                {
                    nLength = Marshal.SizeOf(this);
                }
                public int nLength;
                public IntPtr lpSecurityDescriptor = IntPtr.Zero;
                public bool bInheritHandle;
            }

            [DllImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, CharSet = CharSet.Unicode,
                CallingConvention = CallingConvention.StdCall)]
            internal static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
                int dwLogonType, int dwLogonProvider, ref IntPtr phToken);


            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto, BestFitMapping = true)]
            internal static extern bool CreateProcessAsUser(
                IntPtr hToken,
                string lpApplicationName,
                string lpCommandLine,
                SECURITY_ATTRIBUTES lpProcessAttributes,
                SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                int dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                STARTUPINFO lpStartupInfo,
                PROCESS_INFORMATION lpProcessInformation);
            
            [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto,
                CallingConvention = CallingConvention.StdCall)]
            internal static extern bool CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
            public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi, SetLastError = true, BestFitMapping = false)]
            public static extern bool DuplicateHandle(
                HandleRef hSourceProcessHandle,
                SafeHandle hSourceHandle,
                HandleRef hTargetProcess,
                out SafeFileHandle targetHandle,
                int dwDesiredAccess,
                bool bInheritHandle,
                int dwOptions
            );

            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi, SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi, SetLastError = true)]
            public static extern IntPtr GetStdHandle(int whichHandle);
        }

    }