using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace CSharpAPI
{
    class Program
    {
        //const string REMOTE_APPLAYER_NAME = "127.0.0.1:80";
        //const string DEFAULT_RECV_DIR = "R:\\";
        const string REMOTE_APPLAYER_NAME = "asus-u5f:80";
        const string DEFAULT_RECV_DIR = "D:\\";
        //const string REMOTE_APPLAYER_NAME = "lt-at4:80";
        //const string REMOTE_APPLAYER_NAME = "lt-ux31e:80";
        //const string REMOTE_APPLAYER_NAME = "E000:AAAA::1";

        static Byte[] bufPublicKey = new Byte[FSPAPI.CRYPTO_NACL_KEYBYTES];
        static Byte[] bufPrivateKey = new Byte[FSPAPI.CRYPTO_NACL_KEYBYTES];
        static Byte[] bufPeersKey = new Byte[FSPAPI.CRYPTO_NACL_KEYBYTES];
        static Byte[] bufSharedKey = new Byte[FSPAPI.CRYPTO_NACL_KEYBYTES];

        static bool finished = false;
        static Byte[] fileName = new Byte[256];
        static FileStream hFile;
        
        static void Main(string[] args)
        {
            FSP_SocketParameter context = new FSP_SocketParameter();
            context.onError = new NotifyOrReturn(onNotified);
            context.afterAccept = new CallbackConnected(onConnected);
            FSPAPI.Connect2(REMOTE_APPLAYER_NAME, ref context);
            Console.Write("Press return or any other key to exit...");
            while (!finished && !Console.KeyAvailable)
                System.Threading.Thread.Sleep(0);
        }



        public static int onNotified(IntPtr handle, FSP_ServiceCode code, int result)
        {
            Console.WriteLine("Handle = {0:X}, code = {1}, result = {2}", handle, code, result);
            return 0;
        }



        public static int onConnected(IntPtr handle, ref FSP_SocketParameter context)
        {
            Console.WriteLine("Connected, handle = {0:X}", handle);
            if(handle == (IntPtr)0)
	        {
                Console.WriteLine("Connection failed.");
		        return -1;
	        }

            if (context.len <= 0)
                goto l_nokey;

            // well, how to marshal a complicate, mixed string and byte array?
            byte[] original = new byte[1024];
            Marshal.Copy(context.welcome, original, 0, context.len);
            // we knew there must be a welcome message. 
            int mLen = Array.IndexOf<byte>(original, 0);
            if (mLen++ <= 0)
                goto l_nokey;
            // Now mLen is the number of bytes occupied by the message, including the termination '\0'
            Console.WriteLine("--- Welcome message from remote peer --- ");
            Console.WriteLine(">>>");
            Console.WriteLine(Encoding.UTF8.GetString(original, 0, mLen));
            //TODO! .GetEncoding("GBK")? ASCII!?
            Console.WriteLine("<<<");
            if(mLen >= context.len)
                goto l_nokey;

            Array.Copy(original, mLen, bufPeersKey, 0, FSPAPI.CRYPTO_NACL_KEYBYTES);

            FSPAPI.CryptoNaClKeyPair(bufPublicKey, bufPrivateKey);
            FSPAPI.CryptoNaClGetSharedSecret(bufSharedKey, bufPeersKey, bufPrivateKey);
        	FSPAPI.InstallAuthenticKey(handle, bufSharedKey, FSPAPI.CRYPTO_NACL_KEYBYTES, Int32.MaxValue, FlagEndOfMessage.NOT_END_ANYWAY);

            FSPAPI.FSPControl(handle
                , FSP_ControlCode.FSP_SET_CALLBACK_ON_ERROR
                , Marshal.GetFunctionPointerForDelegate(new NotifyOrReturn(onError2)));
            FSPAPI.WriteTo(handle, bufPublicKey, FSPAPI.CRYPTO_NACL_KEYBYTES
                , FlagEndOfMessage.END_OF_MESSAGE
                , new NotifyOrReturn(onPublicKeySent));
            return 0;

l_nokey:
            Console.Write("To read the filename directly...\t");
            if (FSPAPI.ReadFrom(handle, fileName, fileName.Length, new NotifyOrReturn(onReceiveFileNameReturn)) < 0)
            {
                finished = true;
                return -1;  // to dispose/reject the connection
            }
            return 0;
        }



        public static int onError2(IntPtr handle, FSP_ServiceCode code, int result)
        {
            Console.WriteLine("onError2: Handle = {0:X}, code = {1}, result = {2}", handle, code, result);
            FSPAPI.Dispose(handle);
            return 0;
        }


        
        public static int onPublicKeySent(IntPtr handle, FSP_ServiceCode code, int result)
        {
            Console.WriteLine("onPublicKeySent: Handle = {0:X}, code = {1}, result = {2}", handle, code, result);
            if (result < 0)
            {
                FSPAPI.Dispose(handle);
                finished = true;
                return -1;
            }

            Console.Write("To read the filename directly...\t");
            if (FSPAPI.ReadFrom(handle, fileName, fileName.Length, new NotifyOrReturn(onReceiveFileNameReturn)) < 0)
            {
                FSPAPI.Dispose(handle);
                finished = true;
                return -1;
            }

            return 0;
        }



        public static int onReceiveFileNameReturn(IntPtr handle, FSP_ServiceCode code, int result)
        {
            if (code != FSP_ServiceCode.FSP_NotifyDataReady || result < 0)
            {
                FSPAPI.Dispose(handle);
                finished = true;
                return -1;
            }

            if (result == 0)
            {
                Console.WriteLine("No filename returned. onReceiveFileNameReturn called more than once?");
                return 0;
            }

            // The byte length, result, included the terminating zero which should be excluded
            // TODO: should add some configurable work directory
            String filePath = DEFAULT_RECV_DIR + Encoding.UTF8.GetString(fileName, 0, result - 1);
            Console.WriteLine("{0}", filePath);
            try
            {  
                // TODO: exploit to GetDiskFreeSpace to take use of SECTOR size
                // _aligned_malloc
                // the client should take use of 'FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH' for ultimate integrity
                hFile = File.Create(filePath, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
                //    , GENERIC_WRITE
                //    , 0	// shared none
                //    , NULL
                //    , CREATE_NEW
                //    , FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_WRITE_THROUGH
                //    , NULL);
                //// | FILE_FLAG_NO_BUFFERING [require data block alignment which condition is too strict]
                //
                Console.WriteLine("To read content with inline buffering...");
                FSPAPI.RecvInline(handle, new CallbackPeeked(onReceiveNextBlock));
            }
            catch (Exception e)
            {
                Console.WriteLine("Unfortunately exception occured:");
                Console.WriteLine(e.Message);
                finished = true;
                FSPAPI.Dispose(handle);	// may raise second-chance exceptions?
            }

            return 0;
        }


        public static int onReceiveNextBlock(IntPtr handle
            , [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] Byte[] buf, int len, bool toBeContinued)
        {
            if (len < 0)
            {
                Console.WriteLine("FSP Internal panic? Callback on peeked return {0}", len);
                FSPAPI.Dispose(handle);
                finished = true;
                return -1;
            }

            if (len > 0)
            {
                Console.Write("{0} bytes read, to write the buffer directly...", len);
                try
                {
                    hFile.Write(buf, 0, len);
                    Console.WriteLine("done.");
                }
                catch(Exception e)
                {
                    Console.WriteLine("Error on writing file: {0}", e.Message);
                    FSPAPI.Dispose(handle);
                    finished = true;
                    return -1;
                }
            }
            else
            {
                Console.WriteLine("Receive nothing when calling the CallbackPeeked.");
            }

            if (!toBeContinued)
            {
                Console.WriteLine("All data have been received, to acknowledge...\n");
                hFile.Close();
                // Respond with a code saying no error
                int r = FSPAPI.WriteTo(handle, Encoding.ASCII.GetBytes("0000"), 4, FlagEndOfMessage.END_OF_MESSAGE, new NotifyOrReturn(onAcknowledgeSent));
                if (r < 0)
                {
                    FSPAPI.Dispose(handle);
                    finished = true;                    
                    return -1;
                }
            }

            // return a non-zero would let the occupied receive buffer free
            return 1;
        }


        // This time it is really shutdown
        public static int onAcknowledgeSent(IntPtr h, FSP_ServiceCode c, int r)
        {
            Console.WriteLine("Result of sending the acknowledgement: {0}", r);
            if (r < 0)
            {
                finished = true;
                FSPAPI.Dispose(h);
                return 0;
            }

            if (FSPAPI.Shutdown(h, new NotifyOrReturn(onShutdown)) < 0)
            {
                Console.WriteLine("Cannot shutdown gracefully in the final stage.");
                FSPAPI.Dispose(h);
                finished = true;
                return -1;
            }

            return 0;
        }
 

        public static int onShutdown(IntPtr handle, FSP_ServiceCode code, int result)
        {
            Console.WriteLine("onShutdown: Handle = {0:X}, code = {1}, result = {2}", handle, code, result);
            FSPAPI.Dispose(handle);
            return 0;
        }
    }
}
