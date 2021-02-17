using Miningcore.Contracts;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Miningcore.Native
{
    public static unsafe class RandomX
    {

        // RandomX
        private static IntPtr randomxVm;
        private static readonly Dictionary<string, IntPtr> randomxVmCacheCache = new Dictionary<string, IntPtr>();

        // Enable logger logging
        private static readonly ILogger logger = LogManager.GetCurrentClassLogger();


        public enum RandomXVariant
        {
            VARIANT_AUTO = -1, // Autodetect
            VARIANT_0 = 0,  // Original CryptoNight or CryptoNight-Heavy
            VARIANT_1 = 1,  // CryptoNight variant 1 also known as Monero7 and CryptoNightV7
            VARIANT_TUBE = 2,  // Modified CryptoNight-Heavy (TUBE only)
            VARIANT_XTL = 3,  // Modified CryptoNight variant 1 (Stellite only)
            VARIANT_MSR = 4,  // Modified CryptoNight variant 1 (Masari only)
            VARIANT_XHV = 5,  // Modified CryptoNight-Heavy (Haven Protocol only)
            VARIANT_XAO = 6,  // Modified CryptoNight variant 0 (Alloy only)
            VARIANT_RTO = 7,  // Modified CryptoNight variant 1 (Arto only)
            VARIANT_2 = 8,  // CryptoNight variant 2
            VARIANT_HALF = 9,  // CryptoNight variant 2 with half iterations (Masari/Stellite)
            VARIANT_TRTL = 10, // CryptoNight Turtle (TRTL)
            VARIANT_GPU = 11, // CryptoNight-GPU (Ryo)
            VARIANT_WOW = 12, // CryptoNightR (Wownero)
            VARIANT_4 = 13, // CryptoNightR (Monero's variant 4)
            VARIANT_RWZ = 14, // CryptoNight variant 2 with 3/4 iterations and reversed shuffle operation (Graft)
            VARIANT_ZLS = 15, // CryptoNight variant 2 with 3/4 iterations (Zelerius)
            VARIANT_DOUBLE = 16, // CryptoNight variant 2 with double iterations (X-CASH)
            VARIANT_MAX
        };



        [DllImport("librandomx", EntryPoint = "randomx_create_vm_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr randomx_create_vm(IntPtr cache);

        [DllImport("librandomx", EntryPoint = "randomx_free_vm_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_free_vm(IntPtr vm);

        [DllImport("librandomx", EntryPoint = "randomx_create_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr randomx_create_cache(int variant, byte* seedHash, uint seedHashSize);

        [DllImport("librandomx", EntryPoint = "randomx_free_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_free_cache(IntPtr cache);

        [DllImport("librandomx", EntryPoint = "randomx_set_vm_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_set_vm_cache(IntPtr vm, IntPtr cache);

        [DllImport("librandomx", EntryPoint = "randomx_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int randomx(IntPtr ctx, byte* input, byte* output, uint inputLength, RandomXVariant variant, ulong height);


        /// <summary>
        /// Cryptonight Hash (Monero, Monero v7, v8 etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void RandomX(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, RandomXVariant variant, ulong height)
        {
            Console.WriteLine("RandomX Lib");

            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            //lock(randomxVmCacheCache)
            //{
            if(!randomxVmCacheCache.TryGetValue(seedHash, out var cache))
            {
                // Housekeeping
                while(randomxVmCacheCache.Count + 1 > 8)
                {
                    Console.WriteLine("randomxVmCacheCache");

                    var key = randomxVmCacheCache.Keys.First(x => x != seedHash);

                    Console.WriteLine($"Key: {key}");

                    var old = randomxVmCacheCache[key];

                    //randomx_free_cache(old);
                    //randomxVmCacheCache.Remove(old);
                }

                var seedBytes = Encoding.UTF8.GetBytes(seedHash);
                Console.WriteLine($"seecBytes: {seedBytes}");
                // Create new VM
                fixed(byte* seedBytesPtr = seedBytes)
                {
                    Console.WriteLine("randomx_create_cache");
                    cache = randomx_create_cache((int) variant, seedBytesPtr, (uint) seedBytes.Length);
                }

                randomxVmCacheCache[seedHash] = cache;
            }

            if(randomxVm == IntPtr.Zero)
            {
                Console.WriteLine("randomx_create_cache");
                randomxVm = randomx_create_vm(cache);
            }
            else
            {
                Console.WriteLine("randomx_create_cache");
                randomx_set_vm_cache(randomxVm, cache);
            }


            fixed(byte* input = data)
            {
                fixed(byte* output = result)
                {
                    randomx(randomxVm, input, output, (uint) data.Length, variant, height);
                }
            }
            //}



        }


    }
}
