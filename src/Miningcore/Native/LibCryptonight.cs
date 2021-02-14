
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Miningcore.Contracts;
using System.Linq;
using NLog;
using System.Text;

namespace Miningcore.Native
{
    public static unsafe class LibCryptonight
    {
        
        internal class CryptonightContextStore
        {
            internal CryptonightContextStore(Func<IntPtr> allocator, string logId)
            {
                this.logId = logId.ToUpper();

                // allocate context per CPU
                for(var i = 0; i < contexts.BoundedCapacity; i++)
                {
                    contexts.Add(new Lazy<IntPtr>(() =>
                    {
                        var result = allocator();

                        return result;
                    }));
                }
            }

            private readonly string logId;

            // this holds a finite number of contexts for the cryptonight hashing functions
            // if no context is currently available because all are in use, the thread waits
            private readonly BlockingCollection<Lazy<IntPtr>> contexts = new BlockingCollection<Lazy<IntPtr>>(Environment.ProcessorCount);

            internal Lazy<IntPtr> Lease()
            {
                logger.Debug(() => $"Leasing {logId} context ({contexts.Count})");

                return contexts.Take();
            }

            internal void Return(Lazy<IntPtr> ctx)
            {
                contexts.Add(ctx);

                logger.Debug(() => $"Returned {logId} context ({contexts.Count})");
            }
        }

        private static readonly CryptonightContextStore ctxs = new CryptonightContextStore(cryptonight_alloc_context, "cn");
        private static readonly CryptonightContextStore ctxsLite = new CryptonightContextStore(cryptonight_alloc_lite_context, "cn-lite");
        private static readonly CryptonightContextStore ctxsHeavy = new CryptonightContextStore(cryptonight_alloc_heavy_context, "cn-heavy");
        private static readonly CryptonightContextStore ctxsPico = new CryptonightContextStore(cryptonight_alloc_pico_context, "cn-pico");
        //private static readonly CryptonightContextStore ctxsRandomX = new CryptonightContextStore(cryptonight_alloc_randomx_context, "cn-randomx");

        // RandomX
        private static IntPtr randomxVm;
        private static readonly Dictionary<string, IntPtr> randomxVmCacheCache = new Dictionary<string, IntPtr>();



        // Enable logger logging
        private static readonly ILogger logger = LogManager.GetCurrentClassLogger();


        [DllImport("libcryptonight", EntryPoint = "cryptonight_alloc_context_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr cryptonight_alloc_context();

        [DllImport("libcryptonight", EntryPoint = "cryptonight_alloc_lite_context_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr cryptonight_alloc_lite_context();

        [DllImport("libcryptonight", EntryPoint = "cryptonight_alloc_heavy_context_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr cryptonight_alloc_heavy_context();

        [DllImport("libcryptonight", EntryPoint = "cryptonight_alloc_pico_context_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr cryptonight_alloc_pico_context();

        [DllImport("libcryptonight", EntryPoint = "cryptonight_free_context_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void cryptonight_free_context(IntPtr ptr);



        [DllImport("libcryptonight", EntryPoint = "cryptonight_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int cryptonight(IntPtr ctx, byte* input, byte* output, uint inputLength, CryptonightVariant variant, ulong height);

        [DllImport("libcryptonight", EntryPoint = "cryptonight_light_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int cryptonight_light(IntPtr ctx, byte* input, byte* output, uint inputLength, CryptonightVariant variant, ulong height);

        [DllImport("libcryptonight", EntryPoint = "cryptonight_heavy_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int cryptonight_heavy(IntPtr ctx, byte* input, byte* output, uint inputLength, CryptonightVariant variant, ulong height);

        [DllImport("libcryptonight", EntryPoint = "cryptonight_pico_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int cryptonight_pico(IntPtr ctx, byte* input, byte* output, uint inputLength, CryptonightVariant variant, ulong height);




        //[DllImport("libcryptonight", EntryPoint = "cryptonight_alloc_randomx_context_export", CallingConvention = CallingConvention.Cdecl)]
        //private static extern IntPtr cryptonight_alloc_randomx_context();


        [DllImport("libcryptonight", EntryPoint = "randomx_create_vm_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr randomx_create_vm(IntPtr cache);

        [DllImport("libcryptonight", EntryPoint = "randomx_free_vm_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_free_vm(IntPtr vm);

        [DllImport("libcryptonight", EntryPoint = "randomx_create_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr randomx_create_cache(int variant, byte* seedHash, uint seedHashSize);

        [DllImport("libcryptonight", EntryPoint = "randomx_free_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_free_cache(IntPtr cache);

        [DllImport("libcryptonight", EntryPoint = "randomx_set_vm_cache_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern void randomx_set_vm_cache(IntPtr vm, IntPtr cache);

        [DllImport("libcryptonight", EntryPoint = "randomx_export", CallingConvention = CallingConvention.Cdecl)]
        private static extern int randomx(IntPtr ctx, byte* input, byte* output, uint inputLength, CryptonightVariant variant, ulong height);




        public delegate void CryptonightHash(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, CryptonightVariant variant, ulong height);





        // see https://github.com/xmrig/xmrig/blob/master/src/common/xmrig.h
        public enum CryptonightVariant
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

        /// <summary>
        /// Cryptonight Hash (Monero, Monero v7, v8 etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void Cryptonight(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, CryptonightVariant variant, ulong height)
        {
            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            var ctx = ctxs.Lease();

            try
            {
                fixed (byte* input = data)
                {
                    fixed (byte* output = result)
                    {
                        cryptonight(ctx.Value, input, output, (uint) data.Length, variant, height);
                    }
                }
            }

            finally
            {
                ctxs.Return(ctx);
            }
        }

        /// <summary>
        /// Cryptonight Lite Hash (AEON etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void CryptonightLight(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, CryptonightVariant variant, ulong height)
        {
            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            var ctx = ctxsLite.Lease();

            try
            {
                fixed (byte* input = data)
                {
                    fixed (byte* output = result)
                    {
                        cryptonight_light(ctx.Value, input, output, (uint) data.Length, variant, height);
                    }
                }
            }

            finally
            {
                ctxsLite.Return(ctx);
            }
        }

        /// <summary>
        /// Cryptonight Heavy Hash (TUBE etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void CryptonightHeavy(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, CryptonightVariant variant, ulong height)
        {
            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            var ctx = ctxsHeavy.Lease();

            try
            {
                fixed (byte* input = data)
                {
                    fixed (byte* output = result)
                    {
                        cryptonight_heavy(ctx.Value, input, output, (uint) data.Length, variant, height);
                    }
                }
            }

            finally
            {
                ctxsHeavy.Return(ctx);
            }
        }

        /// <summary>
        /// Cryptonight Pico Hash (TUBE etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void CryptonightPico(ReadOnlySpan<byte> data, Span<byte> result, CryptonightVariant variant, ulong height)
        {
            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            var ctx = ctxsPico.Lease();

            try
            {
                fixed (byte* input = data)
                {
                    fixed (byte* output = result)
                    {
                        cryptonight_pico(ctx.Value, input, output, (uint) data.Length, variant, height);
                    }
                }
            }

            finally
            {
                ctxsPico.Return(ctx);
            }
        }

        /// <summary>
        /// Cryptonight Hash (Monero, Monero v7, v8 etc.)
        /// </summary>
        /// <param name="variant">Algorithm variant</param>
        public static void RandomX(ReadOnlySpan<byte> data, string seedHash, Span<byte> result, CryptonightVariant variant, ulong height)
        {
            Console.WriteLine("RandomX Lib");

            Contract.Requires<ArgumentException>(result.Length >= 32, $"{nameof(result)} must be greater or equal 32 bytes");

            lock(randomxVmCacheCache)
            {
                if(!randomxVmCacheCache.TryGetValue(seedHash, out var cache))
                {
                    // Housekeeping
                    while(randomxVmCacheCache.Count + 1 > 8)
                    {
                        var key = randomxVmCacheCache.Keys.First(x => x != seedHash);
                        var old = randomxVmCacheCache[key];

                        randomx_free_cache(old);
                        randomxVmCacheCache.Remove(key);
                    }

                    var seedBytes = Encoding.UTF8.GetBytes(seedHash);

                    // Create new VM
                    fixed(byte* seedBytesPtr = seedBytes)
                    {
                        cache = randomx_create_cache((int) variant, seedBytesPtr, (uint) seedBytes.Length);
                    }

                    randomxVmCacheCache[seedHash] = cache;
                }

                if(randomxVm == IntPtr.Zero)
                    randomxVm = randomx_create_vm(cache);
                else
                    randomx_set_vm_cache(randomxVm, cache);

                fixed(byte* input = data)
                {
                    fixed(byte* output = result)
                    {
                        randomx(randomxVm, input, output, (uint) data.Length, variant, height);
                    }
                }
            }



        }


    }
}
