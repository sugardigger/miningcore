using Newtonsoft.Json;

namespace Miningcore.Blockchain.Cryptonote.StratumResponses
{
    public class CryptonoteJobParams
    {
        [JsonProperty("job_id")]
        public string JobId { get; set; }

        public string Blob { get; set; }
        public string Target { get; set; }

        // Introduced for CNv4 (aka CryptonightR)
        public ulong Height { get; set; }

        // Introduced for RandomX 
        [JsonProperty("seed_hash")]
        public string SeedHash { get; set; }
    }

    public class CryptonoteLoginResponse : CryptonoteResponseBase
    {
        public string Id { get; set; }
        public CryptonoteJobParams Job { get; set; }
    }
}
