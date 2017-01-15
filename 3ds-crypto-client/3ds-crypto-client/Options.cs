using System.Text;
using CommandLine;

namespace _3ds_crypto_client {
    class Options {
        [Option("ip", DefaultValue = "192.168.1.137", HelpText = "The IP address of the 3DS running the crypto server.", Required = false)]
        public string InputIP { get; set; }

        [Option('i',"input",HelpText = "The Input file.", Required = true)]
        public string InputFile { get; set; }

        [Option('o',"output",DefaultValue = "", HelpText = "The output file. If output file is not specified, The filename will be based on operation performed.", Required = false)]
        public string OutputFile { get; set; }

        [Option('m',"mode",HelpText = "The Operation to be performed", Required = true)]
        public CryptoOperation Mode { get; set; }

        [HelpOption]
        public string GetUsage() {
            var usage = new StringBuilder();
            usage.AppendLine("Quickstart Application 1.0");
            usage.AppendLine("Read user manual for usage instructions...");
            return usage.ToString();
        }
    }

    public enum CryptoOperation
    {
        EncryptTitleKeys,
        DecryptTitleKeys,
        EncryptBOSS,
        DecryptBOSS
    }
}
