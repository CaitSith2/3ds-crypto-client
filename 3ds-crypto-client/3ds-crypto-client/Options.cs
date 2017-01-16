using System;
using System.Net.Mime;
using System.Text;
using CommandLine;
using CommandLine.Text;
using static System.AppDomain;

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

        [Option]
        public bool help { get; set; }

        [HelpOption]
        public string GetUsage() {
            var helptext = new HelpText
            {
                Heading = new HeadingInfo("3DS Crypto Client", "v1.0"),
                Copyright = new CopyrightInfo("CaitSith2", 2017),
                AdditionalNewLineAfterOption = true,
                AddDashesToOption = true
            };
            helptext.AddPreOptionsLine("");
            helptext.AddPreOptionsLine($"Usage: {CurrentDomain.FriendlyName} options [--help for more information]");

            if(help)
                helptext.AddOptions(this);
            return helptext;
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
