using System;
using System.Net;
using System.Net.Mime;
using System.Text;
using System.Xml.Serialization;
using CommandLine;
using CommandLine.Text;
using static System.AppDomain;

namespace _3ds_crypto_client {
    [XmlRoot("Program_Settings")]
    public class Options {
        [XmlElement("IP_Address")]
        [Option("ip", HelpText = "The IP address of the 3DS running the crypto server.", Required = false)]
        public string InputIP { get; set; }

        [XmlElement("Keep_Logs")]
        [Option("keep_log",HelpText = "Keep log files of the operations performed")]
        public KeepLogSetting KeepLog { get; set; }

        [XmlIgnore]
        [Option('i',"input",HelpText = "The Input file.", Required = true)]
        public string InputFile { get; set; }

        [XmlIgnore]
        [Option('o',"output", HelpText = "The output file. If output file is not specified, The filename will be based on operation performed.", Required = false)]
        public string OutputFile { get; set; }

        [XmlIgnore]
        [Option('m',"mode",HelpText = "The Operation to be performed", Required = true)]
        public CryptoOperation Mode { get; set; }

        [XmlIgnore]
        [Option]
        public bool help { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            var helptext = new HelpText
            {
                Heading = Program.heading,
                Copyright = Program.copyright,
                AdditionalNewLineAfterOption = true,
                AddDashesToOption = true,
                MaximumDisplayWidth = Console.WindowWidth
            };
            helptext.AddPreOptionsLine("");
            helptext.AddPreOptionsLine($"Usage: {CurrentDomain.FriendlyName} options [--help for more information]");

            if (help)
                helptext.AddOptions(this);
            return helptext;
        }

        public Options GetSettings()
        {
            var settings = Util.DeserializeFile<Options>("settings.xml")
                           ?? new Options
                           {
                               InputIP = "192.168.1.137",
                               KeepLog = KeepLogSetting.Always
                           };
            IPAddress ip_temp;
            if (!string.IsNullOrEmpty(InputIP) && IPAddress.TryParse(InputIP, out ip_temp))
                settings.InputIP = InputIP;
            if (KeepLog != KeepLogSetting.Settings)
                settings.KeepLog = KeepLog;

            settings.InputFile = InputFile;
            settings.OutputFile = OutputFile;
            settings.Mode = Mode;

            Util.Serialize(settings, "settings.xml");
            return settings;
        }
    }

    public enum KeepLogSetting
    {
        Settings,
        Never,
        ExceptionsOnly,
        Always,
    }

    public enum CryptoOperation
    {
        EncryptTitleKeys,
        DecryptTitleKeys,
        EncryptBOSS,
        DecryptBOSS,
    }
}
