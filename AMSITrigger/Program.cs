using NDesk.Options;

using System;
using System.Diagnostics;
using System.IO;

namespace AmsiTrigger
{
    using static Globals;

    public static class Globals
    {
        public static int MinSignatureLength { get; set; } = 6;       // Playing with these can result in quicker execution time and less AMSIScanBuffer calls. It can also reduce the accuracy of trigger identification.
        public static int MaxSignatureLength { get; set; } = 2048;    // Setting maxSignatureLength will ensure that signatures split over data chunks dont get missed as only the first (chunkSize - maxSignatureLength) will be reported as clean
        public static int ChunkSize { get; set; } = 4096;
        public static bool Help { get; set; } = false;
        public static string FilePath { get; set; }
        public static string FileUrl { get; set; }
        public static int AmsiCalls { get; set; } = 0;
        public static int ChunksProcessed { get; set; } = 0;
        public static bool IsMalicious { get; set; } = false;
        public static int ThreatsFound { get; set; } = 0;
    }

    class Program
    {
        static void Main(string[] args)
        {
            Helpers.PrintLogo();

            if (!ValidParameters(args))
            {
                return;
            }

#if DEBUG
            CustomConsole.WriteDebug("Debug mode enabled");
            CustomConsole.WriteDebug($"Chunk Size: {ChunkSize}");
            CustomConsole.WriteDebug($"Max Sig Length: {MaxSignatureLength}");
#endif

            var watch = Stopwatch.StartNew();

            using (var amsi = new AmsiInstance())
            {
                if (!amsi.IsProtectionEnabled)
                {
                    CustomConsole.WriteError("Ensure Real-time Protection is enabled");
                    return;
                }

                amsi.FindTriggers();

                if (IsMalicious && ThreatsFound == 0)
                {
                    CustomConsole.WriteError("File is malicious, but could not find individual threat(s). Modify MaxSigLength and/or ChunkSize to finesse the detections.");
                }
            }

            watch.Stop();

#if DEBUG
            CustomConsole.WriteDebug($"Chunks Processed: {ChunksProcessed}");
            CustomConsole.WriteDebug($"Threats Found: {ThreatsFound}");
            CustomConsole.WriteDebug($"AmsiScanBuffer Calls: {AmsiCalls}");
            CustomConsole.WriteDebug($"Total Execution Time: {Math.Round(watch.Elapsed.TotalSeconds, 2)}s");
#endif
        }

        public static bool ValidParameters(string[] args)
        {
            var options = new OptionSet()
            {
                {"i|inputfile=", "Path to a file on disk", o => FilePath = o},
                {"u|url=", "URL eg. https://10.1.1.1/Invoke-NinjaCopy.ps1", o => FileUrl = o},
                {"m|maxsiglength=","Maximum Signature Length to cater for, default=2048", (int o) => MaxSignatureLength = o},
                {"c|chunksize=","Chunk size to send to AMSIScanBuffer, default=4096", (int o) => ChunkSize = o},
                {"h|?|help","Show Help", o => Help = true},
            };

            try
            {
                options.Parse(args);

                if (Help || args.Length == 0)
                {
                    ShowHelp(options);
                    return false;
                }
            }
            catch (Exception e)
            {
                CustomConsole.WriteError(e.Message);
                ShowHelp(options);
                return false;
            }

            if (!string.IsNullOrEmpty(FilePath) && !string.IsNullOrEmpty(FileUrl))
            {
                CustomConsole.WriteError("Supply either -i or -u, not both");
                return false;
            }

            if (!string.IsNullOrEmpty(FileUrl) && !FileUrl.Substring(0, 7).Equals("http://", StringComparison.OrdinalIgnoreCase) && !FileUrl.Substring(0, 8).Equals("https://", StringComparison.OrdinalIgnoreCase))
            {
                CustomConsole.WriteError("Invalid URL - must begin with http:// or https://");
                return false;
            }

            if (ChunkSize < MaxSignatureLength)
            {
                CustomConsole.WriteError("chunksize should always be > maxSignatureLength");
                return false;
            }

            if (!string.IsNullOrEmpty(FilePath) && !File.Exists(FilePath))
            {
                CustomConsole.WriteError("File not found");
                return false;
            }

            return true;
        }

        public static void ShowHelp(OptionSet p)
        {
            p.WriteOptionDescriptions(Console.Out);
        }
    }
}