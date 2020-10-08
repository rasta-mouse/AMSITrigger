using System;

namespace AmsiTrigger
{
    static class CustomConsole
    {
        public static void WriteOutput(string output)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Out.WriteLine($" [+] {output}");
            Console.ResetColor();
        }

        public static void WriteError(string error)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine($" [!] {error}");
            Console.ResetColor();
        }

        public static void WriteDebug(string debug)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Out.WriteLine($" [*] {debug}");
            Console.ResetColor();
        }

        public static void WriteThreat(string threat)
        {
            WriteError("Threat found!");

            if (!string.IsNullOrEmpty(threat))
            {
                Console.Out.WriteLine(threat);
            }
        }
    }
}