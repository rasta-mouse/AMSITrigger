using System;
using System.IO;
using System.Net;
using System.Text;

namespace AmsiTrigger
{
    using static NativeMethods;
    using static Globals;

    class AmsiInstance : IDisposable
    {
        IntPtr amsiContext;

        byte[] fullSample;
        byte[] chunkSample;
        int triggerStart = 0;
        int triggerEnd;
        int startIndex = 0;

        public AmsiInstance()
        {
            AmsiInitialize(@"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.18362.1", out amsiContext);
        }

        public void FindTriggers()
        {
            if (!string.IsNullOrEmpty(FilePath))
            {
                fullSample = File.ReadAllBytes(FilePath);
            }
            else
            {
                try
                {
                    using (var client = new WebClient())
                    {
                        fullSample = client.DownloadData(FileUrl);
                    }
                }
                catch (Exception e)
                {
                    CustomConsole.WriteError(e.Message);
                    return;
                }
            }

            CustomConsole.WriteOutput($"Scanning input: {fullSample.Length} bytes");
            var result = ScanBuffer(fullSample);

            if (result != AMSI_RESULT.AMSI_RESULT_DETECTED)
            {
                CustomConsole.WriteOutput("No threats found");
                return;
            }
            else
            {
                IsMalicious = true;
            }

            while (startIndex + ChunkSize < fullSample.Length)
            {
                chunkSample = new byte[ChunkSize];
                Array.Copy(fullSample, startIndex, chunkSample, 0, ChunkSize);

                ProcessChunk(chunkSample);
            }

            while (startIndex < fullSample.Length)
            {
                chunkSample = new byte[fullSample.Length - startIndex];
                Array.Copy(fullSample, startIndex, chunkSample, 0, chunkSample.Length);
                ProcessChunk(chunkSample);
            }
        }

        void ProcessChunk(byte[] chunkSample)
        {
            ChunksProcessed++;

            var result = ScanBuffer(chunkSample);

            if (result != AMSI_RESULT.AMSI_RESULT_DETECTED)
            {
                if (chunkSample.Length > MaxSignatureLength)
                {
                    startIndex += ChunkSize - MaxSignatureLength;
                }
                else
                {
                    startIndex += chunkSample.Length;
                }

                return;
            }

            triggerEnd = FindTriggerEnd() + 1;
            triggerStart = FindTriggerStart(triggerEnd);

            ThreatsFound++;

            HexDump(chunkSample, triggerStart, triggerEnd - triggerStart);

            startIndex += triggerEnd;

            return;
        }

        int FindTriggerEnd()
        {
            for (int sampleIndex = 2; sampleIndex < chunkSample.Length + MinSignatureLength; sampleIndex += MinSignatureLength)
            {
                if (sampleIndex > chunkSample.Length)
                {
                    sampleIndex = chunkSample.Length;
                }

                var tmpSample = new byte[sampleIndex];
                Array.Copy(chunkSample, 0, tmpSample, 0, sampleIndex);

                var result = ScanBuffer(tmpSample);

                if (result == AMSI_RESULT.AMSI_RESULT_DETECTED)
                {
                    int lastBytes;

                    for (lastBytes = 0; lastBytes < MinSignatureLength; lastBytes++)
                    {
                        tmpSample = new byte[sampleIndex - lastBytes];
                        Array.Copy(chunkSample, 0, tmpSample, 0, sampleIndex - lastBytes);
                        result = ScanBuffer(tmpSample);

                        if (result != AMSI_RESULT.AMSI_RESULT_DETECTED)
                        {
                            return sampleIndex - lastBytes;
                        }
                    }

                    return sampleIndex - lastBytes;
                }
            }

            return 0;
        }

        int FindTriggerStart(int triggerEnd)
        {
            for (int sampleIndex = triggerEnd - 1; sampleIndex > 0; sampleIndex--)
            {
                var tmpSample = new byte[triggerEnd - sampleIndex];
                Array.Copy(chunkSample, sampleIndex, tmpSample, 0, triggerEnd - sampleIndex);
                
                var result = ScanBuffer(tmpSample);

                if (result == AMSI_RESULT.AMSI_RESULT_DETECTED)
                {
                    return sampleIndex;
                }
            }

            return 0;
        }

        public void HexDump(byte[] sample, int start, int length)
        {
            var bytesPerLine = 16;

            var tmpSample = new byte[length];
            Array.Copy(sample, start, tmpSample, 0, length);

            var hexChars = "0123456789ABCDEF".ToCharArray();

            var firstHexColumn =
                  8                     // 8 characters for the address
                + 3;                    // 3 spaces

            var firstCharColumn = firstHexColumn
                + bytesPerLine * 3                  // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8            // - 1 extra space every 8 characters from the 9th
                + 2;                                // 2 spaces 

            var lineLength = firstCharColumn
                + bytesPerLine                      // - characters to show the ascii value
                + Environment.NewLine.Length;       // Carriage return and line feed (should normally be 2)

            var line = (new string(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            var expectedLines = (length + bytesPerLine - 1) / bytesPerLine;
            var result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < length; i += bytesPerLine)
            {
                line[0] = hexChars[(i >> 28) & 0xF];
                line[1] = hexChars[(i >> 24) & 0xF];
                line[2] = hexChars[(i >> 20) & 0xF];
                line[3] = hexChars[(i >> 16) & 0xF];
                line[4] = hexChars[(i >> 12) & 0xF];
                line[5] = hexChars[(i >> 8) & 0xF];
                line[6] = hexChars[(i >> 4) & 0xF];
                line[7] = hexChars[(i >> 0) & 0xF];

                var hexColumn = firstHexColumn;
                var charColumn = firstCharColumn;

                for (var j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= length)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        var b = tmpSample[i + j];

                        line[hexColumn] = hexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = hexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }

                    hexColumn += 3;
                    charColumn++;
                }

                result.Append(line);
            }

            CustomConsole.WriteThreat(result.ToString());
        }

        AMSI_RESULT ScanBuffer(byte[] sample)
        {
            AmsiScanBuffer(amsiContext, sample, (uint)sample.Length, "Sample", IntPtr.Zero, out AMSI_RESULT result);
            AmsiCalls++;
            return result;
        }

        public bool IsProtectionEnabled
        {
            get
            {
                var sample = Encoding.UTF8.GetBytes("Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'");
                var result = ScanBuffer(sample);

                if (result == AMSI_RESULT.AMSI_RESULT_NOT_DETECTED)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
        }

        public void Dispose()
        {
            AmsiUninitialize(amsiContext);
        }
    }
}