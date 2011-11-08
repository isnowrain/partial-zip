using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
namespace partial_zip
{
    //iSn0wra1n
    class Program
    {
        unsafe static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("usage: {0} <zipurl> <path> <dest>", System.Diagnostics.Process.GetCurrentProcess().ProcessName);
                return;
            }
            string url = args[0];
            string path = args[1];
            string dest = args[2];
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "HEAD";
            HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            int zipFileLength = (int)res.ContentLength;
            int start;

            if (zipFileLength > (0xffff + 22))
                start = zipFileLength - 0xffff - 22;
            else
                start = 0;

            req = (HttpWebRequest)WebRequest.Create(url);
            req.AddRange(start, zipFileLength - 1);
            res = (HttpWebResponse)req.GetResponse();
            byte[] data = Encoding.Unicode.GetBytes(new StreamReader(res.GetResponseStream(), Encoding.Unicode).ReadToEnd());
            int sigLoc = FindPattern(data, BitConverter.GetBytes(0x06054b50));
            byte[] buf = new byte[22];
            for (int i = 0; i < 21; i++)
            {
                buf[i] = data[sigLoc + i];
            }
            BinaryReader rdr = new BinaryReader(new MemoryStream(buf), Encoding.Unicode);

            int sig = rdr.ReadInt32();
            int thisDiskNo = rdr.ReadInt16();
            int dwcds = rdr.ReadInt16();
            int cdRecordsInThisDisk = rdr.ReadInt16();
            int noOfCDRecords = rdr.ReadInt16();
            int sizeOfCD = rdr.ReadInt32();
            int offsetOfCD = rdr.ReadInt32();
            int lenZipComment = rdr.ReadInt16();

            req = (HttpWebRequest)WebRequest.Create(url);
            req.AddRange(offsetOfCD, offsetOfCD + sizeOfCD - 1);
            res = (HttpWebResponse)req.GetResponse();
            data = Encoding.Unicode.GetBytes(new StreamReader(res.GetResponseStream(), Encoding.Unicode).ReadToEnd());

            rdr = new BinaryReader(new MemoryStream(data), Encoding.Unicode);

            int[] cdSig = new int[noOfCDRecords];
            short[] version = new short[noOfCDRecords];
            short[] verNeedExtract = new short[noOfCDRecords];
            short[] bitFlag = new short[noOfCDRecords];
            short[] compMethod = new short[noOfCDRecords];
            short[] flmt = new short[noOfCDRecords];
            short[] flmd = new short[noOfCDRecords];
            int[] crc32 = new int[noOfCDRecords];
            int[] compSize = new int[noOfCDRecords];
            int[] unCompSize = new int[noOfCDRecords];
            short[] fNameLength = new short[noOfCDRecords];
            short[] eFLength = new short[noOfCDRecords];
            short[] fCl = new short[noOfCDRecords];
            short[] diskNo = new short[noOfCDRecords];
            short[] intFile = new short[noOfCDRecords];
            int[] extFile = new int[noOfCDRecords];
            int[] offSetLocalFileHeader = new int[noOfCDRecords];
            string[] fileName = new string[noOfCDRecords];
            string[] extraField = new string[noOfCDRecords];
            string[] fileComment = new string[noOfCDRecords];
            for (int i = 0; i < noOfCDRecords; i++)
            {
                cdSig[i] = rdr.ReadInt32();
                version[i] = rdr.ReadInt16();
                verNeedExtract[i] = rdr.ReadInt16();
                bitFlag[i] = rdr.ReadInt16();
                compMethod[i] = rdr.ReadInt16();
                flmt[i] = rdr.ReadInt16();
                flmd[i] = rdr.ReadInt16();
                crc32[i] = rdr.ReadInt32();
                compSize[i] = rdr.ReadInt32();
                unCompSize[i] = rdr.ReadInt32();
                fNameLength[i] = rdr.ReadInt16();
                eFLength[i] = rdr.ReadInt16();
                fCl[i] = rdr.ReadInt16();
                diskNo[i] = rdr.ReadInt16();
                intFile[i] = rdr.ReadInt16();
                extFile[i] = rdr.ReadInt32();
                offSetLocalFileHeader[i] = rdr.ReadInt32();

                byte[] temp = new byte[fNameLength[i]];
                rdr.Read(temp, 0, fNameLength[i]);
                fileName[i] = Encoding.ASCII.GetString(temp);

                if (eFLength[i] != 0)
                {
                    temp = new byte[eFLength[i]];
                    rdr.Read(temp, 0, eFLength[i]);
                    extraField[i] = Encoding.ASCII.GetString(temp);
                }
                if (fCl[i] != 0)
                {
                    temp = new byte[fCl[i]];
                    rdr.Read(temp, 0, fCl[i]);
                    fileComment[i] = Encoding.ASCII.GetString(temp);
                }
            }

            bool success = false;
            int index = 0;
            for (int i = 0; i < noOfCDRecords; i++)
            {
                if (fileName[i] == path)
                {
                    success = true;
                    index = i;
                }
            }
            if (success == false)
            {
                Console.WriteLine("Could not find '{0}' in archive", path);
                return;
            }

            start = offSetLocalFileHeader[index];
            req = (HttpWebRequest)WebRequest.Create(url);
            req.AddRange(start, start + 30 - 1);
            res = (HttpWebResponse)req.GetResponse();
            data = Encoding.Unicode.GetBytes(new StreamReader(res.GetResponseStream(), Encoding.Unicode).ReadToEnd());
            rdr = new BinaryReader(new MemoryStream(data), Encoding.Unicode);

            int signature = rdr.ReadInt32();
            short versionExtract = rdr.ReadInt16();
            short flag = rdr.ReadInt16();
            short method = rdr.ReadInt16();
            short modTime = rdr.ReadInt16();
            short modDate = rdr.ReadInt16();
            int crc = rdr.ReadInt32();
            int cSize = rdr.ReadInt32();
            int ucSize = rdr.ReadInt32();
            short lenFileName = rdr.ReadInt16();
            short lenExtraField = rdr.ReadInt16();
            //FileName
            //Extra Field
            byte[] fileData = new byte[compSize[index]];
            start = offSetLocalFileHeader[index] + 30 + lenFileName + lenExtraField;
            req = (HttpWebRequest)WebRequest.Create(url);
            req.AddRange(start, start + compSize[index] - 1);
            res = (HttpWebResponse)req.GetResponse();
            res.GetResponseStream().Read(fileData, 0, fileData.Length);
            /*
             * If bit 3 (0x08) of the general-purpose flags field is set, then the CRC-32 and file sizes are not known when the header is written. 
             * The fields in the local header are filled with zero, and the CRC-32 and size are appended in a 12-byte structure immediately after the compressed data
             */
            if (method == 0x08)
            {
                DeflateStream decompress = new DeflateStream(new MemoryStream(fileData), CompressionMode.Decompress);                
                byte[] fData = new byte[unCompSize[index]];
                decompress.Read(fData, 0, fData.Length);
                File.WriteAllBytes(dest, fData);
                Console.WriteLine("Done");
                return;
            }
            File.WriteAllBytes(dest, fileData);
            Console.WriteLine("Done");
            Console.Read();
        }

        private static int FindPattern(byte[] data, byte[] pattern)
        {
            int idx1 = 0;

            while (idx1 < data.Length)
            {
                if (data[idx1] == pattern[0])
                {
                    bool good = true;
                    for (int idx2 = 1; idx2 < pattern.Length; ++idx2)
                        if (data[idx1 + idx2] != pattern[idx2]) { good = false; break; }

                    if (good) return idx1;
                }

                ++idx1;
            }

            return -1;
        }
    }
}