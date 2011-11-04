using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.IO;
namespace partial_zip
{
    class Program
    {
        unsafe static void Main(string[] args)
        {

            string url = "http://appldnld.apple.com/iPhone4/061-9858.20101122.Er456/iPhone3,1_4.2.1_8C148_Restore.ipsw";
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
            byte[] data = Encoding.Unicode.GetBytes(new StreamReader(res.GetResponseStream(),Encoding.Unicode).ReadToEnd());            
            int sigLoc = FindPattern(data,BitConverter.GetBytes(0x06054b50));            
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
            req.AddRange(offsetOfCD, offsetOfCD + sizeOfCD -1);
            res = (HttpWebResponse)req.GetResponse();
            data = Encoding.Unicode.GetBytes(new StreamReader(res.GetResponseStream(),Encoding.Unicode).ReadToEnd());            

            rdr = new BinaryReader(new MemoryStream(data), Encoding.Unicode);

            int cdSig = rdr.ReadInt32();
            int version = rdr.ReadInt16();
            int verNeedExtract = rdr.ReadInt16();
            int bitFlag = rdr.ReadInt16();
            int compMethod = rdr.ReadInt16();
            int flmt = rdr.ReadInt16();
            int flmd = rdr.ReadInt16();
            int crc32 = rdr.ReadInt32();
            int compSize = rdr.ReadInt32();
            int unCompSize = rdr.ReadInt32();
            int fNameLength = rdr.ReadInt16();
            int eFLength = rdr.ReadInt16();
            int fCl = rdr.ReadInt16();
            int diskNo = rdr.ReadInt16();
            int intFile = rdr.ReadInt16();
            int extFile = rdr.ReadInt32();
            int offSetLocalFileHeader = rdr.ReadInt32();


            Console.Read();
        }
                
        static int FindPattern(byte[] data, byte[] pattern)
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
