// NB-0101: single-file same-volume no-clobber rename by a verified Windows handle.
// Called only by the locally scoped guard; no shell, deletion, or cross-volume copying.
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;

internal static class FileMove {
    const uint READ_ATTR=0x80, GENERIC_READ=0x80000000, DELETE=0x10000, SHARE_READ=1;
    const uint OPEN_EXISTING=3, BACKUP_SEMANTICS=0x02000000, OPEN_REPARSE=0x00200000, DIRECTORY=0x10, REPARSE=0x400;
    const long MAX_BYTES=4*1024*1024;
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct RenameHeader { public uint Flags;public IntPtr RootDirectory;public uint FileNameLength;public char FirstChar; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int cls,IntPtr buffer,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,IntPtr buffer,uint size);
    static void Check(bool ok,string where){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),where);}
    static string Canonical(string p){
        if(p.Length>1024||!Regex.IsMatch(p,@"^[A-Za-z]:\\")||p.Substring(2).Contains(":")||p.Contains("/")||p.IndexOf('\0')>=0)throw new ArgumentException("Local absolute path required");
        string normalized=Path.GetFullPath(p);
        if(!String.Equals(p,normalized,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Non-canonical path");
        foreach(string c in p.Substring(3).Split('\\')){
            if(c.Length==0||c=="."||c==".."||c.EndsWith(".")||c.EndsWith(" ")||c.IndexOfAny(Path.GetInvalidFileNameChars())>=0||Regex.IsMatch(c,@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)",RegexOptions.IgnoreCase))throw new ArgumentException("Unsafe path component");
        }
        return p;
    }
    static string FinalName(SafeFileHandle h){
        StringBuilder b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);
        Check(n>0&&n<b.Capacity,"GetFinalPathNameByHandle");
        string p=b.ToString();if(!p.StartsWith(@"\\?\",StringComparison.Ordinal)||p.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase))throw new IOException("Non-local final path");
        return p.Substring(4);
    }
    static Info Verify(SafeFileHandle h,string expected,bool directory){
        Check(!h.IsInvalid,"CreateFile");
        Info i;Check(GetFileInformationByHandle(h,out i),"GetFileInformationByHandle");
        if((i.Attributes&REPARSE)!=0||((i.Attributes&DIRECTORY)!=0)!=directory||
            !String.Equals(FinalName(h).TrimEnd('\\'),expected.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("Object identity or reparse boundary");
        return i;
    }
    static SafeFileHandle PinDirectory(string p,List<SafeFileHandle> pins){
        SafeFileHandle h=CreateFileW(p,READ_ATTR,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,BACKUP_SEMANTICS|OPEN_REPARSE,IntPtr.Zero);
        try{Verify(h,p,true);pins.Add(h);return h;}catch{h.Dispose();throw;}
    }
    static SafeFileHandle PinAncestors(string path,List<SafeFileHandle> pins){
        string drive=Path.GetPathRoot(path),dir=Path.GetDirectoryName(path),cur=drive;
        SafeFileHandle result=PinDirectory(cur,pins);
        string tail=dir.Substring(drive.Length);
        if(tail.Length==0)return result;
        foreach(string c in tail.Split('\\')){cur=Path.Combine(cur,c);result=PinDirectory(cur,pins);}
        return result;
    }
    static void OnlyDefaultStream(SafeFileHandle h){
        IntPtr b=Marshal.AllocHGlobal(65536);
        try{
            Check(GetFileInformationByHandleEx(h,7,b,65536),"FileStreamInfo");
            int next=Marshal.ReadInt32(b),len=Marshal.ReadInt32(b,4);
            if(next!=0||len!=14||Marshal.PtrToStringUni(IntPtr.Add(b,24),len/2)!="::$DATA")throw new IOException("Alternate data streams denied");
        }finally{Marshal.FreeHGlobal(b);}
    }
    static string Hash(SafeFileHandle h){
        using(var stream=new FileStream(new SafeFileHandle(h.DangerousGetHandle(),false),FileAccess.Read,4096,false))
        using(var sha=SHA256.Create()){return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
    }
    static int Run(string[] args){
        if(args.Length!=3||!Regex.IsMatch(args[2],"^[a-f0-9]{64}$"))throw new ArgumentException("Expected source, destination and digest");
        string source=Canonical(args[0]),dest=Canonical(args[1]);
        if(String.Equals(source,dest,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Same path");
        var pins=new List<SafeFileHandle>();
        try{
            PinAncestors(source,pins);SafeFileHandle parent=PinAncestors(dest,pins);Info target;Check(GetFileInformationByHandle(parent,out target),"Target directory");
            using(var h=CreateFileW(source,GENERIC_READ|DELETE,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE,IntPtr.Zero)){
                Info original=Verify(h,source,false);long size=((long)original.SizeHigh<<32)|original.SizeLow;
                if(original.Links!=1||size<0||size>MAX_BYTES||original.Volume!=target.Volume)throw new IOException("Link, size or volume denied");
                OnlyDefaultStream(h);
                if(Hash(h)!=args[2])throw new IOException("Digest mismatch");
                byte[] name=Encoding.Unicode.GetBytes(dest);
                int fileOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"FirstChar"),rootOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"RootDirectory"),lengthOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"FileNameLength");
                int sizeBuffer=Math.Max(Marshal.SizeOf(typeof(RenameHeader)),fileOffset+name.Length+2);IntPtr buf=Marshal.AllocHGlobal(sizeBuffer);
                try{
                    for(int i=0;i<sizeBuffer;i++)Marshal.WriteByte(buf,i,0);
                    Marshal.WriteIntPtr(buf,rootOffset,IntPtr.Zero);Marshal.WriteInt32(buf,lengthOffset,name.Length);Marshal.Copy(name,0,IntPtr.Add(buf,fileOffset),name.Length);
                    // Flags/ReplaceIfExists remains zero. Kernel checks destination conflict.
                    Check(SetFileInformationByHandle(h,3,buf,(uint)sizeBuffer),"FileRenameInfo");
                }finally{Marshal.FreeHGlobal(buf);}
                Info after=Verify(h,dest,false);
                if(after.Volume!=original.Volume||after.IndexHigh!=original.IndexHigh||after.IndexLow!=original.IndexLow||after.Links!=1)throw new IOException("Unknown rename outcome");
                Console.WriteLine("MOVE_OK");return 0;
            }
        }finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    public static int Main(string[] args){
        try{return Run(args);}catch(Win32Exception e){Console.Error.WriteLine("Native move refused or outcome unknown: "+e.Message+" ("+e.NativeErrorCode+")");return 126;}catch(Exception e){Console.Error.WriteLine("Native move refused or outcome unknown: "+e.GetType().Name);return 126;}
    }
}
