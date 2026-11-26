// NB-0101: Windows native file boundary. Each component is opened relative to
// a verified, pinned directory handle. No reparse traversal or overwrite by path.
// Owner-selected roots and OS ACLs remain mandatory; this is not an elevation broker.
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
    const uint READ_ATTR=0x80, GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000, DELETE=0x10000, SHARE_READ=1;
    const uint OPEN_EXISTING=3, BACKUP_SEMANTICS=0x02000000, OPEN_REPARSE=0x00200000, DIRECTORY=0x10, REPARSE=0x400;
    const uint SYNC=0x100000,TRAVERSE=0x20,LIST_DIR=1,NT_OPEN=1,NT_CREATE=2,NT_SYNC=0x20,NT_DIR=1,NT_FILE=0x40;
    const int MAX_BYTES=4*1024*1024,MAX_ENTRIES=4096;
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct RenameHeader { public uint Flags;public IntPtr RootDirectory;public uint FileNameLength;public char FirstChar; }
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length,MaximumLength;public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length;public IntPtr RootDirectory,ObjectName;public uint Attributes;public IntPtr SecurityDescriptor,SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status;public UIntPtr Information; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int cls,IntPtr buffer,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,IntPtr buffer,uint size);
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out IntPtr handle,uint access,ref ObjectAttributes attributes,out IoStatusBlock status,IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,IntPtr ea,uint eaLength);
    [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle h,out IoStatusBlock status,IntPtr data,uint size,int informationClass);
    [DllImport("ntdll.dll")] static extern int NtQueryDirectoryFile(SafeFileHandle h,IntPtr evt,IntPtr apc,IntPtr context,out IoStatusBlock status,IntPtr data,uint size,int informationClass,[MarshalAs(UnmanagedType.U1)] bool single,IntPtr name,[MarshalAs(UnmanagedType.U1)] bool restart);
    [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);
    static void Check(bool ok,string where){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),where);}
    static void CheckNt(int status,string where){if(status<0)throw new Win32Exception(unchecked((int)RtlNtStatusToDosError(status)),where);}
    static bool IsHash(string x){return Regex.IsMatch(x,"^[a-f0-9]{64}$");}
    static bool SamePath(string a,string b){return String.Equals(a,b,StringComparison.OrdinalIgnoreCase);}
    static bool SameObject(Info a,Info b){return a.Volume==b.Volume&&a.IndexHigh==b.IndexHigh&&a.IndexLow==b.IndexLow;}
    static long Size(Info i){return ((long)i.SizeHigh<<32)|i.SizeLow;}
    static string Canonical(string p){
        if(p.Length>1024||!Regex.IsMatch(p,@"^[A-Za-z]:\\")||p.Substring(2).Contains(":")||p.Contains("/")||p.IndexOf('\0')>=0)throw new ArgumentException("Local absolute path required");
        string normalized=Path.GetFullPath(p);
        if(!SamePath(p,normalized))throw new ArgumentException("Non-canonical path");
        foreach(string c in p.Substring(3).Split('\\')){
            if(c.Length==0||c=="."||c==".."||c.EndsWith(".")||c.EndsWith(" ")||c.IndexOfAny(Path.GetInvalidFileNameChars())>=0||Regex.IsMatch(c,@"^(CON|PRN|AUX|NUL|COM[1-9\u00B9\u00B2\u00B3]|LPT[1-9\u00B9\u00B2\u00B3])(\.|$)",RegexOptions.IgnoreCase))throw new ArgumentException("Unsafe path component");
        }
        return p;
    }
    static SafeFileHandle OpenRelative(SafeFileHandle parent,string name,uint access,uint disposition,uint options,uint share=SHARE_READ){
        if(name.Length==0||name.Length>255||name=="."||name==".."||name.IndexOfAny(new char[]{'\\','/',':','\0'})>=0)throw new ArgumentException("Single relative component required");
        IntPtr text=Marshal.StringToHGlobalUni(name),ptr=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        try{
            UnicodeString u=new UnicodeString();u.Length=(ushort)(name.Length*2);u.MaximumLength=(ushort)(u.Length+2);u.Buffer=text;Marshal.StructureToPtr(u,ptr,false);
            ObjectAttributes a=new ObjectAttributes();a.Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes));a.RootDirectory=parent.DangerousGetHandle();a.ObjectName=ptr;a.Attributes=0x40;
            IntPtr h;IoStatusBlock io;
            int status=NtCreateFile(out h,access|SYNC,ref a,out io,IntPtr.Zero,0,share,disposition,options|NT_SYNC|OPEN_REPARSE,IntPtr.Zero,0);
            CheckNt(status,"NtCreateFile relative");return new SafeFileHandle(h,true);
        }finally{Marshal.FreeHGlobal(ptr);Marshal.FreeHGlobal(text);}
    }
    static string FinalName(SafeFileHandle h){
        StringBuilder b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);
        Check(n>0&&n<b.Capacity,"GetFinalPathNameByHandle");
        string p=b.ToString();if(!p.StartsWith(@"\\?\",StringComparison.Ordinal)||p.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase))throw new IOException("Non-local final path");
        return p.Substring(4);
    }
    static Info Verify(SafeFileHandle h,string expected,bool? directory){
        Check(!h.IsInvalid,"CreateFile");
        Info i;Check(GetFileInformationByHandle(h,out i),"GetFileInformationByHandle");
        bool isDir=(i.Attributes&DIRECTORY)!=0;
        if((i.Attributes&REPARSE)!=0||(directory.HasValue&&isDir!=directory.Value)||
            !SamePath(FinalName(h).TrimEnd('\\'),expected.TrimEnd('\\'))||(!isDir&&i.Links!=1))throw new IOException("Object identity, link or reparse boundary");
        return i;
    }
    static SafeFileHandle PinDirectory(string p,List<SafeFileHandle> pins,SafeFileHandle parent=null,bool list=false){
        uint access=READ_ATTR|TRAVERSE|(list?LIST_DIR:0);
        SafeFileHandle h=parent==null?CreateFileW(p,access,3,IntPtr.Zero,OPEN_EXISTING,BACKUP_SEMANTICS|OPEN_REPARSE,IntPtr.Zero):OpenRelative(parent,Path.GetFileName(p),access,NT_OPEN,0,3);
        try{Verify(h,p,true);pins.Add(h);return h;}catch{h.Dispose();throw;}
    }
    static SafeFileHandle PinAncestors(string path,List<SafeFileHandle> pins){
        string drive=Path.GetPathRoot(path),dir=Path.GetDirectoryName(path),cur=drive;
        SafeFileHandle result=PinDirectory(cur,pins);
        string tail=dir.Substring(drive.Length);
        if(tail.Length==0)return result;
        foreach(string c in tail.Split('\\')){cur=Path.Combine(cur,c);result=PinDirectory(cur,pins,result);}
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
    static Info Regular(SafeFileHandle h,string p,bool bounded){
        Info i=Verify(h,p,false);long size=Size(i);
        if(size<0||(bounded&&size>MAX_BYTES))throw new IOException("File size denied");
        OnlyDefaultStream(h);return i;
    }
    static string Digest(byte[] bytes){using(var sha=SHA256.Create()){return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}}
    static byte[] ReadHandle(SafeFileHandle h,Info i){
        if(Size(i)<0||Size(i)>MAX_BYTES)throw new IOException("File size denied");
        byte[] bytes=new byte[(int)Size(i)];
        using(var stream=new FileStream(new SafeFileHandle(h.DangerousGetHandle(),false),FileAccess.Read,4096,false)){
            stream.Position=0;int at=0;while(at<bytes.Length){int n=stream.Read(bytes,at,bytes.Length-at);if(n==0)throw new IOException("Truncated file");at+=n;}
            if(stream.ReadByte()!=-1)throw new IOException("File grew");
        }
        Info after;Check(GetFileInformationByHandle(h,out after),"Read identity");
        if(!SameObject(i,after)||Size(after)!=Size(i)||i.WriteHigh!=after.WriteHigh||i.WriteLow!=after.WriteLow||after.Links!=1)throw new IOException("File changed");
        return bytes;
    }
    static byte[] Input(){
        using(var input=Console.OpenStandardInput())using(var bytes=new MemoryStream()){
            byte[] b=new byte[32768];int n;
            while((n=input.Read(b,0,b.Length))>0){if(bytes.Length+n>MAX_BYTES)throw new IOException("Input too large");bytes.Write(b,0,n);}
            return bytes.ToArray();
        }
    }
    static void RenameNoClobber(SafeFileHandle h,SafeFileHandle parent,string dest){
        Verify(parent,Path.GetDirectoryName(dest),true);
        byte[] name=Encoding.Unicode.GetBytes(Path.GetFileName(dest));
        int fileOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"FirstChar"),rootOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"RootDirectory"),lengthOffset=(int)Marshal.OffsetOf(typeof(RenameHeader),"FileNameLength");
        int sizeBuffer=Math.Max(Marshal.SizeOf(typeof(RenameHeader)),fileOffset+name.Length+2);IntPtr buf=Marshal.AllocHGlobal(sizeBuffer);
        try{
            for(int i=0;i<sizeBuffer;i++)Marshal.WriteByte(buf,i,0);
            Marshal.WriteIntPtr(buf,rootOffset,parent.DangerousGetHandle());Marshal.WriteInt32(buf,lengthOffset,name.Length);Marshal.Copy(name,0,IntPtr.Add(buf,fileOffset),name.Length);
            IoStatusBlock io;CheckNt(NtSetInformationFile(h,out io,buf,(uint)sizeBuffer,10),"NtSetInformationFile relative rename");
        }finally{Marshal.FreeHGlobal(buf);}
    }
    static bool MarkDelete(SafeFileHandle h){
        IntPtr b=Marshal.AllocHGlobal(1);
        try{Marshal.WriteByte(b,1);return SetFileInformationByHandle(h,4,b,1);}
        finally{Marshal.FreeHGlobal(b);}
    }
    static SafeFileHandle OpenFile(SafeFileHandle parent,string path,uint access){return OpenRelative(parent,Path.GetFileName(path),access,NT_OPEN,NT_FILE);}
    static Info VerifyMoved(SafeFileHandle h,string path,Info before){
        Info after=Regular(h,path,true);if(!SameObject(before,after)||Size(before)!=Size(after))throw new IOException("Unknown rename outcome");return after;
    }
    static int Move(string source,string dest,string hash){
        if(!IsHash(hash)||SamePath(source,dest))throw new ArgumentException("Invalid move");
        var pins=new List<SafeFileHandle>();
        try{
            SafeFileHandle sourceParent=PinAncestors(source,pins),parent=PinAncestors(dest,pins);Info target;Check(GetFileInformationByHandle(parent,out target),"Target directory");
            using(var h=OpenFile(sourceParent,source,GENERIC_READ|DELETE)){
                Info original=Regular(h,source,true);if(original.Volume!=target.Volume||Digest(ReadHandle(h,original))!=hash)throw new IOException("Volume or digest mismatch");
                RenameNoClobber(h,parent,dest);VerifyMoved(h,dest,original);Console.WriteLine("MOVE_OK");return 0;
            }
        }finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static int Read(string path){
        var pins=new List<SafeFileHandle>();
        try{
            SafeFileHandle parent=PinAncestors(path,pins);
            using(var h=OpenFile(parent,path,GENERIC_READ)){
                Info i=Regular(h,path,true);byte[] bytes=ReadHandle(h,i);VerifyMoved(h,path,i);
                using(var output=Console.OpenStandardOutput()){output.Write(bytes,0,bytes.Length);output.Flush();}
                return 0;
            }
        }finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static Info Metadata(SafeFileHandle parent,string p){
        using(var h=OpenRelative(parent,Path.GetFileName(p),READ_ATTR,NT_OPEN,0)){
            Info i=Verify(h,p,null);if((i.Attributes&DIRECTORY)==0)OnlyDefaultStream(h);return i;
        }
    }
    static int Stat(string path){
        var pins=new List<SafeFileHandle>();
        try{SafeFileHandle parent=PinAncestors(path,pins);Info i=Metadata(parent,path);Console.WriteLine(((i.Attributes&DIRECTORY)!=0?"D\t0":"F\t"+Size(i).ToString(System.Globalization.CultureInfo.InvariantCulture)));return 0;}
        finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static int List(string path){
        var pins=new List<SafeFileHandle>();IntPtr buffer=IntPtr.Zero;
        try{
            SafeFileHandle parent=PinAncestors(path,pins),dir=PinDirectory(path,pins,parent,true);
            buffer=Marshal.AllocHGlobal(65536);
            var lines=new List<string>();int scanned=0;bool truncated=false,restart=true;
            while(!truncated){
                IoStatusBlock io;int status=NtQueryDirectoryFile(dir,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out io,buffer,65536,12,false,IntPtr.Zero,restart);restart=false;
                if(status==unchecked((int)0x80000006)||status==unchecked((int)0xC000000F))break;
                CheckNt(status,"NtQueryDirectoryFile");ulong used=io.Information.ToUInt64();
                if(used==0||used>65536)throw new IOException("Invalid directory result");
                int at=0;
                while((ulong)at<used){
                    if((ulong)at+12>used)throw new IOException("Invalid directory record");
                    int next=Marshal.ReadInt32(buffer,at),length=Marshal.ReadInt32(buffer,at+8);
                    if(length<=0||length%2!=0||(ulong)at+12+(ulong)length>used)throw new IOException("Invalid directory name");
                    string name=Marshal.PtrToStringUni(IntPtr.Add(buffer,at+12),length/2);
                    if(name!="."&&name!=".."){
                        if(scanned++>=MAX_ENTRIES){truncated=true;break;}
                        try{
                            string p=Canonical(Path.Combine(path,name));Info i=Metadata(dir,p);
                            lines.Add(Convert.ToBase64String(Encoding.UTF8.GetBytes(name))+"\t"+((i.Attributes&DIRECTORY)!=0?"D\t0":"F\t"+Size(i).ToString(System.Globalization.CultureInfo.InvariantCulture)));
                        }catch(IOException){}catch(Win32Exception){}catch(ArgumentException){}catch(UnauthorizedAccessException){}
                    }
                    if(next==0)break;if(next<12+length||(ulong)at+(ulong)next>=used)throw new IOException("Invalid directory cursor");at+=next;
                }
            }
            Verify(dir,path,true);Console.WriteLine(truncated?"LIST_1":"LIST_0");foreach(string line in lines)Console.WriteLine(line);return 0;
        }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static int Mkdir(string path){
        var pins=new List<SafeFileHandle>();
        try{
            SafeFileHandle parent=PinAncestors(path,pins);
            using(var dir=OpenRelative(parent,Path.GetFileName(path),READ_ATTR|TRAVERSE,NT_CREATE,NT_DIR,3)){Verify(dir,path,true);}
            Console.WriteLine("MKDIR_OK");return 0;
        }finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static SafeFileHandle Backup(string path,string hash,List<SafeFileHandle> pins){
        SafeFileHandle parent=PinAncestors(path,pins);SafeFileHandle h=OpenFile(parent,path,GENERIC_READ);
        try{Info i=Regular(h,path,true);if(Digest(ReadHandle(h,i))!=hash)throw new IOException("Backup digest mismatch");return h;}
        catch{h.Dispose();throw;}
    }
    static int Write(string path,string expected,string newHash,string backupPath){
        if(!IsHash(newHash)||(expected!="new"&&!IsHash(expected))||(expected=="new"?backupPath!="":backupPath==""))throw new ArgumentException("Invalid write");
        byte[] bytes=Input();if(Digest(bytes)!=newHash)throw new IOException("Input digest mismatch");
        var pins=new List<SafeFileHandle>();SafeFileHandle original=null,backup=null,temp=null;
        bool tempRenamed=false,oldRenamed=false;
        try{
            SafeFileHandle targetParent=PinAncestors(path,pins);
#if NB_TEST_PIN_PAUSE
            // Only a test compiler defines this. The production helper has no pause hook.
            Console.Error.WriteLine("SYNTHETIC_PIN_READY");Console.Error.Flush();System.Threading.Thread.Sleep(1200);
#endif
            Info oldInfo=new Info();
            if(expected!="new"){
                backupPath=Canonical(backupPath);if(SamePath(backupPath,path))throw new IOException("Backup overlaps");
                backup=Backup(backupPath,expected,pins);
                original=OpenFile(targetParent,path,GENERIC_READ|DELETE);oldInfo=Regular(original,path,true);
                if(Digest(ReadHandle(original,oldInfo))!=expected)throw new IOException("Original digest conflict");
            }
            string parent=Path.GetDirectoryName(path),tmp=Path.Combine(parent,".nb-tmp-"+Guid.NewGuid().ToString("N"));
            temp=OpenRelative(targetParent,Path.GetFileName(tmp),GENERIC_READ|GENERIC_WRITE|DELETE,NT_CREATE,NT_FILE);
            Info tempInfo=Regular(temp,tmp,true);
            using(var stream=new FileStream(new SafeFileHandle(temp.DangerousGetHandle(),false),FileAccess.ReadWrite,4096,false)){
                stream.Write(bytes,0,bytes.Length);stream.Flush(true);
            }
            tempInfo=Regular(temp,tmp,true);if(Digest(ReadHandle(temp,tempInfo))!=newHash)throw new IOException("Staged digest mismatch");
            if(original!=null){
                string old=Path.Combine(parent,".nb-tmp-old-"+Guid.NewGuid().ToString("N"));
                RenameNoClobber(original,targetParent,old);oldRenamed=true;VerifyMoved(original,old,oldInfo);
#if NB_TEST_FAULT
                // Compiled only in a separate synthetic test helper.
                Environment.Exit(73);
#endif
            }
            RenameNoClobber(temp,targetParent,path);tempRenamed=true;Info final=VerifyMoved(temp,path,tempInfo);
            if(Digest(ReadHandle(temp,final))!=newHash)throw new IOException("Unknown write outcome");
            if(oldRenamed)Check(MarkDelete(original),"Old staged file cleanup");
            Console.WriteLine("WRITE_OK");return 0;
        }finally{
            if(temp!=null){if(!temp.IsInvalid&&!tempRenamed)MarkDelete(temp);temp.Dispose();}
            if(original!=null)original.Dispose();if(backup!=null)backup.Dispose();
            for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();
        }
    }
    static int Trash(string path,string hash,string backupPath){
        if(!IsHash(hash)||SamePath(path,backupPath))throw new ArgumentException("Invalid trash");
        var pins=new List<SafeFileHandle>();
        try{
            SafeFileHandle parent=PinAncestors(path,pins);
            using(var backup=Backup(backupPath,hash,pins))using(var source=OpenFile(parent,path,GENERIC_READ|DELETE)){
                Info i=Regular(source,path,true);if(Digest(ReadHandle(source,i))!=hash)throw new IOException("Source digest mismatch");
                Check(MarkDelete(source),"Recoverable trash disposition");
            }
            Console.WriteLine("TRASH_OK");return 0;
        }finally{for(int i=pins.Count-1;i>=0;i--)pins[i].Dispose();}
    }
    static int Run(string[] args){
        if(args.Length==2&&args[0]=="io-read")return Read(Canonical(args[1]));
        if(args.Length==2&&args[0]=="io-stat")return Stat(Canonical(args[1]));
        if(args.Length==2&&args[0]=="io-list")return List(Canonical(args[1]));
        if(args.Length==2&&args[0]=="io-mkdir")return Mkdir(Canonical(args[1]));
        if(args.Length==5&&args[0]=="io-write")return Write(Canonical(args[1]),args[2],args[3],args[4]);
        if(args.Length==4&&args[0]=="io-trash")return Trash(Canonical(args[1]),args[2],Canonical(args[3]));
        if(args.Length==3)return Move(Canonical(args[0]),Canonical(args[1]),args[2]);
        throw new ArgumentException("Unknown native file operation");
    }
    public static int Main(string[] args){
        try{return Run(args);}catch(Win32Exception e){Console.Error.WriteLine("Native file operation refused or outcome unknown: "+e.Message+" ("+e.NativeErrorCode+")");return 126;}catch(Exception e){Console.Error.WriteLine("Native file operation refused or outcome unknown: "+e.GetType().Name);return 126;}
    }
}
