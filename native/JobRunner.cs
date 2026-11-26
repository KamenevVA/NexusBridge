// NB-0102: Windows-only process lifetime boundary, not a filesystem/network sandbox.
// Child is assigned to a non-breakaway job at creation; only three stdio handles inherit.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

internal static class JobRunner {
    const uint KILL_ON_CLOSE=0x2000, ACTIVE_LIMIT=8, JOB_LIST=0x2000d, HANDLE_LIST=0x20002;
    const uint EXTENDED_STARTUP=0x80000, NO_WINDOW=0x08000000, SUSPENDED=4, USE_STD_HANDLES=0x100;
    const uint SYNCHRONIZE=0x00100000, DUPLICATE_SAME_ACCESS=2, WAIT_TIMEOUT=258, WAIT_FAILED=0xffffffff;
    [StructLayout(LayoutKind.Sequential)] struct Basic {
        public long PerProcessUserTimeLimit,PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize,MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass,SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadOperationCount,WriteOperationCount,OtherOperationCount,ReadTransferCount,WriteTransferCount,OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] struct Extended {
        public Basic BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit,JobMemoryLimit,PeakProcessMemoryUsed,PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
        public uint cb;
        public string lpReserved,lpDesktop,lpTitle;
        public uint dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags;
        public ushort wShowWindow,cbReserved2;
        public IntPtr lpReserved2,hStdInput,hStdOutput,hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup StartupInfo; public IntPtr AttributeList; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread;public uint ProcessId,ThreadId; }
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int cls,ref Extended data,uint size);
    [StructLayout(LayoutKind.Sequential)] struct CpuRate { public uint ControlFlags,Rate; }
    [DllImport("kernel32.dll",EntryPoint="SetInformationJobObject",SetLastError=true)] static extern bool SetCpuRate(IntPtr job,int cls,ref CpuRate data,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,UIntPtr attribute,IntPtr value,UIntPtr size,IntPtr previous,IntPtr retSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetStdHandle(int id);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcessW(string exe,StringBuilder command,IntPtr processAttr,IntPtr threadAttr,bool inherit,uint flags,IntPtr env,string cwd,ref StartupEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForMultipleObjects(uint count,IntPtr[] handles,bool all,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);

    static void Check(bool ok,string where) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error(),where); }
    static bool Valid(IntPtr p) { return p!=IntPtr.Zero && p!=new IntPtr(-1); }
    static void Close(IntPtr p) { if(Valid(p)) CloseHandle(p); }
    static IntPtr DuplicateStd(int n) {
        IntPtr p=GetStdHandle(n),v;
        Check(Valid(p),"GetStdHandle");
        Check(DuplicateHandle(GetCurrentProcess(),p,GetCurrentProcess(),out v,0,true,DUPLICATE_SAME_ACCESS),"DuplicateHandle");
        return v;
    }
    // Windows CRT argument quoting, including trailing backslashes before the final quote.
    static string Quote(string s) {
        StringBuilder b=new StringBuilder();b.Append('"');int slashes=0;
        foreach(char c in s) {
            if(c=='\\') { slashes++;continue; }
            if(c=='"') { b.Append('\\',slashes*2+1);b.Append('"'); }
            else { b.Append('\\',slashes);b.Append(c); }
            slashes=0;
        }
        b.Append('\\',slashes*2);b.Append('"');return b.ToString();
    }
    static int Run(string[] args) {
        if(args.Length<4 || args.Length>36) throw new ArgumentException("Expected parent PID, timeout, absolute executable and cwd");
        uint parentPid,timeout;
        if(!UInt32.TryParse(args[0],out parentPid)||parentPid==0||!UInt32.TryParse(args[1],out timeout)||timeout<100||timeout>60000)throw new ArgumentException("Invalid lifetime");
        string exe=args[2],cwd=args[3];
        if(!Path.IsPathRooted(exe)||!Path.IsPathRooted(cwd)||!File.Exists(exe)||!Directory.Exists(cwd)||!String.Equals(Path.GetExtension(exe),".exe",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Invalid local executable");
        StringBuilder command=new StringBuilder(Quote(exe));
        for(int i=4;i<args.Length;i++)command.Append(' ').Append(Quote(args[i]));
        if(command.Length>=32767)throw new ArgumentException("Command too long");
        IntPtr job=IntPtr.Zero,parent=IntPtr.Zero,list=IntPtr.Zero,jobs=IntPtr.Zero,handles=IntPtr.Zero;
        IntPtr[] std=new IntPtr[3];ProcessInfo pi=new ProcessInfo();bool initialized=false;
        try {
            parent=OpenProcess(SYNCHRONIZE,false,parentPid);Check(Valid(parent),"OpenProcess parent");
            job=CreateJobObject(IntPtr.Zero,null);Check(Valid(job),"CreateJobObject");
            Extended limits=new Extended();limits.BasicLimitInformation.LimitFlags=KILL_ON_CLOSE|ACTIVE_LIMIT|0x100|0x200;limits.BasicLimitInformation.ActiveProcessLimit=8;limits.ProcessMemoryLimit=new UIntPtr(384u*1024u*1024u);limits.JobMemoryLimit=new UIntPtr(768u*1024u*1024u);
            Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(Extended))),"SetInformationJobObject");
            CpuRate cpu=new CpuRate();cpu.ControlFlags=5;cpu.Rate=2500;Check(SetCpuRate(job,15,ref cpu,(uint)Marshal.SizeOf(typeof(CpuRate))),"Set job CPU hard cap");
            std[0]=DuplicateStd(-10);std[1]=DuplicateStd(-11);std[2]=DuplicateStd(-12);
            IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            if(size.ToInt64()<=0||size.ToInt64()>65536)throw new InvalidOperationException("Attribute list size");
            list=Marshal.AllocHGlobal(size);Check(InitializeProcThreadAttributeList(list,2,0,ref size),"InitializeProcThreadAttributeList");initialized=true;
            jobs=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobs,job);
            handles=Marshal.AllocHGlobal(IntPtr.Size*3);for(int i=0;i<3;i++)Marshal.WriteIntPtr(handles,i*IntPtr.Size,std[i]);
            Check(UpdateProcThreadAttribute(list,0,new UIntPtr(JOB_LIST),jobs,new UIntPtr((uint)IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Job list attribute");
            Check(UpdateProcThreadAttribute(list,0,new UIntPtr(HANDLE_LIST),handles,new UIntPtr((uint)(IntPtr.Size*3)),IntPtr.Zero,IntPtr.Zero),"Handle list attribute");
            StartupEx startup=new StartupEx();startup.StartupInfo.cb=(uint)Marshal.SizeOf(typeof(StartupEx));startup.StartupInfo.dwFlags=USE_STD_HANDLES;startup.StartupInfo.hStdInput=std[0];startup.StartupInfo.hStdOutput=std[1];startup.StartupInfo.hStdError=std[2];startup.AttributeList=list;
            Check(CreateProcessW(exe,command,IntPtr.Zero,IntPtr.Zero,true,EXTENDED_STARTUP|NO_WINDOW|SUSPENDED,IntPtr.Zero,cwd,ref startup,out pi),"CreateProcessW");
            bool member;Check(IsProcessInJob(pi.Process,job,out member)&&member,"Job membership");
            Check(ResumeThread(pi.Thread)!=WAIT_FAILED,"ResumeThread");
            uint wait=WaitForMultipleObjects(2,new IntPtr[]{pi.Process,parent},false,timeout);
            if(wait==WAIT_TIMEOUT)return 124;
            if(wait==1)return 125;
            Check(wait==0,"WaitForMultipleObjects");
            uint code;Check(GetExitCodeProcess(pi.Process,out code),"GetExitCodeProcess");
            return unchecked((int)code);
        } finally {
            // Closing the last job handle kills every remaining member, including descendants.
            Close(job);Close(pi.Thread);Close(pi.Process);Close(parent);
            foreach(IntPtr h in std)Close(h);
            if(initialized)DeleteProcThreadAttributeList(list);
            if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);if(jobs!=IntPtr.Zero)Marshal.FreeHGlobal(jobs);if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
        }
    }
    public static int Main(string[] args) {
        try { return Run(args); }
        catch(Win32Exception e) { Console.Error.WriteLine("NexusBridge Job boundary failed: "+e.Message+" ("+e.NativeErrorCode+")");return 126; }
        catch(Exception) { Console.Error.WriteLine("NexusBridge Job boundary refused execution");return 126; }
    }
}
