// launcher for in-process EAT patching of a native licensing DLL.
//   csc -nologo -target:winexe -platform:x86 -optimize+ -out:launcher.exe ^
//       -resource:stub.bin,stub.bin launch.cs
//
// Retargeting: change AppName / TargetDll below, then rebuild the slot table in
// stub.asm so it matches the new DLL's exports.
//
// The target checks its licensing DLL byte for byte (including length) before
// it will run, so neither editing nor replacing the file is an option.  This
// launcher starts the app normally, then repoints the loaded DLL's export
// address table at stubs living in a blob it allocated inside the process.
// Selected slots answer with canned values; everything else forwards to the
// original function, so unrelated features keep working.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class Launch
{
    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40, PAGE_READWRITE = 0x04;
    const int TRAMP_BASE = 0x8000;

    // ==== 换目标程序只改这两行 ====
    const string AppName   = "TARGET";        // 目标程序名（不含 .exe）
    const string TargetDll = "AUTH.dll";      // 承载授权逻辑的 native DLL

    // The stub blob carries one entry per export slot plus its own symbol table,
    // so nothing below depends on what the target DLL happens to be called or
    // which functions it exports; the two sides line up by position.
    //
    // CfgOn: cfg words forced to 1 (index into the cfg block, layout in stub.asm).
    static readonly int[] CfgOn = { 0, 1, 2, 3, 4, 5, 6, 8 };

    // StrInit: canned replies written into the string block, same index order.
    static readonly string[] StrInit = {
        "Right,OK",
        "2099年12月31日23时59分59秒",
        "该软件已经是最新版",
        "请各位用户遵守国家法律法规",
        "99999", "99999", "99999"
    };

    [DllImport("kernel32", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr got);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr got);
    [DllImport("kernel32", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, IntPtr size, uint type, uint protect);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint nprot, out uint old);
    [DllImport("kernel32")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32")]
    static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);
    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern bool Module32FirstW(IntPtr snap, ref MODULEENTRY32W e);
    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern bool Module32NextW(IntPtr snap, ref MODULEENTRY32W e);
    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("user32")]
    static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32")]
    static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr p);
    [DllImport("user32")]
    static extern uint GetWindowThreadProcessId(IntPtr h, out int pid);
    [DllImport("user32", CharSet = CharSet.Unicode)]
    static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32", CharSet = CharSet.Unicode)]
    static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32")]
    static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32")]
    static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32", CharSet = CharSet.Unicode, EntryPoint = "SendMessageTimeoutW")]
    static extern IntPtr SendMessageTimeoutW(IntPtr h, uint msg, IntPtr wp, StringBuilder lp,
        uint flags, uint timeout, out IntPtr result);
    [DllImport("user32")]
    static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32")]
    static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32")]
    static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32")]
    static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32")]
    static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32", EntryPoint = "SystemParametersInfoW")]
    static extern bool SystemParametersInfo(uint action, uint param, ref RECT r, uint winIni);
    [DllImport("user32")]
    static extern bool SetProcessDPIAware();
    [DllImport("user32")]
    static extern bool FlashWindow(IntPtr h, bool invert);

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    delegate bool EnumProc(IntPtr h, IntPtr p);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32W
    {
        public int dwSize; public int cntUsage; public int th32ProcessID;
        public IntPtr th32DefaultHeapID; public int th32ModuleID, cntThreads,
            th32ParentProcessID, pcPriClassBase, dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MODULEENTRY32W
    {
        public int dwSize, th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public IntPtr modBaseAddr, modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    static string Text(IntPtr h)
    {
        IntPtr got;
        var sb = new StringBuilder(1024);
        SendMessageTimeoutW(h, 0x000D, (IntPtr)1024, sb, 0x0002, 150, out got);
        if (sb.Length > 0) return sb.ToString();
        var sb2 = new StringBuilder(1024);
        GetWindowTextW(h, sb2, 1024);
        return sb2.ToString();
    }

    static string Cls(IntPtr h) { var sb = new StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString(); }

    static List<IntPtr> WindowsOf(int pid)
    {
        var list = new List<IntPtr>();
        EnumWindows((h, p) => { int q; GetWindowThreadProcessId(h, out q); if (q == pid) list.Add(h); return true; }, IntPtr.Zero);
        return list;
    }

    static List<IntPtr> Children(IntPtr parent)
    {
        var list = new List<IntPtr>();
        EnumChildWindows(parent, (h, p) => { list.Add(h); return true; }, IntPtr.Zero);
        return list;
    }

    static IntPtr FindWindow(int pid, string titlePart, bool visibleOnly, bool topLevel)
    {
        List<IntPtr> src = topLevel ? WindowsOf(pid) : new List<IntPtr>();
        foreach (var h in src)
        {
            if (visibleOnly && !IsWindowVisible(h)) continue;
            if (Text(h).Contains(titlePart)) return h;
        }
        return IntPtr.Zero;
    }

    static IntPtr MainWindow(int pid)
    {
        foreach (var h in WindowsOf(pid))
        {
            if (!IsWindowVisible(h)) continue;
            if (Cls(h) == "#32770") continue;
            if (Text(h) == AppName) return h;
        }
        return IntPtr.Zero;
    }

    static IntPtr FindDialog(int pid)
    {
        foreach (var h in WindowsOf(pid))
            if (Cls(h) == "#32770" && IsWindowVisible(h)) return h;
        return IntPtr.Zero;
    }

    static IntPtr FindChildByText(IntPtr parent, string text)
    {
        foreach (var c in Children(parent))
            if (Text(c) == text) return c;
        return IntPtr.Zero;
    }

    static int PidsOf(string exe)
    {
        var found = new List<int>();
        IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
        var e = new PROCESSENTRY32W(); e.dwSize = Marshal.SizeOf(e);
        if (Process32FirstW(snap, ref e))
            do { if (e.szExeFile.Equals(exe, StringComparison.OrdinalIgnoreCase)) found.Add(e.th32ProcessID); }
            while (Process32NextW(snap, ref e));
        CloseHandle(snap);
        return found.Count > 0 ? found[0] : 0;
    }

    // 主程序与"同名安装包"的鉴别：安装包是单文件且体积很大；真程序旁必须有授权 DLL 与 Resources
    static bool LooksLikeRealApp(string dir, string exe)
    {
        try
        {
            long len = new System.IO.FileInfo(exe).Length;
            if (len > 40L * 1024 * 1024) return false;                 // 40 MB 以上是 Inno Setup 安装包
            if (!System.IO.File.Exists(System.IO.Path.Combine(dir, TargetDll))) return false;
            if (!System.IO.File.Exists(System.IO.Path.Combine(dir, @"Resources\adb.exe"))) return false;
            return true;
        }
        catch { return false; }
    }

    // 在目录里找出真正的目标程序：先看本目录，再看一层子目录
    static string ResolveExe(string dir)
    {
        string direct = System.IO.Path.Combine(dir, AppName + ".exe");
        if (System.IO.File.Exists(direct) && LooksLikeRealApp(dir, direct)) return direct;

        try
        {
            foreach (string sub in System.IO.Directory.GetDirectories(dir))
            {
                string cand = System.IO.Path.Combine(sub, AppName + ".exe");
                if (System.IO.File.Exists(cand) && LooksLikeRealApp(sub, cand)) return cand;
            }
        }
        catch { }
        return null;
    }

    static bool Verbose = false;
    static readonly StringBuilder Buf = new StringBuilder();

    [DllImport("kernel32")]
    static extern bool AllocConsole();

    [DllImport("user32", CharSet = CharSet.Unicode)]
    static extern int MessageBoxW(IntPtr h, string text, string caption, uint type);

    // 默认静默：GUI 版没有控制台，Say 只缓存，出错时用弹窗一次性展示
    static void Say(string s)
    {
        if (Verbose) Console.WriteLine(s);
        Buf.AppendLine(s);
    }

    static int Main(string[] args)
    {
        SetProcessDPIAware();   // 用物理像素坐标算居中，避免高分屏下算偏

        string dir = null;
        foreach (string a in args)
        {
            if (a == "-v" || a == "--verbose" || a == "--console") Verbose = true;
            else if (dir == null) dir = a;
        }
        if (Verbose)
        {
            AllocConsole();
            Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        }
        if (dir == null) dir = AppDomain.CurrentDomain.BaseDirectory;

        string exe = ResolveExe(dir);
        if (exe == null)
        {
            string direct = System.IO.Path.Combine(dir, AppName + ".exe");
            if (System.IO.File.Exists(direct))
            {
                Say("这个不是主程序：" + direct);
                Say("   它是安装包（" + (new System.IO.FileInfo(direct).Length / 1024 / 1024) + " MB），不是装好的程序。");
                Say("请先运行安装包把它装到某个目录，再把本启动器放进装好的目录（含 " + TargetDll + " 的那个）。");
            }
            else
            {
                Say("在 " + dir + " 里没找到装好的 " + AppName + ".exe");
                Say("请把本启动器放到安装目录（含 " + AppName + ".exe、" + TargetDll + "、Resources 的那个文件夹）下。");
            }
            Pause();
            return 2;
        }
        dir = System.IO.Path.GetDirectoryName(exe);

        byte[] stub;
        using (var s = typeof(Launch).Assembly.GetManifestResourceStream("stub.bin"))
        {
            if (s == null) { Say("启动器损坏：缺少 stub 资源"); Pause(); return 3; }
            stub = new byte[s.Length];
            s.Read(stub, 0, stub.Length);
        }

        foreach (int old in AllPids(AppName + ".exe"))
        {
            try { Process.GetProcessById(old).Kill(); } catch { }
        }
        System.Threading.Thread.Sleep(700);

        Say("[1/4] 启动主程序 ...");
        Say("      " + exe);
        var p = Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = dir, UseShellExecute = true });
        IntPtr login = IntPtr.Zero;
        for (int i = 0; i < 400; i++)
        {
            login = FindWindow(p.Id, "用户登录", true, true);
            if (login != IntPtr.Zero) break;
            if (p.HasExited) break;
            System.Threading.Thread.Sleep(150);
        }
        if (login == IntPtr.Zero)
        {
            if (p.HasExited)
            {
                Say("主程序启动后立即退出，退出码 0x" + p.ExitCode.ToString("X8") + " (" + p.ExitCode + ")");
                Say("常见原因：目录里缺少 " + TargetDll + " / Resources，或 .NET Framework 未装，或被杀软拦截。");
            }
            else
            {
                Say("主程序在跑（pid " + p.Id + "）但 60 秒内没出现登录窗口。");
            }
            Pause();
            return 4;
        }
        System.Threading.Thread.Sleep(1800);

        Say("[2/4] 注入授权补丁 ...");
        string err = null;
        if (!Inject(p.Id, stub, out err))
        {
            Say("注入失败: " + err);
            Pause();
            return 5;
        }

        Say("[3/4] 触发授权 ...");
        for (int attempt = 0; attempt < 3; attempt++)
        {
            IntPtr btn = FindChildByText(login, "试用");
            if (btn != IntPtr.Zero) PostMessageW(btn, 0x00F5, IntPtr.Zero, IntPtr.Zero);

            bool sawDialog = false;
            for (int i = 0; i < 60; i++)
            {
                System.Threading.Thread.Sleep(150);
                if (FindDialog(p.Id) != IntPtr.Zero) { sawDialog = true; break; }
            }
            if (!sawDialog) break;

            // dismiss every stacked dialog, then look again
            for (int round = 0; round < 40; round++)
            {
                IntPtr dlg = FindDialog(p.Id);
                if (dlg == IntPtr.Zero) break;
                IntPtr ok = FindChildByText(dlg, "确定");
                if (ok == IntPtr.Zero) ok = FindChildByText(dlg, "OK");
                if (ok != IntPtr.Zero) PostMessageW(ok, 0x00F5, IntPtr.Zero, IntPtr.Zero);
                System.Threading.Thread.Sleep(250);
            }
            System.Threading.Thread.Sleep(600);
            if (MainWindow(p.Id) != IntPtr.Zero) break;
        }

        Say("[4/4] 等待主界面 ...");
        IntPtr mw = IntPtr.Zero;
        for (int i = 0; i < 120; i++)
        {
            System.Threading.Thread.Sleep(300);
            mw = MainWindow(p.Id);
            if (mw != IntPtr.Zero) break;
        }
        if (mw == IntPtr.Zero)
        {
            Say("已注入但主界面未出现，请手动点一次“试用”。");
            Pause();
            return 6;
        }

        // 把窗口拉到屏幕正中间并置顶，避免"程序在跑但看不到"
        // 主程序加载完 Form 后会自己恢复上次的窗口位置，所以要多摆几次
        for (int i = 0; i < 8; i++)
        {
            System.Threading.Thread.Sleep(i == 0 ? 900 : 400);
            mw = MainWindow(p.Id);
            if (mw == IntPtr.Zero) continue;
            PlaceWindow(mw);
        }
        Say("完成，已进入主界面（付费功能已解锁）。");
        Say("      窗口已置顶显示：" + AppName + "  (pid " + p.Id + ")");

        // 后台模式：注入 + 置顶完成后本进程自动退出，不留黑窗口。
        // 置顶只保留 2.2 秒（足够用户看见），随后取消，免得一直压着别的程序。
        System.Threading.Thread.Sleep(2200);
        mw = MainWindow(p.Id);
        if (mw != IntPtr.Zero) UnTopmost(mw);
        // 只有显式 --verbose 时才留着控制台让用户看日志
        if (Verbose)
        {
            Console.WriteLine();
            Console.WriteLine("按回车键关闭（主程序继续运行）...");
            try { Console.ReadLine(); } catch { }
        }
        return 0;
    }

    // 居中 + 置顶 + 前台，确保用户一眼能看到
    // 注意：主程序在 WM_WINDOWPOSCHANGING 里会拒掉外部移窗请求，
    // 必须带 SWP_NOSENDCHANGING(0x0400) 让它收不到这个通知。
    static void PlaceWindow(IntPtr h)
    {
        const int SW_RESTORE = 9;
        const uint SWP_SHOWWINDOW = 0x0040;
        const uint SWP_NOSENDCHANGING = 0x0400;

        var wa = new RECT();
        SystemParametersInfo(0x0030, 0, ref wa, 0);

        RECT r;
        GetWindowRect(h, out r);
        int w = r.Right - r.Left, ht = r.Bottom - r.Top;
        if (w < 400) w = 1100;
        if (ht < 400) ht = 880;
        // 别超出工作区
        if (w > wa.Right - wa.Left) w = wa.Right - wa.Left;
        if (ht > wa.Bottom - wa.Top) ht = wa.Bottom - wa.Top;

        int x = wa.Left + (wa.Right - wa.Left - w) / 2;
        int y = wa.Top + (wa.Bottom - wa.Top - ht) / 2;
        if (x < wa.Left) x = wa.Left;
        if (y < wa.Top) y = wa.Top;

        uint flags = SWP_SHOWWINDOW | SWP_NOSENDCHANGING;
        ShowWindow(h, SW_RESTORE);
        // 保持 TOPMOST，否则清掉置顶后会被启动器的控制台窗口压住
        SetWindowPos(h, (IntPtr)(-1), x, y, w, ht, flags);   // HWND_TOPMOST
        BringWindowToTop(h);
        SetForegroundWindow(h);
        FlashWindow(h, true);
    }

    static void UnTopmost(IntPtr h)
    {
        const uint SWP_NOMOVE = 0x0002, SWP_NOSIZE = 0x0001,
                   SWP_NOACTIVATE = 0x0010, SWP_NOSENDCHANGING = 0x0400;
        SetWindowPos(h, (IntPtr)(-2), 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOSENDCHANGING);
    }

    static List<int> AllPids(string exe)
    {
        var found = new List<int>();
        IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
        var e = new PROCESSENTRY32W(); e.dwSize = Marshal.SizeOf(e);
        if (Process32FirstW(snap, ref e))
            do { if (e.szExeFile.Equals(exe, StringComparison.OrdinalIgnoreCase)) found.Add(e.th32ProcessID); }
            while (Process32NextW(snap, ref e));
        CloseHandle(snap);
        return found;
    }

    static void Pause()
    {
        if (Verbose)
        {
            Console.WriteLine("按回车键关闭 ...");
            try { Console.ReadLine(); } catch { }
            return;
        }
        MessageBoxW(IntPtr.Zero, Buf.ToString().Trim(), AppName + " 启动器", 0x00000010);
    }

    static bool Inject(int pid, byte[] stub, out string err)
    {
        err = null;
        IntPtr h = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (h == IntPtr.Zero) { err = "OpenProcess " + Marshal.GetLastWin32Error(); return false; }
        try
        {
            long baseAddr = 0; int imgSize = 0;
            IntPtr snap = CreateToolhelp32Snapshot(0x8, pid);
            var me = new MODULEENTRY32W(); me.dwSize = Marshal.SizeOf(me);
            bool okMod = Module32FirstW(snap, ref me);
            while (okMod)
            {
                if (me.szModule.Equals(TargetDll, StringComparison.OrdinalIgnoreCase))
                {
                    baseAddr = me.modBaseAddr.ToInt64(); imgSize = me.modBaseSize.ToInt32(); break;
                }
                okMod = Module32NextW(snap, ref me);
            }
            CloseHandle(snap);
            if (baseAddr == 0) { err = TargetDll + " 未加载"; return false; }

            // --- PE export directory ---
            byte[] pe = new byte[0x400];
            IntPtr got;
            ReadProcessMemory(h, (IntPtr)baseAddr, pe, (IntPtr)pe.Length, out got);
            int lfanew = BitConverter.ToInt32(pe, 0x3C);
            int opt = lfanew + 24;
            int ddoff = opt + (BitConverter.ToUInt16(pe, lfanew + 20) == 0x20b ? 112 : 96);
            int expRva = BitConverter.ToInt32(pe, ddoff);
            int expSize = BitConverter.ToInt32(pe, ddoff + 4);
            if (expRva == 0) { err = "无导出表"; return false; }

            byte[] ed = new byte[40];
            ReadProcessMemory(h, (IntPtr)(baseAddr + expRva), ed, (IntPtr)40, out got);
            int nfun = BitConverter.ToInt32(ed, 20), nname = BitConverter.ToInt32(ed, 24);
            int afun = BitConverter.ToInt32(ed, 28), aname = BitConverter.ToInt32(ed, 32), aord = BitConverter.ToInt32(ed, 36);
            if (nfun <= 0 || nfun > 512) { err = "导出表异常 nfun=" + nfun; return false; }

            // Walk the export address table by slot index.  No name lookup at all:
            // the stub blob is indexed identically, so positions are the contract.
            var rva = new uint[nfun];
            byte[] t4 = new byte[4];
            for (int i = 0; i < nfun; i++)
            {
                ReadProcessMemory(h, (IntPtr)(baseAddr + afun + i * 4), t4, (IntPtr)4, out got);
                rva[i] = BitConverter.ToUInt32(t4, 0);
            }

            // --- symbol table ---
            int magicAt = -1;
            for (int i = stub.Length - 4; i >= 0; i--)
                if (stub[i] == 0x50 && stub[i + 1] == 0x41 && stub[i + 2] == 0x4B && stub[i + 3] == 0x42) { magicAt = i; break; }
            if (magicAt < 0) { err = "stub 缺少符号表"; return false; }
            int count = BitConverter.ToInt32(stub, magicAt + 4);
            var sym = new int[count];
            for (int i = 0; i < count; i++) sym[i] = BitConverter.ToInt32(stub, magicAt + 8 + i * 4);

            // --- write blob ---
            IntPtr blob = VirtualAllocEx(h, IntPtr.Zero, (IntPtr)0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (blob == IntPtr.Zero) { err = "VirtualAllocEx " + Marshal.GetLastWin32Error(); return false; }
            WriteProcessMemory(h, blob, stub, (IntPtr)stub.Length, out got);

            Action<int, byte[]> putRaw = (o, b) =>
            {
                IntPtr w; WriteProcessMemory(h, (IntPtr)(blob.ToInt64() + o), b, (IntPtr)b.Length, out w);
            };
            Action<int, uint> putU32 = (o, v) => putRaw(o, BitConverter.GetBytes(v));

            // --- real_* slots (thunk target or trampoline) ---
            byte[] code16 = new byte[16];
            int thunks = 0, tramps = 0, miss = 0;
            for (int i = 0; i < nfun; i++)
            {
                uint r = rva[i];
                if (r == 0) { miss++; continue; }
                long entry = baseAddr + r;
                ReadProcessMemory(h, (IntPtr)entry, code16, (IntPtr)16, out got);
                long realAddr;
                if (code16[0] == 0x56 && code16[1] == 0x57 && code16[2] == 0x53 && code16[3] == 0xE8)
                {
                    realAddr = entry + 8 + BitConverter.ToInt32(code16, 4); thunks++;
                }
                else
                {
                    int n = DisplacedLength(code16);
                    byte[] tramp = new byte[n + 5];
                    Array.Copy(code16, 0, tramp, 0, n);
                    for (int k = 0; k < n; )
                    {
                        int il = InstrLength(code16, k); if (il <= 0) il = 1;
                        if (code16[k] == 0xE8 || code16[k] == 0xE9)
                        {
                            int oldRel = BitConverter.ToInt32(code16, k + 1);
                            long newRel = entry + k + 5 + oldRel - (blob.ToInt64() + TRAMP_BASE + i * 32 + k + 5);
                            Array.Copy(BitConverter.GetBytes((int)newRel), 0, tramp, k + 1, 4);
                        }
                        k += il;
                    }
                    int back = (int)(entry + n - (blob.ToInt64() + TRAMP_BASE + i * 32 + n + 5));
                    tramp[n] = 0xE9;
                    Array.Copy(BitConverter.GetBytes(back), 0, tramp, n + 1, 4);
                    putRaw(TRAMP_BASE + i * 32, tramp);
                    realAddr = blob.ToInt64() + TRAMP_BASE + i * 32; tramps++;
                }
                putU32(sym[46 + i], (uint)realAddr);
            }

            // --- cfg + strings ---
            for (int i = 0; i < 16; i++) putU32(sym[30 + i], 0);
            foreach (int i in CfgOn) putU32(sym[30 + i], 1);

            Encoding gbk = Encoding.GetEncoding(936);
            for (int i = 0; i < StrInit.Length; i++)
            {
                byte[] b = gbk.GetBytes(StrInit[i]);
                byte[] dst = new byte[Math.Min(b.Length, 255)];
                Array.Copy(b, dst, dst.Length);
                putRaw(sym[76 + i], dst);
            }

            // --- patch EAT entries ---
            int patched = 0;
            for (int i = 0; i < nfun; i++)
            {
                uint r = rva[i];
                if (r == 0) continue;
                IntPtr target = (IntPtr)(baseAddr + r);
                long dest = blob.ToInt64() + sym[i];
                long rel = dest - (target.ToInt64() + 5);
                if (rel < int.MinValue || rel > int.MaxValue) continue;
                byte[] code = new byte[5];
                code[0] = 0xE9;
                Array.Copy(BitConverter.GetBytes((int)rel), 0, code, 1, 4);
                uint oldp;
                if (!VirtualProtectEx(h, target, (IntPtr)5, PAGE_EXECUTE_READWRITE, out oldp)) continue;
                IntPtr w2;
                bool wok = WriteProcessMemory(h, target, code, (IntPtr)5, out w2);
                uint dummy;
                VirtualProtectEx(h, target, (IntPtr)5, oldp, out dummy);
                if (wok) patched++;
            }
            Say(string.Format("      {2} @0x{0:X8}  blob @0x{1:X8}", baseAddr, blob.ToInt64(), TargetDll));
            Say(string.Format("      转发槽 {0}/{4} (thunk {1}, 跳板 {2})  已改写 {3}/{4}",
                nfun - miss, thunks, tramps, patched, nfun));
            if (patched < 20) { err = "改写数过少: " + patched; return false; }
            return true;
        }
        finally { CloseHandle(h); }
    }

    static int DisplacedLength(byte[] code)
    {
        int n = 0;
        while (n < 5) { int l = InstrLength(code, n); if (l <= 0) l = 1; n += l; if (n > 12) break; }
        return n;
    }

    static int InstrLength(byte[] b, int off)
    {
        int i = off;
        while (true)
        {
            byte p = b[i];
            if (p == 0x66 || p == 0x67 || p == 0xF0 || p == 0xF2 || p == 0xF3 ||
                p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65) { i++; continue; }
            break;
        }
        byte op = b[i++];
        if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0x98 || op == 0x99 ||
            op == 0xC3 || op == 0xCB || op == 0xCC || op == 0xC9 || op == 0xF8 ||
            op == 0xF9 || op == 0xFC || op == 0xFD || op == 0xF5 || op == 0xF4 ||
            (op >= 0x91 && op <= 0x97)) return i - off;
        if (op == 0xC2) return i - off + 2;
        if (op == 0x68) return i - off + 4;
        if (op == 0x6A) return i - off + 1;
        if (op >= 0xB8 && op <= 0xBF) return i - off + 4;
        if (op == 0xA1 || op == 0xA3 || op == 0xA0 || op == 0xA2) return i - off + 4;
        if (op == 0xEB) return i - off + 1;
        if (op == 0xE9 || op == 0xE8) return i - off + 4;
        if (op >= 0x70 && op <= 0x7F) return i - off + 1;
        if (op == 0x0F)
        {
            byte op2 = b[i++];
            if (op2 >= 0x80 && op2 <= 0x8F) return i - off + 4;
            int m0 = ModRmLength(b, i);
            return m0 < 0 ? -1 : (i - off) + m0;
        }
        int ml = ModRmLength(b, i);
        if (ml < 0) return -1;
        int total = (i - off) + ml;
        int modrm = b[i];
        int reg = (modrm >> 3) & 7;
        if (op == 0x83 || op == 0x6B) total += 1;
        else if (op == 0x81 || op == 0x69 || op == 0xC7) total += 4;
        else if (op == 0xC6) total += 1;
        else if (op == 0xA9) total += 4;
        else if (op == 0xF6) total += (reg == 0 || reg == 1) ? 1 : 0;
        else if (op == 0xF7) total += (reg == 0 || reg == 1) ? 4 : 0;
        else if (op == 0xC0 || op == 0xC1) total += 1;
        return total;
    }

    static int ModRmLength(byte[] b, int i)
    {
        byte m = b[i];
        int mod = (m >> 6) & 3, rm = m & 7, n = 1;
        if (mod == 3) return n;
        if (rm == 4)
        {
            byte sib = b[i + n]; n++;
            if (mod == 0 && (sib & 7) == 5) n += 4;
        }
        else if (mod == 0 && rm == 5) n += 4;
        if (mod == 1) n += 1;
        else if (mod == 2) n += 4;
        return n;
    }
}
