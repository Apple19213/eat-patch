# eat-patch

针对「.NET 主程序 + native 授权 DLL」的进程内 EAT 补丁。

[English](README.md) | **中文** | [日本語](README.ja.md)

我看的这个程序由托管 WinForms 外壳加一个 native 授权 DLL 组成。有意思的逻辑全在 DLL 里，托管侧只声明了 18 个 `DllImport`，剩下的就是画窗口。这个仓库是我最后写出来的启动器：正常启动程序，在内存里改掉 DLL 的导出地址表，让授权相关调用返回预设值。磁盘上一个字节都不动。

它不是通用脱壳机，换一个程序不改代码跑不起来。当成一个完整案例加一套可复用的 stub 布局来看比较合适。

## 为什么只能走内存

显而易见的路子在这个目标上全部碰壁：

| 试过的做法 | 结果 |
|---|---|
| 改托管 IL | 15638 个方法体里 13019 个是 4 字节空壳（`nop nop ldc.i4.1 ret`），没有可改的东西 |
| 改磁盘上的 DLL | 翻 1 个字节，或者追加 1 个字节，程序 1.1 秒内退出，`rc=0`，无窗口、无 .NET 事件日志 |
| 换个同名代理 DLL | 同样静默退出 |
| `App.exe.local` 重定向 | 被忽略；Win7 之后没有 manifest 声明就不生效 |

过程中排除了两件事：PE checksum（`stored=0x0`，根本没填）和内置哈希（整文件与各节的 md5/sha1/sha256/crc32，raw 与 hex 两种形式在 32 MB 的 exe 全文搜过，零命中）。剩下的解释只能是「覆盖每个字节 + 精确文件长度」的校验，而且失败时直接 `Exit` 而不是抛异常。所以唯一站得住的位置是校验已经通过之后：进程内部。

## 工作原理

**stub blob**（`src/stub.asm`）是 `nasm -f bin` 的产物，位置无关：

```asm
BASEP:
    push ebx
    call %%a
%%a: pop ebx
    sub ebx, %%a
```

每个 stub 靠这个把 blob 自身地址取到 `ebx`，注入器 `VirtualAllocEx` 到哪都能跑，不需要重定位。

**按槽位，不按名字。** stub 叫 `f00`..`f29`，cfg 字叫 `c00`..`c15`，真实地址槽叫 `r00`..`r29`，字符串叫 `s0`..`s6`。两边只按 EAT 序号对齐，源码里没有任何目标专有的标识符。注入器按 ordinal 遍历导出地址表，从不读名字字符串。

**转发只能用 jmp。** 两边都是 stdcall。`call` 进去再 `ret` 会把参数弹两次，现象是 `0xC0000005`：

```asm
mov eax, [ebx + r21]
pop ebx
jmp eax
```

**r 槽指向跳板，不指向入口。** 入口那 5 个字节就是 `E9`，把 r 槽指回入口等于转发立刻跳回 stub 自己。thunk 形态的导出（`56 57 53 E8 rel32 5B 5F 5E C3`）真身就是 `entry + 8 + rel32`；其余的要把被顶掉的序言抄进 blob，修正其中 `E8`/`E9` 的相对位移，末尾补一条 `E9` 跳回 `entry + n`。这需要一个小 x86-32 长度解码器，`launch.cs` 里的 `DisplacedLength`/`InstrLength` 覆盖了序言里实际会出现的指令。

**自描述符号表。** blob 末尾是 `PAKB`、一个计数、83 个 dword。注入器从文件末尾倒着扫就能找到。改 `stub.asm` 不用动注入器，偏移过期也不会悄悄写错位置。

## 两个花了不少时间的点

`f13` 是字符串释放函数。调用方拿到指针一律会释放，但预设字符串住在 blob 里而不是 DLL 堆上，交给真实实现去 `free` 会破坏堆，进程当场死。stub 先判断指针是否落在 `[blob, end_of_block)`，是就本地返回。

`f06(2)`、`f06(3)`、`f06(4)` 会被调用方 `Double.Parse`。返回空串会在消息循环里抛异常，而肉眼看到的现象是「补丁打了、授权也对了、主界面就是不出来」，很容易误判成补丁没生效。这三个槽位填数字，窗口立刻出现。

## 编译

需要 `nasm` 和 .NET Framework 编译器，正常的 Windows 机器上都有。

```bat
build\build.bat
```

或者手动两步：

```bat
nasm -f bin -l build\stub.lst -o build\stub.bin src\stub.asm

%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe ^
  -nologo -target:winexe -platform:x86 -optimize+ ^
  -out:build\launcher.exe ^
  -resource:build\stub.bin,stub.bin src\launch.cs
```

`-target:winexe` 很关键：exe 子系统会弹黑窗口，winexe 全程静默，只在失败时弹一个 `MessageBoxW`。

## 用法

```
launcher.exe                    静默：找程序 → 注入 → 触发 → 解除置顶 → 退出
launcher.exe --verbose          保留控制台，打印四步日志
launcher.exe "D:\path\to\app"   指定目录；会往下探测一层子目录
```

它按体积判断哪个是真程序——安装包和主程序同名但约 52 MB，会被跳过——同时要求 native DLL 和 `Resources` 目录就在旁边。找不到就弹框说明，不会静默失败。

## 换目标程序

改 `src/launch.cs` 顶部两个常量：

```csharp
const string AppName   = "TARGET";
const string TargetDll = "AUTH.dll";
```

然后重写 `src/stub.asm` 的槽位表，让它对上目标的导出：哪些槽本地应答、各自参数多少字节、cfg 段怎么排。`launch.cs` 里的 `CfgOn` 和 `StrInit` 按槽位序号选行为。

## 已知限制

- 只有 32 位。目标是 x86，注入代码也是。
- 导出表必须小且无转发；按序号遍历的前提是 `AddressOfFunctions[i]` 是普通 RVA。
- 只对一个目标、一个 Windows 版本验证过。启动后会重新保护内存页的壳子没测。
- `--verbose` 模式下目标程序自身的窗口怪癖依旧存在：主窗没有标题栏（`style=0x16030000`），不带 `SWP_NOSENDCHANGING` 就拒绝外部移窗。

## 延伸阅读

- [技术分析（中文）](docs/技术分析.md) —— 完整判断链路，每个失败的实验和原因。
- [Technical write-up (English)](docs/analysis.md) —— 同样内容，英文版。

## 这里没有什么

没有目标二进制、没有 DLL、没有安装包、没有反编译产物、没有内存转储。

## 许可

MIT
