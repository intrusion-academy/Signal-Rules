# EXEC-JAVA-SPAWNED-RECON: a Java process started a reconnaissance tool

**Intel to Signal #1: Java4Shell (CVE-2026-114938)** · rule file: [`executions-java-spawned-recon.json`](executions-java-spawned-recon.json) · module **Executions** · severity **high**

> We can't see the bug. We can see what comes next.

## The intel

Java4Shell is a heap overflow in HotSpot's AVX-512 Base64 decode intrinsic: the routine the JIT swaps in for `java.util.Base64` once the code runs hot. Malformed padding makes it write past its buffer.

| | |
|---|---|
| Affected | OpenJDK 17.0.6 and later, on the 17, 21, 25 and 27 lines; Java 8 and 11 reported unaffected |
| Hardware | x86-64 with AVX-512 VBMI: Intel Xeon Ice Lake and newer, AMD EPYC Zen 4 and newer. ARM64 is not affected |
| Score | 9.2 (CVSS 4.0, Calif) · 8.1 (CVSS 3.1, Oracle) |
| Claimed impact | Pre-auth RCE on default installs of Jenkins, Jira, Confluence, Keycloak, Artifactory and PingFederate (Calif). Other teams reproduced the overflow and a crash, but not code execution |
| Status (2026-11-18) | No in-the-wild exploitation reported. The public proof of concept corrupts memory but does not run code |
| Fix | The November 2026 Oracle and OpenJDK updates. Follow your vendor's advice on any stopgap |

### Does it affect Windows?

Yes, on the right server CPU. The vulnerable stub (`generate_base64_decodeBlock` in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`) is in HotSpot's x86 layer, which every operating system shares. It is enabled only by CPU features (`supports_avx512_vbmi()` and `supports_avx512bw()`), with no Windows exclusion. On Windows, `UseBASE64Intrinsics` is `true` by default.

- **Exposed:** Windows Server on Ice Lake or newer Xeon, or Zen 4 or newer EPYC, running a Java 17.0.6+ application.
- **Not exposed:** Intel 12th-gen and newer client CPUs (AVX-512 is switched off; the JVM reports `UseAVX = 2`), ARM64, and Java 8 and 11.

## What Signal can see

The attacker's first commands. After any Java remote code execution, the attacker needs to know where they landed, and on Windows the Java process starts a process to find out. Windows records that in Security event 4688 (with command-line logging) and Sysmon event 1. If the process is still running, Signal also sees it in the live process table.

```
java.exe                  ->  whoami.exe
java.exe                  ->  cmd.exe /c whoami /all
ws_TomcatService.exe      ->  powershell.exe -enc ...
```

## What Signal can't see

- **The overflow itself.** It happens inside the JVM's memory.
- **The denial-of-service crash.** This rule does not read Java's crash logs or the Application log.
- **An exploit that never starts a process,** such as an in-memory implant.
- **A Java service under a renamed launcher** that is not in the rule's list. Tomcat's own service names (`tomcat9.exe`...) are covered by the built-in `WEB-SERVER-STARTED-PROCESS`.
- **A host with no process-creation logging,** neither 4688 nor Sysmon.

## History

The bug changes; the first commands don't.

- **Log4Shell, 2021-22.** In attacks on VMware Horizon on Windows, the Java Tomcat service `ws_TomcatService.exe` started `cmd.exe` and encoded PowerShell to fetch the next stage ([BlackBerry](https://blogs.blackberry.com/en/2022/01/log4u-shell4me), [Anvilogic](https://www.anvilogic.com/threat-reports/log4shell-and-coinminers)).
- **APT35 and Log4Shell.** A malicious Java class ran a Base64-encoded PowerShell command to load a modular toolkit ([Check Point Research](https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/)).
- Hunting guidance from that time looked for the same thing: shells as children of Java processes ([Splunk](https://research.splunk.com/endpoint/28c81306-5c47-11ec-bfea-acde48001122), [Sygnia](https://www.sygnia.co/?p=1436)).

## The rule

```
condition:  java_parent and (recon_tool or (shell and shell_recon))

java_parent   process.parent_name ends with  \java.exe  \javaw.exe  \ws_tomcatservice.exe
recon_tool    process.name ends with         whoami, net, net1, nltest, systeminfo, quser, qwinsta,
                                             dsquery, certutil, bitsadmin, mshta, regsvr32
shell         process.name ends with         cmd, powershell, pwsh
shell_recon   process.command_line contains  whoami, nltest, systeminfo, net user, net group,
                                             net localgroup, quser, certutil, bitsadmin, mshta,
                                             regsvr32, downloadstring, downloadfile,
                                             invoke-webrequest, frombase64string, -enc, -encodedcommand
```

- **Evidence:** `process_creation` (Security 4688, Sysmon 1) and `running_process`.
- **Coalesce:** `process.name`, `process.command_line`. Each distinct child command is one signal.
- **Tags:** T1059, T1033, T1082, T1087, T1105, T1218. Not T1190: a process tree does not show how the Java process was made to do this.
- **Why Executions, not Webshells:** the Webshells module keeps only processes whose parent is one of its own web servers, so a rule placed there never sees `java.exe`.

### Built to stay quiet

Severity is **high, not critical**: a Java program may legitimately run one of these tools, for example a build job that calls `whoami` directly.

| Benign activity | Why it doesn't fire |
|---|---|
| Jenkins or Gradle build steps (`cmd /c call ...\jenkins123.bat`) | A shell matches only when its own command line does recon, a download or an encoded command |
| Java libraries reading hardware IDs (`ipconfig /all`, `wmic`, `tasklist`, `getmac`, `reg`) | Those tools are left out |
| Java desktop programs opening a link (`rundll32 url.dll,FileProtocolHandler`) | `rundll32` is left out |
| A shell from Java with no command line recorded | The selection is unknown, never a signal |

The rule ships 11 tests (4 that must match, 7 look-alikes that must not). `signal rules -check -rules .\rules` reports none failed.

## Proof

Tested end to end on 2026-11-18, on Windows 11 with Security process-creation auditing (with command lines) and Sysmon. A harmless Java program, below, made `java.exe` the parent of the processes an attacker's first commands would create. It contains no exploit code, and that CPU cannot trigger Java4Shell.

| Child of `java.exe` | Result |
|---|---|
| `whoami` | **signal** (Security 4688, corroborated by Sysmon 1) |
| `cmd.exe /c "whoami /groups"` | **signal** |
| `cmd.exe /c "whoami && ping -n 1800 127.0.0.1"` (still running) | **signal**, also seen live as a running process |
| `cmd.exe /c "echo build step"` (decoy) | no signal |

A run of this rule alone took 1.1 s: `-m Executions`, every other Executions rule suppressed by a profile, and `-rules` pointing at a folder holding only this file.

```java
// Harmless simulation: java.exe starts what an attacker's first commands would start. No exploit.
public class IntelToSignalSim {
    static Process run(String... cmd) throws Exception {
        return new ProcessBuilder(cmd).inheritIO().start();
    }
    public static void main(String[] args) throws Exception {
        run("whoami").waitFor();                                        // must match
        run("cmd.exe", "/c", "whoami /groups").waitFor();               // must match
        run("cmd.exe", "/c", "echo build step").waitFor();              // decoy: must not match
        run("cmd.exe", "/c", "whoami && ping -n 300 127.0.0.1 >nul").waitFor(); // match, also while running
    }
}
```

Run it from PowerShell with a JDK 11 or newer: `java IntelToSignalSim.java`. Then, in an elevated prompt, run Signal with the rule (below). Uninstall the JDK afterwards if you installed it only for this.

## What's needed

- Process creation auditing with command lines (Security 4688), or Sysmon event 1.
- Signal 1.0.1 or newer: [intrusion.academy/signal](https://intrusion.academy/signal).
- This rule: [github.com/intrusion-academy/Signal-Rules](https://github.com/intrusion-academy/Signal-Rules).

## Hunt and assess now

1. **Hunt.** In an elevated prompt:

   ```
   signal live -m Executions -rules .\Signal-Rules\rules -o \\fileserver\signal-runs\
   ```

   On a signal: read the command line and the account, then find which application the Java process was from its own command line (`-jar`, the class path, the install folder). Read that application's access log at that minute for the request that caused it.
2. **Assess.** List Java 17.0.6+ installs on servers with AVX-512 VBMI CPUs (Ice Lake or newer Xeon, Zen 4 or newer EPYC). Patch to the November 2026 updates, and follow your vendor's advice on stopgaps.
3. **Prepare.** Turn on process creation auditing with command lines, or Sysmon, before you need it.

## References

- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/) · [Horizon3.ai](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-114938/) · [VulnCheck](https://www.vulncheck.com/blog/java4shell) · [Blackpoint Cyber](https://blackpointcyber.com/blog/java4shell-cve-2026-114938-java-base64-decoder-flaw/) · [SecurityWeek](https://www.securityweek.com/java4shell-vulnerability-puts-many-enterprise-applications-at-risk-of-takeover/) · [Cisco Talos](https://blog.talosintelligence.com/java4shell/) · [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now)
- OpenJDK 21 source: `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`, `src/hotspot/cpu/x86/vm_version_x86.cpp`

Found a false positive? [Report it](../../../issues/new/choose). Have a better version? Open a pull request.
