# Incident Report: Rogue Inbound Firewall Rule (TCP 9009)

Nov 8, 2026 · @Jeff Dingess

A vendor motherboard utility running as SYSTEM silently added 592 identical, wide-open inbound firewall rules for TCP port 9009 on a home Windows 11 workstation; the source was identified through event-log correlation, removed, and the host hardened.

## Summary

Root cause was vendor software behaving badly, not malware: Gigabyte's GCloud service re-added its firewall exception at every start without checking for an existing one.

| Field | Detail |
| --- | --- |
| Asset | Home workstation: Gigabyte B550 GAMING X V2 (rev 1.3), Windows 11 Pro |
| Finding | 592 duplicate inbound rules named "allow 9009": TCP 9009, any program, any profile, any remote address |
| Source | GCloud.exe (service Gservice, part of Gigabyte APP Center), running as SYSTEM |
| Exposure | GCloud bound an HTTP listener on port 9009 on the LAN address, the Hyper-V virtual switch and localhost |
| Exploitation | Not observed; not fully assessed (firewall connection logging was off) |
| Severity | Medium: SYSTEM-level web service reachable from the LAN through an unrestricted rule |
| Status | Closed. Rules removed, service disabled, host hardened; two open items remain |

## Timeline

Rules accumulated over about 16 days of boots; detection to verified fix took one working session. Times are local (Pacific).

| When | Event |
| --- | --- |
| 2026-10-12 | Gigabyte chipset drivers, APP Center and RGB utilities installed on a fresh build |
| 2026-10-12 to 10-28 | GCloud re-adds "allow 9009" at each service start; 592 copies accumulate |
| 2026-10-28 22:35:42 | Last rule-added event in the firewall log: netsh.exe (32-bit) run as SYSTEM |
| 2026-11-07 | Inbound-rule audit flags 592 identical "allow 9009" rules |
| 2026-11-07 | Event-log correlation attributes the rule to GCloud.exe |
| 2026-11-07 | Containment: firewall config exported, all 592 rules deleted, Gservice disabled |
| 2026-11-07 | Verified after two reboots: rule count 0, service stays disabled |
| 2026-11-07 to 11-08 | Eradication and hardening: utilities removed, BIOS updated FC to FHc, Secure Boot, SVM and Memory Integrity enabled |

## Detection and analysis

The attribution came from correlating two logs within the same second, not from guessing by port number.

**Audit.** Listed every enabled inbound allow rule with PowerShell (Get-NetFirewallRule). One name, "allow 9009", appeared 592 times.

**Rule scope.** Port filter TCP 9009; application filter Any; address filter Any; profile Any; no description. A script-written rule, not one an installer UI creates.

**Listener check.** Nothing listening on 9009 at the time (Get-NetTCPConnection, Get-NetUDPEndpoint). Note: HTTP.sys listeners show as PID 4 (System), so this check alone can miss them.

**Firewall log.** The rule-added event showed Modifying User S-1-5-18 (SYSTEM) and Modifying Application C:\Windows\SysWOW64\netsh.exe: a 32-bit program running as SYSTEM.

**Persistence sweep.** No scheduled task, service command line or script file under Program Files or ProgramData referenced netsh or 9009.

**Correlation.** Pulled every Application and System event from 10 minutes before to 5 minutes after the rule was added. In the same second:

HCLOUD: NAT POST:Set_Firewall:Set firewall port:9009

GCloud: service started successfully

HttpService 113: URL reservations on port 9009 for the LAN address, the Hyper-V switch and 127.0.0.1, by C:\Program Files (x86)\GIGABYTE\GService\GCloud.exe as SYSTEM

**Conclusion.** GCloud adds the rule on every start without checking for a duplicate, then serves HTTP on port 9009 to the LAN.

Related finding: GigabyteUpdateService is dropped by the firmware at each boot (the 2023 Eclypsium report on Gigabyte's download assistant). The installed BIOS (FC, June 2023) already carried Gigabyte's fix, and this board offers no BIOS switch to stop the drop.

## Containment, eradication and recovery

Every action was verified by a command whose output could be checked, and each change was reversible until confirmed.

| Phase | Action | Verified by |
| --- | --- | --- |
| Contain | Exported firewall config as a rollback point (netsh advfirewall export) | Backup file present |
| Contain | Deleted all 592 "allow 9009" rules | Rule count 0, still 0 after two reboots |
| Contain | Stopped and disabled Gservice (GCloud) | Service shows Stopped / Disabled after reboot |
| Contain | Disabled unused inbound rules: Remote Desktop, Remote Assistance, Armoury Crate debug and socket servers, Teredo, Lync | Rules show Enabled = False |
| Eradicate | Uninstalled Gigabyte APP Center, GService, SIV, @BIOS, Smart Backup, EasyTune, RGB Fusion | Uninstall entries removed |
| Eradicate | Uninstalled cFosSpeed ("Gigabyte Speed"), which ran its own HTTP listener on all interfaces (port 1487) | Service no longer present |
| Eradicate | Disabled leftover MyService1 (GIGABYTE Adjust) | Stopped / Disabled |
| Recover | Updated BIOS FC (2023) to FHc (Aug 2026): fixes for LogoFAIL, Sinkclose, CVE-2024-36347, CVE-2025-2884, CVE-2026-6726/6727 | Win32_BIOS reports FHc |
| Recover | Restored Secure Boot factory keys (system moved from Setup to User mode) and enabled Secure Boot | Confirm-SecureBootUEFI = True |
| Recover | Enabled SVM and Memory Integrity (HVCI) | Hypervisor present; VBS status 2, HVCI running |
| Harden | Scoped 22 crypto-node and dev-server rules to Private profile, LocalSubnet, edge traversal blocked | Rule table shows Private / Block / LocalSubnet |

During the BIOS update, Q-Flash could not read the file from an installer-formatted USB stick; a single-partition FAT32 stick on a different rear port worked. After the update, the NVMe boot drive twice failed to enumerate after a warm restart; a full power cycle restored it, and later restarts were normal.

BitLocker was enabled, then rolled back by owner decision because of the lockout risk on hardware that had just shown boot faults. A recovery key printed to the console during setup was treated as exposed and rotated before rollback.

## Lessons learned and open items

The main lesson: vendor utilities installed with drivers can open network services with SYSTEM rights, and only a periodic rule audit catches them.

**Audit inbound rules after installing hardware software.** A rule-count check would have caught this on day one instead of after 592 boots.

**A port number is not attribution.** The firewall log named only netsh; the parent process came from correlating events in the same second.

**Check HTTP.sys reservations** (netsh http show servicestate) as well as socket listeners, since HTTP.sys services hide behind PID 4.

**Firmware can reinstall software.** Disabling a service in Windows does not stop a WPBT drop; the fix is a BIOS update or BIOS setting.

**Weigh lockout risk before encryption.** Full-disk encryption on hardware with an unresolved boot fault adds risk; it was rolled back rather than forced.

**Never let a secret reach shared output.** A recovery key printed to the console was rotated right away.

Open items:

☐ Run a Microsoft Defender Offline scan (recommended, not yet performed)

☐ Turn on Windows Firewall logging of dropped and allowed connections, so future exposure can be assessed

☐ Verify the ISP gateway's IPv6 firewall (admin access not yet recovered)

☐ Watch for a repeat of the NVMe boot drive failing to enumerate; if it recurs, check the SSD firmware

## Skills demonstrated

The work followed the NIST SP 800-61 incident response lifecycle taught in the Google Cybersecurity Certificate.

| NIST phase | What was done | Tools |
| --- | --- | --- |
| Preparation | Took a firewall config backup before changes; confirmed drive-encryption status before the BIOS flash | netsh advfirewall export, Get-BitLockerVolume |
| Detection and analysis | Rule audit, scope analysis, Windows event-log correlation, persistence sweep | PowerShell NetSecurity cmdlets, Get-WinEvent, Get-ScheduledTask, Win32_Service |
| Containment, eradication and recovery | Rule removal, service disablement, software removal, firmware update, Secure Boot and HVCI | PowerShell, Gigabyte Q-Flash, UEFI setup |
| Post-incident activity | This report, lessons learned, open items tracked |  |

Also shown: least-privilege network scoping (LocalSubnet rules), change verification after each step, and risk-based rollback of a change (BitLocker).
