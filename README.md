# 🎯 Threat-Hunting-Scenario-Assistance

<img width="800" height="500" alt="threat-hunt-assistance" src="https://github.com/user-attachments/assets/68e724f8-a7e1-4c3f-88df-0365c94e6cb9" />


**Participant:** Jamal Copeland

**Date:** 11 November 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts
* Native Windows utilities: `powershell.exe`, `cmd.exe`, `schtasks.exe`, `csc.exe`

---


 # 📖 **Scenario**
 
A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

## Starting Point

Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given: 

1. Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

🕵️ **Identify the first machine to look at**

Query used:
```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-17))
| where InitiatingProcessAccountName != "system"
| where ActionType == "FileCreated"
| where FolderPath contains "download" or InitiatingProcessFolderPath contains "download"
| where FileName contains "desk" or FileName contains "help" or FileName contains "support" or FileName contains "tool"
| where InitiatingProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, ReportId, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

🧠 **Thought process:** I focused on the first half of October because that’s when multiple machines reportedly began spawning suspicious downloads. From there, I filtered out system-driven noise and targeted user-initiated file creations in the Downloads folder that matched the attacker’s naming patterns and PowerShell execution behavior. Sorting the refined dataset by time allowed me to pinpoint the earliest host showing this pattern and establish the proper starting point for the hunt.

<img width="1506" height="411" alt="flag1-deviceName" src="https://github.com/user-attachments/assets/db18355e-d0e8-4837-b381-413b44d67b6d" />


**Answer: gab-intern-vm**

---

## 🟩 Flag 1 – Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:**
Look for atypical script or interactive command activity that deviates from normal user behavior or baseline patterns.

**Thought:**
Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.

🧠 **Thought process:** I figured, since the first thing you do once you get remote access is type whoami, so I searched for that command in the command line. I found a command 'whoami' of which SHA256 was the right answer, BUT upon inspecting the SHA256 for actual clues of recon, I used the KQL below to find a lot of clues for example commands like whoami, schtasks, and deleting evidence of onedrivesetup. The evidence of the attacker being present was overwhelming.

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) ..datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "downloads" 
| project TimeGenerated, ActionType, ProcessCommandLine, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, ReportId, InitiatingProcessCommandLine
```

<img width="1442" height="272" alt="flag1-InitialExecution" src="https://github.com/user-attachments/assets/273440d9-eb2b-412d-86ec-d6fa281679ee" />


**Answer: -ExecutionPolicy**

## 🟩 Flag 2 – Defense Disabling

**Objective:**

Identify indicators that suggest attempts to imply or simulate changing security posture.

Query used:
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where InitiatingProcessAccountName == "g4bri3lintern"
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "artifact"
```

🧠 **Thought process:** I used DeviceProcessEvents within the given date range and filtered on the g4bri3lintern account and gab-intern-vm to focus on the intern’s activity. From there, I searched for command lines containing the keyword "artifact", which led me to the process referencing DefenderTamperArtifact.lnk as the file related to this exploit.

<img width="975" height="298" alt="image" src="https://github.com/user-attachments/assets/d34db1ac-d624-45ba-a256-b7cefac70eca" />


**Answer: DefenderTamperArtifact.lnk**

---

## 🟩 Flag 3 – Quick Data Probe

**Objective:**

Spot brief attempts to access transient sensitive data.

**What to Hunt:**

Clipboard or lightweight data queries.

**Thought:**

Clipboard access is a classic low-effort probe, so I filtered for commands referencing it. The result showed a silent clipboard read attempt.

Query used:
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("Get-Clipboard","Set-Clipboard","Get-Clipboard -","clip.exe","/c clip","-clip","clipboard")
```
<img width="975" height="192" alt="image" src="https://github.com/user-attachments/assets/553e777a-eb50-4ede-90bb-05d933248466" />

**Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"**

---

## 🟩 Flag 4 – Host Context Recon

**Objective:**

Find activity gathering basic system or user context.

**What to Hunt:**

Recon commands such as hostname, whoami, or environment checks.

**Thought:**

By filtering recon-style command fragments, I pinpointed the last executed context query. This timestamp aligned with ongoing situational awareness checks.

Query used: 
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="975" height="377" alt="image" src="https://github.com/user-attachments/assets/392a2084-9207-4066-b704-8c496841f6f7" />

**Answer: 2025-10-09T12:51:44.3425653Z**

---

## 🟩 Flag 5 – Storage Surface Mapping

**Objective:**

Detect discovery of local or network storage locations that might hold interesting data.

**What to Hunt:**

Look for enumeration of filesystem or share surfaces and lightweight checks of available storage.

**Thought:**

Abusing trusted binaries helps attackers blend in — keep an eye on LOLBins.


 🕵️ **Provide the command value associated with the initial exploit**

Query used: same as query #4

<img width="975" height="377" alt="image" src="https://github.com/user-attachments/assets/517461d7-5ca3-433d-b609-309afb98ef5a" />


**Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size"**

---

## 🟩 Flag 6 – Connectivity & Name Resolution Check

**Objective:**

Identify checks that validate network reachability and name resolution.

**What to Hunt:**

Network or process events indicating DNS or interface queries and simple outward connectivity probes.

Query used:

```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName == "powershell.exe"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, ActionType, InitiatingProcessParentFileName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

<img width="2276" height="243" alt="image" src="https://github.com/user-attachments/assets/9ae0dfc7-9adc-487f-a370-5dc29c4d5602" />


**Answer: RuntimeBroker.exe**

---

## 🟩 Flag 7 – Interactive Session Discovery

**Objective:**

Reveal attempts to detect interactive or active user sessions on the host.

**What to Hunt:**

Signals that enumerate current session state or logged-in sessions without initiating a takeover.

**Thought:**

Knowing which sessions are active helps an actor decide whether to act immediately or wait.

 🕵️ **What is the unique ID of the initiating process**

Query used:

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessUniqueId, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="2268" height="243" alt="image" src="https://github.com/user-attachments/assets/a255780f-2ced-4549-821a-58032b117b9b" />

**Answer: 2533274790397065**

---

## 🟩 Flag 8 – Runtime Application Inventory

**Objective:**

Detect enumeration of running applications and services to inform risk and opportunity.

**What to Hunt:**

Events that capture broad process/process-list snapshots or queries of running services.

**Thought:**

A process inventory shows what’s present and what to avoid or target for collection.

 🕵️ **Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host.**

Query used:

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "tasklist"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessUniqueId, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="2166" height="180" alt="image" src="https://github.com/user-attachments/assets/6543d75e-dc95-4dc7-a73d-b244e97b3649" />

**Answer: tasklist.exe**

**Notes:**

Searching for enumeration binaries quickly surfaced tasklist.exe. Its execution indicated a full process inventory snapshot.

---

## 🟩 Flag 9 – Privilege Surface Check

**Objective:**

Detect attempts to understand privileges available to the current actor.

**What to Hunt:**

Telemetry that reflects queries of group membership, token properties, or privilege listings.

**Thought:**

Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

 🕵️ **Identify the timestamp of the very first attempt**

Query used:

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "who"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessUniqueId, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

🧠 **Thought process:** Privilege checks frequently appear early in an attack chain, so I sorted whoami use chronologically. The first timestamp revealed when the actor mapped their rights.

<img width="2079" height="295" alt="image" src="https://github.com/user-attachments/assets/78d513d8-05b9-4064-ab50-82b404bd6660" />

**Answer: 10/9/2025, 12:52:14.313 PM**

---

## 🟩 Flag 10 – Proof-of-Access & Egress Validation

**Objective:**

Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**What to Hunt:**

Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data.

**Thought:**

This step demonstrates both access and the potential to move meaningful data off the host...

 🕵️ **Which outbound destination was contacted first?**

Query used:

```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName == "powershell.exe"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, ActionType, InitiatingProcessParentFileName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

🧠 **Thought process:** Connectivity test domains are common egress validators, so I filtered for them explicitly. The first such outbound was to Microsoft’s connectivity endpoint.

<img width="2271" height="247" alt="image" src="https://github.com/user-attachments/assets/01825fda-9137-47db-9db0-ea1bbba0cd9a" />

**Answer: www.msftconnecttest.com**

---

## 🟩 Flag 11 – Bundling / Staging Artifacts

**Objective:**

Identify the remote machine the attacker pivoted to next.

**What to Hunt:**

File system events or operations that show grouping, consolidation, or packaging of gathered items.

**Thought:**

Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

 🕵️ **Provide the full folder path value where the artifact was first dropped into**

Query used: 
```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName != "system"
| project 
    TimeGenerated,
    DeviceName,
    FolderPath,
    FileName, 
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    ActionType, InitiatingProcessParentFileName
| where FileName contains "artifact"
| sort by TimeGenerated desc
```

<img width="975" height="79" alt="image" src="https://github.com/user-attachments/assets/3e70e953-b448-4f4e-81f3-cfc326f9cc83" />

**Answer: C:\Users\Public\ReconArtifacts.zip**

---

## 🟩 Flag 12 – Outbound Transfer Attempt (Simulated)

**Objective:**

Identify attempts to move data off-host or test upload capability.

**What to Hunt:**

Network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**Thought:**

Succeeded or not, attempt is still proof of intent — and it reveals egress paths or block points.

 🕵️ **Provide the IP of the last unusual outbound connection**

Query used:

```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where InitiatingProcessAccountName contains "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, LocalIP, RemoteIP, RemoteUrl
```

<img width="975" height="122" alt="image" src="https://github.com/user-attachments/assets/1022749e-c35b-444e-8a57-1303d5b0a889" />

**Answer: 100.29.147.161**

---

## 🟩 Flag 13 – Scheduled Re-Execution Persistence

**Objective:**

Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**What to Hunt:**

Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:**

Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

 🕵️ **What was the name of the registry value**

Query used: Used previous queries

**Answer: SupportToolUpdater**

---

## 🟩 Flag 14 – Autorun Fallback Persistence

**Objective:**

Spot lightweight autorun entries placed as backup persistence in user scope.

**What to Hunt:**

Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:**

Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

 🕵️ **What was the name of the registry value**

**Answer: RemoteAssistUpdater**

---

## 🟩 Flag 15 – Planted Narrative / Cover Artifact

**Objective:**

Identify a narrative or explanatory artifact intended to justify the activity.

**What to Hunt:**

Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

 🕵️ **Identify the file name of the artifact left behind**

Query used:

```
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-17))
| where InitiatingProcessAccountName contains "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, LocalIP, RemoteIP, RemoteUrl
```

**Answer: SupportChat_log.lnk**

---

## ✅ Conclusion

This “support session” was a full intrusion, not a misunderstanding.

The attacker gained an initial foothold on gab-intern-vm via “desk/help/support/tool”-style binaries launched from the Downloads folder, then immediately shifted into living-off-the-land behavior using native binaries like powershell.exe, cmd.exe, wmic, schtasks.exe, and tasklist.exe. They:

- Ran recon of the host and user context (whoami, clipboard probing, task and disk enumeration).

- Mapped storage with wmic logicaldisk get name,freespace,size.

- Validated outbound connectivity (e.g., www.msftconnecttest.com) before reaching out to an unusual IP: 100.29.147.161.

- Bundled local findings into C:\Users\Public\ReconArtifacts.zip for staging and potential exfiltration.

- Established persistence via scheduled/autorun mechanisms (e.g., RemoteAssistUpdater-style registry entries and Defender tamper artifacts).

- Planted SupportChat_log.lnk as a narrative cover to make activity look like benign remote assistance.

The activity chain shows clear intent, capability, and stealth: initial access, recon, staging, exfil path testing, persistence, and an attempted “clean” storyline. The relative lack of noisy malware and the reliance on LOLBins and clean logs indicates a deliberate anti-forensic approach.
