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
DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

🧠 **Thought process:** I sorted the results by file name, that way it was easy to sift through the results and find the odd one out.

<img width="400" src="https://github.com/user-attachments/assets/8f2dce56-934b-4bd4-95b2-32f67088554c"/>

**Answer: RuntimeBroker.exe**

---

## 🟩 Flag 7 – HTA Abuse via LOLBin

**Objective:**

Detect execution of HTML Application files using trusted Windows tools.

**What to Hunt:**

Execution via `mshta.exe` pointing to local HTA scripts.

**Thought:**

HTA-based execution is a social engineering favorite — it leverages trust and native execution.

 🕵️ **Provide the value of the command associated with the exploit**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has ".hta"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| order by Timestamp asc
```

🧠 **Thought process:** The hints were good enough for me to find the results directly, where file name was mshta.exe and command line having .hta extensions

<img width="600" src="https://github.com/user-attachments/assets/a0c40640-28f7-45bc-9314-2a502cfef238"/>

**Answer: "mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta**

---

## 🟩 Flag 8 – ADS Execution Attempt

**Objective:**

Track if attackers stored payloads in Alternate Data Streams (ADS).

**What to Hunt:**

DLLs hidden in common file types like `.docx` with `:hidden.dll` behavior.

**Thought:**

ADS hides in plain sight — it’s a classic LOLBin trick to store malware where few would look.

**Hint:**

1. Capitalist

 🕵️ **Provide the SHA1 value associated**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15) .. datetime(2025-06-19))
| where InitiatingProcessCommandLine has ":"
| where InitiatingProcessCommandLine has ".dll"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp desc
```

🧠 **Thought process:** I filtered for the command line having ":" and ".dll" in it, according to the hint. The compattelrunner.exe sounds like Capitalist, so I figured it's the answer which it was. Upon further inspection, I could see that Write-Host 'Final result: 1' command was run before the compattelrunner.exe scan. It's faking the result of a scan — potentially to mimic a real system check or mislead defenders. Then, the second command does the actual .inf scan. This staged behavior is often seen in malware to print fake result (decoy), actually scan system or possibly drop drivers or persistence tools.

<img width="400" src="https://github.com/user-attachments/assets/97c83a1b-8bcc-4b15-ab39-c49512c362cd"/>

**Answer: 801262e122db6a2e758962896f260b55bbd0136a**

---

## 🟩 Flag 9 – Registry Persistence Confirmation

**Objective:**

Confirm that persistence was achieved via registry autorun keys.

**What to Hunt:**

Registry path and value that re-executes the attack script.

**Thought:**

Once in the registry, an attacker can survive reboots — making this a prime persistence marker.

 🕵️ **Provide the value of the registry tied to this particular exploit**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where RegistryKey endswith @"CurrentVersion\Run"
     or RegistryKey endswith @"CurrentVersion\RunOnce"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

🧠 **Thought process:** I just looked for commands Run or RunOnce within the RegistryKey where these persistence methods usually are, and it gave me the answer.

<img width="800" src="https://github.com/user-attachments/assets/d6ceceae-d855-4dc6-a1ce-4f929e5e9dca"/>

**Answer: HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run**

---

## 🟩 Flag 10 – Scheduled Task Execution

**Objective:**

Validate the scheduled task that launches the payload.

**What to Hunt:**

Name of the task tied to the attack’s execution flow.

**Thought:**

Even if stealthy, scheduled tasks leave clear creation trails. Look for unfamiliar task names.

 🕵️ **What is the name of the scheduled task created**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** I looked for scheduled tasks and found what I was looking for and more.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: MarketHarvestJob**

---

## 🟩 Flag 11 – Target of Lateral Movement

**Objective:**

Identify the remote machine the attacker pivoted to next.

**What to Hunt:**

Remote system name embedded in command-line activity.

**Thought:**

The attack is expanding. Recognizing lateral targets is key to containment.

 🕵️ **Drop the next compromised machine name**

Query used: same as flag 10

🧠 **Thought process:** In the previous flag I spotted lateral movement to a different machine as a scheduled task. I also noticed it at flag 2 where I looked into the SHA256.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: centralsrvr**

---

## 🟩 Flag 12 – Lateral Move Timestamp

**Objective:**

Pinpoint the exact time of lateral move to the second system.

**What to Hunt:**

Execution timestamps of commands aimed at the new host.

**Thought:**

Timing matters — it allows us to reconstruct the attack window on the second host.

 🕵️ **When was the last lateral execution?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has "C2.ps1"
```

🧠 **Thought process:** From the previous flag, I gathered enough evidence to jump directly to the lateral movement execution with the above query.

<img width="250" src="https://github.com/user-attachments/assets/67306d9b-279b-45a5-83a1-df6a47c916c1"/>

**Answer: 2025-06-17T03:00:49.525038Z**

---

## 🟩 Flag 13 – Sensitive File Access

**Objective:**

Reveal which specific document the attacker was after.

**What to Hunt:**

Verify if the attackers were after a similar file

**Thought:**

The goal is rarely just control — it’s the data. Identifying what they wanted is vital.

**Hint:**

1. Utilize previous findings

 🕵️ **Provide the standard hash value associated with the file**

Query used:

```
DeviceFileEvents
| where DeviceName == "centralsrvr"
| where FileName == "QuarterlyCryptoHoldings.docx"
| project Timestamp, FileName, SHA256, FolderPath, InitiatingProcessFileName
```

🧠 **Thought process:** I assumed, according to the hint, that the file they were after was the same one as in flag 3, so I jumped directly to that file and got the SHA256 of the QuarterlyCryptoHoldings.docx file.

<img width="400" src="https://github.com/user-attachments/assets/58ec4895-d925-4468-b5b2-9c5109d7ffac"/>

**Answer: b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98**

---

## 🟩 Flag 14 – Data Exfiltration Attempt

**Objective:**

Validate outbound activity by hashing the process involved.

**What to Hunt:**

Process hash related to exfiltration to common outbound services.

**Thought:**

Exfil isn’t just about the connection — process lineage shows who initiated the theft.

 🕵️ **Provide the associated MD5 value of the exploit**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where InitiatingProcessCommandLine contains "exfiltrate"
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessMD5
```

🧠 **Thought process:** This flag was a little bit of a challenge, but I sifted through a lot of files throughout the hunt, where I found some exfiltratedata.ps1 executables, but was not sure if it was there for just noise or to throw me off. I played around with the KQL to lower the amount of logs shown and found that the above-mentioned executable was actually the one responsible for exfiltration.

<img width="600" src="https://github.com/user-attachments/assets/cb9dd4b7-2e56-47c9-b6fb-09e902e1fcf6"/>

**Answer: 2e5a8590cf6848968fc23de3fa1e25f1**

---

## 🟩 Flag 15 – Destination of Exfiltration

**Objective:**

Identify final IP address used for data exfiltration.

**What to Hunt:**

Remote IPs of known unauthorized cloud services.

**Thought:**

Knowing where data went informs response and informs IR/containment scope.

 🕵️ **Identify the IP of the last outbound connection attempt**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where RemoteUrl in~ (
   "drive.google.com",
   "dropbox.com",
   "www.dropbox.com",
   "pastebin.com",
   "dw8wjz3q0i4gj.cloudfront.net",
   "o.ss2.us"
)
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessSHA256
| sort by Timestamp desc
```

🧠 **Thought process:** I filtered for the remote URLs that I noticed could be a third-party unauthorized cloud service, and I only had 4 IPs to choose from, and in the end, it was the IP of pastebin.com

<img width="600" src="https://github.com/user-attachments/assets/4db9f414-56df-4e73-b30c-cd5d664bae8d"/>

**Answer: 104.22.69.199**

---

## 🟩 Flag Flag 16 – PowerShell Downgrade Detection

**Objective:**

Spot PowerShell version manipulation to avoid logging.

**What to Hunt:**

`-Version 2` execution flag in process command lines.

**Thought:**

This signals AMSI evasion — it’s a red flag tactic to bypass modern defenses.

 🕵️ **When was a downgrade attempt executed?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "-Version 2"
```

🧠 **Thought process:** This was a pretty straightforward flag since the hints gave away what to look for. Once I queried the -Version 2 in the process command line, I had my answer.

<img width="300" src="https://github.com/user-attachments/assets/a501e571-2329-48cf-8df4-edbbb27855ef"/>

**Answer: 2025-06-18T10:52:59.0847063Z**

---

## 🟩 Flag 17 – Log Clearing Attempt

**Objective:**

Catch attacker efforts to cover their tracks.

**What to Hunt:**

Use of `wevtutil cl Security` to clear event logs.

**Thought:**

Cleaning logs shows intent to persist without a trace — it's often one of the final steps before attacker exit.

 🕵️ **Identify the process creation date**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine has_any ("wevtutil", "cl Security")
```

🧠 **Thought process:** The last flag was, at a glance, very simple, but it had a little twist to it. I found what I was looking for immediately, but I had trouble giving in the right time. The question was set as "identifying the process creation time" and not just a Timestamp. At a glance, these two times look the same, so I always just posted the Timestamp time, but after countless hours of questioning myself, I realized what the question is actually asking for.

<img width="250" src="https://github.com/user-attachments/assets/460a7771-351e-4171-9ef6-dbf9118880ad"/>

**Answer: 2025-06-18T10:52:33.3030998Z**

---

## ✅ Conclusion

The attacker leveraged native tools and LOLBins to evade detection, accessed high-value documents, and stealthily exfiltrated them while maintaining persistence. The clean logs indicate deliberate obfuscation and anti-forensic effort.

🛡️ **Recommendations**

	•	Block LOLBins like bitsadmin, mshta via AppLocker or WDAC
	•	Enable script block logging and AMSI
	•	Monitor for PowerShell downgrade attempts (-Version 2)
	•	Watch for registry changes in autorun paths
	•	Alert on suspicious scheduled task creation
	•	Monitor public cloud uploads (e.g. Dropbox, Pastebin)


“Attackers hide in noise. But sometimes, they hide in silence.”
