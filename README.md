# Windows Endpoint Monitoring with Splunk and Sysmon

This is a beginner SOC lab using Sysmon and Splunk to collect and analyze Windows endpoint logs.

This project focuses on setting up Splunk Enterprise on Windows and preparing it to collect Windows Event Logs and Sysmon logs for basic endpoint monitoring.

## Setting Up Sysmon

After installing Splunk, I moved to the next step: setting up Sysmon on my Windows machine.

Sysmon was downloaded from the official Microsoft Sysinternals page. The file came as a ZIP folder, so I extracted it before installation.

I extracted Sysmon to the following folder:

```text
C:\Tools\Sysmon
After extraction, the Sysmon folder contained the required files:
Sysmon.exe
Sysmon64.exe
Sysmon64a.exe
Eula.txt
This confirmed that sysmon was extracted syccessfully and was ready for installation using powershell

##Opening Sysmon from Command Prompt
**Sysmon is not installed by double-clicking the file.**
 It needs to be installed using PowerShell or Command Prompt with administrator permissions.

I opened Command Prompt as Administrator and navigated to the extracted Sysmon folder:
cd "C:\Users\swetha\OneDrive\Downloads\Sysmon"

Then I checked the extracted files using

dir

After confirming that Sysmon64.exe was available,I installed Sysmon using:

Sysmon64.exe -accepteula -i

The installation, sysmon created the required windows service and driver:

Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
Starting Sysmon.

This confirmed that Sysmon was installed successfully and was ready to generate endpoint logs for splunk analysis.
