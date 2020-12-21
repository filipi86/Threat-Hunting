![](media/image1.png){width="8.472916666666666in"
height="8.819538495188102in"}![](media/image3.png){width="0.6041666666666666in"
height="0.6041666666666666in"}![](media/image4.png){width="2.4680555555555554in"
height="1.19375in"}![](media/image5.jpg){width="8.558194444444444in"
height="5.327999781277341in"}

![](media/image6.png){width="2.402083333333333in"
height="0.5666666666666667in"}

> **SOPHOS**
>
> **Detection Report**
>
> **"TheZoo"**![](media/image5.jpg){width="8.550751312335958in"
> height="5.344000437445319in"}

**\
ZUP Security Labs at Zup Innovation**

**Researcher Manager (s): Filipi Pires**

# Introduction

> The purpose of this document, it was to execute several efficiency and
> detection tests in our endpoint solution, provided by Sophos, this
> document brings the result of the defensive security analysis with an
> offensive mindset performed in the execution of 27 folders download
> with **Malwares by The Zoo** repository in our environment.
>
> Regarding the test performed, the first objective it was to simulate
> targeted attacks using known malware to obtain a panoramic view of the
> resilience presented by the solution, with regard to the efficiency in
> its detection by signatures, downloading these artifacts directly on
> the victim\'s machine. The second objective consisted of analyzing the
> detection of those same 27 folders download with Malwares (or those
> not detected yet) when they were changed directories, the idea here is
> to work with manipulation of samples (without execution), and the
> third focal objective it was the execution of a *ScanNow* inside
> victim\'s machines for effectiveness analysis.
>
> With the final product, the front responsible for the product will
> have an instrument capable of guiding a process of mitigation and / or
> correction, as well as optimized improvement, based on the criticality
> of risks.

## Scope

> The efficiency and detection analysis had as target the Cybereason
> Endpoint Protection application (https://cloud.sophos.com) in
> **Version :**

-   **Agent Version = 10.8.9 VE3.79.0**

-   **Core Agent -- 2.10.7 BETA**

-   **Endpoint Advanced 10.8.9.1 BETA**

-   **Sophos Intercept X 2.0.17 BETA**

-   **Device Encryption 2.0.82**

> Installed in the windows machine Windows 10 Pro;
>
> ***Hostname*** - Threat-Hunting-Win10-POC, as you can see in the
> picture below:

![](media/image7.png){width="6.485075459317585in"
height="3.4977285651793526in"}

> **Image 1.1:** Windows 10 Pro 2019 Virtual Machine

## Project Summary 

> The execution of the security analysis tests of the Threat Hunting
> team it was carried out through the execution of 42 Malwares in a
> virtualized environment in a controlled way, simulating a real
> environment, together with their respective best practices of the
> security policies applied, the test occurred during **2 days**,
> without count the weekend, along with the making of this document. The
> intrusion test started on the **24th of September** of the year 2020
> and it was completed on the **28th of September** of the same year.

#  Running the Tests

### 3.1 Description

> A virtual machine with Windows 10 operating system it was deployed to
> perform the appropriate tests, as well as the creation of a security
> policy on the management platform (Threat-Hunting--Win10-POC) e and
> applied to due device.

![](media/image8.png){width="6.756944444444445in"
height="4.088888888888889in"}

> **Image 1.2:** Virtual Machine with Policy applied
>
> The policy created was named **Threat-Hunting--Win10-POC**, following
> the best practices recommended by the manufacturer, and, for testing
> purposes, all due actions were based on an aggressive detection
> method.

![](media/image9.png){width="7.073997156605424in"
height="2.301774934383202in"}

> **Image 1.3:** Policy created by Sophos Central

### 3.2 First Test 

> The first stage of the tests was through the download of 27 folders
> with many different kind of malwares, all of which are already known
> to be older, all of them are in the public repository known and
> maintained by the security community called **The Zoo**
> (<https://github.com/ytisf/theZoo/tree/master/malwares/Binaries>);

![](media/image10.png){width="6.623828740157481in"
height="3.727224409448819in"}

> **Image 1.4:** Download 27 Folders with malicious files
>
> The purpose of this test was to simulate the same process as a user
> receiving a zipped file (.zip) and performing the extraction of these
> artifacts in their own environment.

![](media/image11.png){width="4.45522419072616in"
height="4.372730752405949in"}

> **Image 1.5:** Extraction of 26 Folders with malicious files
>
> After performing the action of extracting the files, it was possible
> to verify that Sophos Security Endpoint there were currently **4
> (four) Malwares** that, when executed inside the environment, could
> perform an infection.

![](media/image12.png){width="6.475214348206475in"
height="3.643596894138233in"}

> **Image 1.6:** Malwares Not Detection by Sophos

### 3.3 Second Test 

> The second stage of the tests was through the transfer of folders to
> another directory within the same machine, the purpose of this test
> was to simulate a transfer of files within the same environment.

![](media/image13.png){width="6.750694444444444in"
height="3.798611111111111in"}

> **Image 1.7: \_\_**NEW_FOLDER\_\_(Sophoo) -- Malware manipulation
>
> When a new file is generated on the disk, soon we should have a new
> entry in a block of that disk and in theory the antivirus should take
> some action (considering that it has the real time enabled), we could
> define it as a file manipulation (still not running) where the
> endpoint protection is already necessary, considering that a new
> directory was created, soon we would have a new repository with
> several hashes inside to be examined..
>
> After performing this second test, we saw that the same 4 malwares
> there were detected yet, as we can see below and mentioned earlier,
> all these malware were already known and validated even in the tool
> about antivirus scanning known as a Virus Total
> ([https://virustotal.com](https://virustotal.com.br)).

![](media/image14.png){width="6.166666666666667in"
height="0.9583333333333334in"}

> **Image 1.8:** Malwares -- Not Detected

### 3.4 Third Test 

> The third stage of the tests was through the use of the *ScanNow*
> action by Cloud Sophos, to perform a complete scan on the machine,
> manually, in this way, all malware should be eliminated, as they are
> already known malware as mentioned earlier.

![](media/image15.png){width="6.356528871391076in"
height="6.022387357830271in"}

> **Image 1.9:** Malwares -- Not Detected after *ScanNow*
>
> After performing this third test and the execution of the ScanNow
> feature, we saw that the same 4 malwares there were detected yet, as
> we can see below and mentioned earlier, even all these malwares were
> already known.

![](media/image16.png){width="6.671642607174103in"
height="3.7541294838145234in"}

> **Image 1.10:** Malwares -- Not Detected after *ScanNow*

# Impact

### 

> At the end of this test, it was possible to verify that there are
> currently 4 known malware that, when executed inside the environment,
> may perform an infection.

-   **I-Worm.NewLove**

hxxps://github.com/ytisf/theZoo/tree/master/malwares/Binaries/VBS.NewLove.A

Basic Properties

MD5 95f4156f23d61b1b888d3b3bb87b6d72

SHA-1 09d2470d17821728cd1da95186f5f51272634287

SHA-256 2246a1a31f8ef272a8ac44c97d383d0607d86ddf4509a176b157853d9c6e0028

Vhash 773a411c5a56087d4d7c5cc36bbf2901

SSDEEP
1536:cfY1wBDtr94PLDcwZANv1pG1ZuQK10Oksk/L1xVCXJW5C6U7EjSRVveO:R1wBJoL4F1w6QK1qFnVCXJYCF7aO

Names

I-Worm.NewLove.zip

output.149790737.txt;

> Worm-type malware, with high criticality, associated with the
> execution of VBS - Visual Basic Script, we have as a characteristic
> high propagation within the environment in which it is executed.

![](media/image17.png){width="5.880597112860892in"
height="3.0635925196850393in"}

> **Image 1.10:** • I-Worm.NewLove.zip -- VirusTotal

-   **Win32.ZeroCleare ( soy.exe )**

hxxps://github.com/ytisf/theZoo/tree/master/malwares/Binaries/Win32.ZeroCleare

> **Trojan-type malware**, which has a dropper behavior, and is
> responsible for downloading other malware within the victim\'s
> environment, developed for Windows 7, Windows 8, Windows 8.1 and
> Windows 10 operating systems.

Basic Properties

MD5 c04236b5678af08c8b70a7aa696f87d5

SHA-1 4b713963f7f7032dda431d8042344febac017cf2

SHA-256 17cc26eb17b5562423dd47ddf6c3bbda34e69c0c65027fe659a9c0becf8438ef

Vhash cbfe429774b42621c19bbecbf0681ac1

SSDEEP
1536:wYFJsIiHyVaM2frJe31Uod74Fru71mTUscFDoRZe6m/fqhuFOnto7:wcWIiHmM8lkFyJmTvcBoze6m3qT2

**Names**

soy.exe

output.149792855.txt;

![](media/image18.png){width="6.272296587926509in"
height="3.701491688538933in"}

> **Image 1.11:** Win32.ZeroCleare (soy.exe) - VirusTotal

-   **OSX.Lazarus**

hxxps://github.com/ytisf/theZoo/blob/master/malwares/Binaries/OSX.Lazarus/

Basic Properties

MD5 bb66ab2db0bad88ac6b829085164cbbb

SHA-1 b16fcd3f5afe5298c7db9128fb057fede66461cf

SHA-256 ae4be6343ba403a264c0f0e5ccff169648dc854f0a71d6509f38b018ce325042

SSDEEP 393216:PB1L7fxLRsW73YjCet0N10FHuFQdpEMcKY66o:b7f5Rswoj4CJuGdpc66o

Names

BitcoinTrader.pkg;

> Malware developed for MacOS environments, focusing on cryptocurrency
> developed by Lazarus Group (APT group).

![](media/image19.png){width="6.347329396325459in"
height="3.12799978127734in"}

> **Image 1.12:** OSX.Lazarus - VirusTotal

-   **The_injected_iFrame_java-cve-2012-1723**

hxxps://github.com/ytisf/theZoo/tree/master/malwares/Binaries/Linux.Chapros.A

Basic Properties

MD5 2bd88b0f267e5aa5ec00d1452a63d9dc

SHA-1 d01f76f5467c86bfa266c429e1315e7aad821f93

SHA-256 a70a8891829344ad3db818b3c4ad76e38a78b0ce3c43d7aaf65752fe56d10e09

Vhash 03fc64a044d19b92f3ce659f6ee3b940

SSDEEP 768:+8YnvovLx9vqu8UvRRToT2Sv4LoM0kit/la0cO:+8YWF1XMAF0kjO

Names

2bd88b0f267e5aa5ec00d1452a63d9dc_the_injected_iFrame_java-cve-2012-1723

the_injected_iFrame_java-cve-2012-1723

java-cve-2012-1723

a70a8891829344ad3db818b3c4ad76e38a78b0ce3c43d7aaf65752fe56d10e09.bin

d01f76f5467c86bfa266c429e1315e7aad821f93_jar.jar

2BD88B0F267E5AA5EC00D1452A63D9DC

jar.jar

nYCND

the_injected_iFrame_java-cve-2012-1723.infected;

-   ***Java Exploit***

> Unspecified vulnerability in the ***Java Runtime Environment (JRE)***
> component in Oracle Java SE 7 update 4 and earlier, 6 update 32 and
> earlier, 5 update 35 and earlier, and 1.4.2_37 and earlier allows
> remote attackers to affect confidentiality, integrity, and
> availability via unknown vectors related to Hotspot.

![](media/image20.png){width="6.347708880139982in"
height="4.6969520997375325in"}

> **Image 1.13:** **The_injected_iFrame_java-cve-2012-1723** -
> VirusTotal

# Corrective Actions

> As we mentioned before, the idea it was execute test in many malwares,
> and this case, for this reason to be totally known the following
> actions will be taken to improve the protection environment of our
> assets:

-   This report will be sent to Sophos Security Team to validate with
    them how the detection flow for known malware works, and why these 4
    malwares didn\'t were detect;

-   Validate the performance of NGAV, Machine Learning and other
    components, regarding this type of detection;

-   The best practices of the configurations will be revalidated with
    the Sophos team;
