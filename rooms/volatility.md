# [Volatility](https://tryhackme.com/room/volatility)

## Task 10 Practical Investigations

```shell
cd /opt/volatility3
python3 vol.py -h
```

### Case 001 - BOB! THIS ISN'T A HORSE!

**What is the build version of the host machine in Case 001?**
**At what time was the memory file acquired in Case 001?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem windows.info | grep -e NTBuildLab -e SystemTime
```

**What process can be considered suspicious in Case 001?**
**What is the PID of the suspicious process in Case 001?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem windows.psscan
```

**What is the parent process of the suspicious process in Case 001?**
**What is the parent process PID in Case 001?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem windows.pstree
PARENT_PID=????
```

**What user-agent was employed by the adversary in Case 001?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem \
 -o /tmp windows.memmap.Memmap \
 --pid $PARENT_PID --dump
strings /tmp/pid.${PARENT_PID}.dmp | grep -i "user-agent"
```

**Was Chase Bank one of the suspicious bank domains found in Case 001?**

```shell
strings /tmp/pid.${PARENT_PID}.dmp | grep -i "www.chase.com"
```

### Case 002 - That Kind of Hurt my Feelings

**What suspicious process is running at PID 740 in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.psscan --pid 740
```

**What is the full path of the suspicious binary in PID 740 in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.dlllist --pid 740 | grep .exe
```

**What is the parent process of PID 740 in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.pstree
```

**What malware is present on the system in Case 002?**

https://www.google.com/search?q=%40WanaDecryptor%40.exe

**What DLL is loaded by the decryptor used for socket creation in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.dlllist --pid 740 | \
  awk '{print $5}' | grep -i '\.dll'
```

**What mutex can be found that is a known indicator of the malware in question in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.handles --pid 1940 | \
  grep -i mutex
```

**What plugin could be used to identify all files loaded from the malware working directory in Case 002?**

```shell
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.filescan
```
