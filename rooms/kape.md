# [KAPE](https://tryhackme.com/r/room/kape)

## Task 7 Hands-on Challenge

```powershell
cd C:\Users\THM-4n6\Desktop\KAPE
.\kape.exe --tsource C:\ `
--tdest C:\Users\THM-4n6\Desktop\T-DEST --tflush --target KapeTriage `
--mdest C:\Users\THM-4n6\Desktop\M-DEST --mflush --module !EZParser --gui
```

What is the Serial Number of the other USB Device?



kape.exe --tsource C: --target USBDevices,USBHistory --tdest C:\KAPE_Output --gui
