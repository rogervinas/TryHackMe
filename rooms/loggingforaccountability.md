# [Logging for Accountability](https://tryhackme.com/r/room/loggingforaccountability)

**How many total events are indexed by Splunk?**

Search `index=windowslogs` and "All time" and "Verbose Mode"

**How many events were indexed from April 15th to 16th 2022?**

Search `index=windowslogs` and "Date Range between 04/15/2022 adn 04/16/2022" and "Verbose Mode"

**How many unique users appear in the data set?**

Search `index=windowslogs | stats dc(UserID)` and "All time" and "Verbose Mode"

**How many events are associated with the user "James"?**

Search `index=windowslogs User="Cybertees\\James"` and "All time" and "Verbose Mode"

**What utility was used in the oldest event associated with "James"?**

Search with "All time" and "Verbose Mode":
```
index=windowslogs User="Cybertees\\James"
| sort _time
| head 1
| table ProcessId, CommandLine
```

**What event ID followed process creation events associated with "James"?**

Search with "All time" and "Verbose Mode":
```
index=windowslogs ProcessId=9428 Category="Network connection detected (rule: NetworkConnect)"
| Table EventID
```
