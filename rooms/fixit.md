# [Fixit](https://tryhackme.com/room/fixit)

## Level 1: Fix Event Boundaries

Go to `/opt/splunk/etc/apps/fixit/default`

Create `props.conf`:
```
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\[Network-log\]:
```

Restart splunk `/opt/splunk/bin/splunk restart`

Check if the logs are correct `index=main` (select 5-minute window to see the latest ones)

## Level 2: Extract Custom Fields

Go to `/opt/splunk/etc/apps/fixit/default`

Create `transforms.conf`:
```
[network_logs_extraction]
REGEX = User named\s+(.+?)\s+from\s+(.+?)\s+department\s+accessed\s+the\s+resource\s+(.+?)/(.*?)\s+from\s+the\s+source\s+IP\s+(\d{1,3}(?:\.\d{1,3}){3})\s+and\s+country\s+(.+?)\s+at:
FORMAT = Username::$1 Department::$2 Domain::$3 Resource::$4 Source_IP::$5 Country::$6
WRITE_META = true
```

Update `props.conf`:
```
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\[Network-log\]:
TRANSFORM-network = network_logs_extraction
```

Restart splunk `/opt/splunk/bin/splunk restart`

Check if the logs are correct `index=main` (select 5-minute window to see the latest ones)

## Answers

### What is the full path to the Fixit app directory in your instance?

```
/opt/splunk/etc/apps/fixit
```

### What is the full path of the network-logs script?

```shell
grep network-logs /opt/splunk/etc/apps/fixit/default/inputs.conf
/opt/splunk/etc/apps/fixit/bin/network-logs
```

### Which Splunk stanza setting will you use to define the event boundaries for the scenario logs?

```
BREAK_ONLY_BEFORE
```

### Which regex pattern should be used to define the start of each event?

```
^\[Network-log\]:
```

### After you’ve extracted the relevant fields, what `Domain` appears in the log data?

Click on `Domain` and see the only value:

```
Cybertees.THM
```

### How many `Username` field values exist within the events generated?

Check the count for `Username`: 28

### How many `URI` field values were you able to extract from the available logs?

Check the count for `Resource`: 12

### As you begin analyzing the network traffic, how many individual `/products` pages appear in the data?

Use this query:
```
index=main Resource="products/*"
| stats count by Resource
```

```
2
```

### What is the only `URI` field value found in the event data without a file extension?

Use this query:
```
index=main NOT Resource="*.*"
| top Resource
```

```
/sales/
```

### Who is the most active User on the network?

Use this query:
```
index=main
| top Username
```

```
Robert Wilson
```

### How many unique IP ranges are represented in the observed network traffic?

Use this query:
```
index=main
| rex field=Source_IP "(?<subnet>\d+\.\d+)\."
| stats count by subnet
```

```
3
```


### Which user accessed the `secret-document.pdf` on your client's server?

Use this query:
```
index=main Resource="secret-document.pdf"
| top Username
```

```
Sarah Hall
```
