# [Fixit](https://tryhackme.com/room/fixit)

## Level 1: Fix Event Boundaries

Go to `/opt/splunk/etc/apps/fixit/default`

Create `props.conf`:
```text
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]
```

Restart splunk `/opt/splunk/bin/splunk restart`

Check if the logs are correct `index=main` (select 5-minute window to see the latest ones)

## Level 2: Extract Custom Fields

Go to `/opt/splunk/etc/apps/fixit/default`

Create `transforms.conf`:
```text
[network_logs_extraction]
REGEX = User named\s+(.+?)\s+from\s+(.+?)\s+department\s+accessed\s+the\s+resource\s+(.+?)/.*?\s+from\s+the\s+source\s+IP\s+(\d{1,3}(?:\.\d{1,3}){3})\s+and\s+country\s+(.+?)\s+at:
FORMAT = Username::$1 Department::$2 Domain::$3 Source_IP::$4 Country::$5
WRITE_META = true
```

Update `props.conf`:
```text
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]
TRANSFORM-network = network_logs_extraction
```

Restart splunk `/opt/splunk/bin/splunk restart`

Check if the logs are correct `index=main` (select 5-minute window to see the latest ones)

## Answers

### What is the full path of the FIXIT app directory?

`/opt/splunk/etc/apps/fixit`

### What Stanza will we use to define Event Boundary in this multi-line Event case?

`BREAK_ONLY_BEFORE`

In the inputs.conf, what is the full path of the network-logs script?
```shell
cat /opt/splunk/etc/apps/fixit/default/inputs.conf
```

`/opt/splunk/etc/apps/fixit/bin/network-logs`

### What regex pattern will help us define the Event's start?

`\[Network-log\]`

### What is the captured domain?

Click on `Domain` and see the only value:

`Cybertees.THM`

### How many countries are captured in the logs?

Check the count for `Country`: 12

### How many departments are captured in the logs?

Check the count for `Department`: 6

### How many usernames are captured in the logs?

Check the count for `Username`: 28

### How many source IPs are captured in the logs?

Check the count for `Source_IP`: 52

### Which configuration files were used to fix our problem? [Alphabetic order: File1, file2, file3]

`inputs.conf, props.conf, transforms.conf`

### What are the TOP two countries the user Robert tried to access the domain from? [Answer in comma-separated and in Alphabetic Order][Format: Country1, Country2]

Use this query:
```text
index=main Username="Robert Wilson" 
| top Country
```

`Canada, United States`

### Which user accessed the secret-document.pdf on the website?

Go to `/opt/splunk/etc/apps/fixit/default`

Update `transforms.conf`:
```text
[network_logs_extraction]
REGEX = User named\s+(.+?)\s+from\s+(.+?)\s+department\s+accessed\s+the\s+resource\s+(.+?)/(.*?)\s+from\s+the\s+source\s+IP\s+(\d{1,3}(?:\.\d{1,3}){3})\s+and\s+country\s+(.+?)\s+at:
FORMAT = Username::$1 Department::$2 Domain::$3 Resource::$4 Source_IP::$5 Country::$6
WRITE_META = true
```

Restart splunk `/opt/splunk/bin/splunk restart`

Use this query:
```text
index=main Resource="secret-document.pdf"
| top Username
```

`Sarah Hall`
