# [Virtualization and Containers](https://tryhackme.com/r/room/virtualizationandcontainers)

## Task 5 Docker

**What flag is obtained at MACHINE_IP:5000 after running the container?**

```shell
docker run -p 5000:5000 -d cryillic/thm_example_app 
curl http://localhost:5000
```

## Task 6 Kubernetes

**How many pods are running on the provided cluster?**

```shell
kubectl get pods
```

**How many system pods are running on the provided cluster?**

```shell
kubectl get pods -n kube-system
```

**What is the pod name on the provided cluster?**

```shell
kubectl get pods
```

**What is the deployment name on the provided cluster?**

```shell
kubectl get deployments
```

**What port is exposed by the service in question 5?**

```shell
kubectl get services hello-tryhackme-service
```

**How many replica sets are deployed on the provided cluster?**
**What is the replica set name on the provided cluster?**

```shell
kubectl get rs
```

**What command would be used to delete the deployment from question 5?**

```shell
kubectl delete deployment hello-tryhackme
```
