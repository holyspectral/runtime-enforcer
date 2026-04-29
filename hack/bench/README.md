# runtime-enforcer benchmark

This tool creates the benchmark of runtime enforcer agent. It examines
a few benchmark:

- CPU utilization
- memory utilization
- the throughput of execve call.

## Pre-requisites

- Single node kubernetes cluster.
- python3
- python3-tabulate
- kubectl
- metrics server
- Increase the max number of pods
- kubectl top
- jetstack/cert-manager and jetstack/cert-manager-csi-driver are installed.

### Minikube

You can create a minikube cluster with the command below:

```
minikube start --driver=kvm2 --extra-config=kubelet.max-pods=200
minikube addons enable metrics-server
```

## TODO

1. Check node CPU/memory usage.

