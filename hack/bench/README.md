# runtime-enforcer benchmark

This tool creates the benchmark of runtime enforcer agent. It examines
a few benchmark:

- CPU utilization
- memory utilization
- the throughput of execve call.

## Pre-requisites

- Single node kubernetes cluster with metrics server enabled
- kubectl, kubectl top and helm CLI are available.
- python3 and python3-tabulate
- Increase the max number of pods
- The pre-requisites of runtime-enforcer, e.g., jetstack/cert-manager and jetstack/cert-manager-csi-driver are installed.

### Minikube

If you use minikube, you can create a minikube cluster with the command below:

```
minikube start --driver=kvm2 --extra-config=kubelet.max-pods=200 --container-runtime=containerd
minikube addons enable metrics-server
```

