# Portoshim

Portoshim is a CRI ([Container Runtime Interface](https://kubernetes.io/docs/concepts/architecture/cri)) plugin 
for [Porto](https://github.com/ten-nancy/porto) container management system.

Portoshim allows Porto daemon to communicate with kubelet, so Porto can be used as Kubernetes container runtime. 
Portoshim is written on Go programming language.

![Porto and other container runtimes](./docs/images/container_runtimes.svg "Porto and other container runtimes")


## Quick start

### Dependencies

Install [Porto container runtime](https://github.com/ten-nancy/porto/blob/master/README.md) and [Go programming language](https://go.dev/doc/install) (at least v1.17).
Run Porto after installation.

### Build

Download Portoshim project from github.com:
```bash
git clone https://github.com/ten-nancy/portoshim.git
cd portoshim
```

Build binary files using ```make``` and install them:
```bash
make
sudo make install
```


### Run

Execute Portoshim binary file (in background optionaly):
```bash
sudo portoshim &
```
or
```bash
sudo portoshim --debug & # add debug logs
```

The following socket has to appear after all actions ```/run/portoshim.sock```.

You can use [crictl](https://github.com/kubernetes-sigs/cri-tools) to check portoshim is running:
```bash
crictl --runtime-endpoint="unix:///run/portoshim.sock" ps
``` 

Also you can write the following config to ```/etc/crictl.yaml``` and do not specify endpoint flags:
```yaml
runtime-endpoint: unix:///run/portoshim.sock
```


## Kubernetes over Porto

You should specify two kubelet flags to use Kubernetes with Porto:
```bash
--container-runtime="remote"
--container-runtime-endpoint="unix:///run/portoshim.sock"
```

Kubelet uses Portoshim as a CRI service and sends CRI gRPC request to it. 
In turn Portoshim converts СRI request from kubelet to Porto request and forward it to Porto. 
Porto performs request. So Portoshim works as proxy between kubelet and Porto.
