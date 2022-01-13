# Kubernetes Security Workshop | Calico Cloud (AKS)
This repository was created for Kubernetes security workshops <br/>
NB: None of the scripts provided in this repo are directly supported by Tigera

## Create a node group for the cluster
Create an empty ```resource group``` for your cluster
```
az group create --name nigelResourceGroup --location northeurope
```
```Transparent mode``` is enabled by default via CLI (Make sure that we are using the Azure CNI)
```
az aks create --resource-group nigelResourceGroup --name nigelAKSCluster --node-vm-size Standard_B2ms --node-count 3 --zones 1 2 3 --network-plugin azure
```

Connect your ```subscription``` to the Azure CLI (if you have not done this already):
```
az account set --subscription 03cfb895-akstest-4ad4-akstest-aeede8dbfc30
```
You can retrieve your cluster credentials and/or set the cluster ```context``` via the below command:
```
az aks get-credentials --resource-group nigelResourceGroup --name nigelAKSCluster
```
Confirm all pods are running in the ```kube-system``` namespace
```
kubectl get pods -n kube-system
```
<img width="844" alt="Screenshot 2021-12-15 at 22 13 20" src="https://user-images.githubusercontent.com/82048393/146273183-db7335e4-0147-4891-9244-fa3c822815bd.png">


## Configure Calico Cloud:
Get your Calico Cloud installation script from the Web UI - https://qq9psbdn-management.calicocloud.io/clusters/grid
```
curl https://installer.calicocloud.io/*****.*****-management_install.sh | bash
```
If your cluster does not have applications, you can use the following storefront application:
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

<img width="731" alt="Screenshot 2021-12-02 at 09 31 00" src="https://user-images.githubusercontent.com/82048393/144395142-da473fc4-db81-4ebe-97f2-3fea17f4b2c0.png">


Create the Product Tier:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/product.yaml
```  
## Zone-Based Architecture  
Create the DMZ Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/dmz.yaml
```
Create the Trusted Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/trusted.yaml
``` 
Create the Restricted Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/restricted.yaml
```

#### Confirm all policies are running:
```
kubectl get networkpolicies.p -n storefront -l projectcalico.org/tier=product
```

## Allow Kube-DNS Traffic: 
We need to create the following policy within the ```tigera-security``` tier <br/>
Determine a DNS provider of your cluster (mine is 'coredns' by default)
```
kubectl get deployments -l k8s-app=kube-dns -n kube-system
```    
Allow traffic for Kube-DNS / CoreDNS:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/allow-kubedns.yaml
```
  
## Increase the Sync Rate: 
``` 
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
```
Introduce the Rogue Application:
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml -n storefront
``` 
Quarantine the Rogue Application: 
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/quarantine.yaml
```
## Introduce Threat Feeds:
Create the FeodoTracker globalThreatFeed: 
``` 
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/threatfeed/feodo-tracker.yaml
```
Verify the GlobalNetworkSet is configured correctly:
``` 
kubectl get globalnetworksets threatfeed.feodo-tracker -o yaml
``` 

Applies to anything that IS NOT listed with the namespace selector = 'acme' 

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/threatfeed/block-feodo.yaml
```

Create a Default-Deny in the 'Default' namespace:

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/default-deny.yaml
```

## Anonymization Attacks:  
Create the threat feed for ```KNOWN-MALWARE``` which we can then block with network policy: 
``` 
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/EuroEKSClusterCC/main/malware-ipfeed.yaml
```

Create the threat feed for ```Tor Bulk Exit``` Nodes: 

``` 
kubectl apply -f https://docs.tigera.io/manifests/threatdef/tor-exit-feed.yaml
```

Additionally, feeds can be checked using following command:

``` 
kubectl get globalthreatfeeds 
```

As you can see from the below example, it's making a pull request from a dynamic feed and labelling it - so we have a static selector for the feed:
```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: vpn-ejr
spec:
  pull:
    http:
      url: https://raw.githubusercontent.com/n1g3ld0uglas/EuroEKSClusterCC/main/ejrfeed.txt
  globalNetworkSet:
    labels:
      threatfeed: vpn-ejr
```
  
## Configuring Honeypods

Create the ```Tigera-Internal``` namespace and alerts for the honeypod services:

```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/common.yaml
```

Expose a vulnerable SQL service that contains an empty database with easy access.<br/>
The pod can be discovered via ClusterIP or DNS lookup:

```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/vuln-svc.yaml 
```

Verify the deployment - ensure that honeypods are running within the tigera-internal namespace:

```
kubectl get pods -n tigera-internal -o wide
```

And verify that global alerts are set for honeypods:

```
kubectl get globalalerts
```

  
  
  
## Deploy the Boutique Store Application

```
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```  

We also offer a test application for Kubernetes-specific network policies:

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/test.yaml
```

#### Block the test application

Deny the frontend pod traffic:

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/frontend-deny.yaml
```

Allow the frontend pod traffic:

```
kubectl delete -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/frontend-deny.yaml
```

#### Introduce segmented policies
Deploy policies for the Boutique application:
  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/boutique-policies.yaml
``` 
Deploy policies for the K8 test application:
  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/test-app.yaml
```
  
## Alerting

Documentation for creating ```GlobalAlert``` custom resources: <br/>
https://docs.tigera.io/v3.11/reference/resources/globalalert <br/>
<br/>

Alert on ```NetworkSet``` changes:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/alerting/networksets.yaml
```

Alert on  suspicious ```DNS Access``` requests:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/alerting/dns-access.yaml
```

Alert on ```lateral access``` to a specific namespace:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/alerting/lateral-access.yaml
``` 
  
## Compliance Reporting

Generate a ``` CIS Benchmark```  report: <br/>
https://docs.tigera.io/v3.11/compliance/overview
```   
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/reporting/daily-cis-report.yaml
```

Generate an ```Inventory```  report
```  
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/reporting/half-hour-inventory-report.yaml
```

Generate a ```Network Access```  report:
``` 
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/reporting/half-hour-network-access.yaml  
```

![compliance-reporting](https://user-images.githubusercontent.com/82048393/144321272-d6303cde-18b3-434a-b2ff-d45c6d9ccece.png)


Confirm your three reports are running as expected:
```
kubectl get globalreports
```

Ensure that the compliance-benchmarker is running, and that the cis-benchmark report type is installed:
```
kubectl get -n tigera-compliance daemonset compliance-benchmarker
kubectl get globalreporttype cis-benchmark
```


In the following example, we use a GlobalReport with CIS benchmark fields to schedule and filter results.
```
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: daily-cis-results
  labels:
    deployment: production
spec:
  reportType: cis-benchmark
  schedule: 0 0 * * *
  cis:
    highThreshold: 100
    medThreshold: 50
    includeUnscoredTests: true
    numFailedTests: 5
    resultsFilters:
    - benchmarkSelection: { kubernetesVersion: "1.13" }
      exclude: ["1.1.4", "1.2.5"]
```
The report is scheduled to run at midnight of the next day (in UTC), and the benchmark items ```1.1.4```  and  ```1.2.5``` will be omitted from the results.

## Securing AKS hosts:

Automatically register your nodes as Host Endpoints (HEPS). <br/>
To enable automatic host endpoints, edit the default KubeControllersConfiguration instance, and set ``` spec.controllers.node.hostEndpoint.autoCreate```  to ```true``` for those ```HostEndpoints``` :

```
kubectl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

Add the label ```kubernetes-host``` to all nodes and their host endpoints:
```
kubectl label nodes --all kubernetes-host=  
```
This tutorial assumes that you already have a tier called '```aws-nodes```' in Calico Cloud:  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/node-tier.yaml
```
Once the tier is created, Build 3 policies for each scenario: <br/>
<br/>
ETCD Host:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/etcd.yaml
```
Master Node:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/master.yaml
```
Worker Node:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/worker.yaml
```

#### Label based on node purpose
To select a specific set of host endpoints (and their corresponding Kubernetes nodes), use a policy selector that selects a label unique to that set of host endpoints. <br/>
For example, if we want to add the label ```environment=dev``` to nodes named node1 and node2:

```
kubectl label node ip-192-168-22-46.eu-west-1.compute.internal env=master
kubectl label node ip-192-168-62-23.eu-west-1.compute.internal env=worker
kubectl label node ip-192-168-74-2.eu-west-1.compute.internal env=etcd
```

Confirm the labels are now assigned:

```
kubectl get nodes --show-labels | grep etcd
```

## Dynamic Packet Capture:

Check that there are no packet captures in this directory  
```
ls *pcap
```
A Packet Capture resource (```PacketCapture```) represents captured live traffic for debugging microservices and application interaction inside a Kubernetes cluster.</br>
https://docs.tigera.io/reference/calicoctl/captured-packets  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
Confirm this is now running:  
```  
kubectl get packetcapture -n storefront
```
Once the capture is created, you can delete the collector:
```
kubectl delete -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
#### Install a Calicoctl plugin  
Use the following command to download the calicoctl binary:</br>
https://docs.tigera.io/maintenance/clis/calicoctl/install#install-calicoctl-as-a-kubectl-plugin-on-a-single-host
``` 
curl -o kubectl-calico -O -L  https://docs.tigera.io/download/binaries/v3.7.0/calicoctl
``` 
Set the file to be executable.
``` 
chmod +x kubectl-calico
```
Verify the plugin works:
``` 
./kubectl-calico -h
``` 
#### Move the packet capture
```
./kubectl-calico captured-packets copy storefront-capture -n storefront
``` 
Check that the packet captures are now created:
```
ls *pcap
```
#### Install TSHARK and troubleshoot per pod 
Use Yum To Search For The Package That Installs Tshark:</br>
https://www.question-defense.com/2010/03/07/install-tshark-on-centos-linux-using-the-yum-package-manager
```  
sudo yum install wireshark
```  
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice1
``` 
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice2
```  

#### Additional was of configuring packet capture jobs:

In the following example, we select all workload endpoints in ```storefront```  namespace.
```  
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: sample-capture-all
  namespace: storefront
spec:
  selector: all()
```  

In the following example, we select all workload endpoints in ```storefront``` namespace and ```Only TCP``` traffic.

```
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: storefront-capture-all-tcp
  namespace: storefront
spec:
  selector: all()
  filters:
    - protocol: TCP
```

You can schedule a PacketCapture to start and/or stop at a certain time. <br/>
Start and end time are defined using ```RFC3339 format```.
```
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: sample-capture-all-morning
  namespace: storefront
spec:
  selector: all()
  startTime: "2021-12-02T11:05:00Z"
  endTime: "2021-12-02T11:25:00Z"
```
In the above example, we schedule traffic capture for 15 minutes between 11:05 GMT and 11:25 GMT for all workload endpoints in ```storefront``` namespace.

## Calico Deep Packet Inspection
Configuring DPI using Calico Enterprise <br/>
Security teams need to run DPI quickly in response to unusual network traffic in clusters so they can identify potential threats. 

### Introduce a test application:
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Also, it is critical to run DPI on select workloads (not all) to efficiently make use of cluster resources and minimize the impact of false positives.

### Bring in a Rogue Application
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml
```

Calico Enterprise provides an easy way to perform DPI using Snort community rules.

### Create DeepPacketInspection resource: 
In this example we will enable DPI on backend pod in storefront namespace:

```
apiVersion: projectcalico.org/v3
kind: DeepPacketInspection
metadata:
  name: database
  namespace: storefront
spec:
  selector: app == "backend"
```

You can disable DPI at any time, selectively configure for namespaces and endpoints, and alerts are generated in the Alerts dashboard in Manager UI. 

### Check that the "tigera-dpi" pods created successfully
It's a deaemonSet so one pod should created in each node:

```
kubectl get pods -n tigera-dpi
```

### Make sure that all pods are in running state
Trigger Snort rule from attacker pod to backend.storefront

```
kubectl exec -it $(kubectl get po -l app=attacker-app -ojsonpath='{.items[0].metadata.name}') -- sh -c "curl http://backend.storefront.svc.cluster.local:80 -H 'User-Agent: Mozilla/4.0' -XPOST --data-raw 'smk=1234'"
```

### Now, go and check the Alerts page in the UI
You should see a signature triggered alert. <br/>
Once satisfied with the alerts, you can disable Deep Packet Inspection via the below command:
```
kubectl delete DeepPacketInspection database -n storefront 
```

### Hipstershop Reference
```
apiVersion: projectcalico.org/v3
kind: DeepPacketInspection
metadata:
  name: hipstershop-dpi-dmz
  namespace: hipstershop
spec:
  selector: zone == "dmz"
```



## Anomaly Detection:

For the managed cluster (like Calico Cloud):

If it is a managed cluster, you have to set up the CLUSTER_NAME environment variable. 
``` 
curl https://docs.tigera.io/manifests/threatdef/ad-jobs-deployment-managed.yaml -O
``` 

Grab your pull secret from the ```tigera-system``` namespace:
``` 
kubectl get secret tigera-pull-secret -n tigera-system -o yaml > secret.yaml
``` 

Swap the name of your cluster into the managed deployment manifest:
``` 
sed -i 's/CLUSTER_NAME/nigel-eks-cluster/g' ad-jobs-deployment-managed.yaml
``` 

If it is a managed cluster, you have to set up the CLUSTER_NAME environment variable. </br>
Automated the process (keep in mind the cluster name specified is - ``` nigel-eks-cluster``` 
``` 
kubectl apply -f ad-jobs-deployment-managed.yaml
``` 

To get this real pod name use:
``` 
kubectl get pods -n tigera-intrusion-detection -l app=anomaly-detection
``` 

Use this command to read logs:
``` 
kubectl logs ad-jobs-deployment-86db6d5d9b-fmt5p -n tigera-intrusion-detection | grep INFO
``` 

If anomalies are detected, you see a line like this:
``` 
2021-10-14 14:06:13 : INFO : AlertClient: sent 5 alerts with anomalies.
``` 

![anomaly-detection-alert](https://user-images.githubusercontent.com/82048393/137357313-e29f6158-5cd9-4f3a-b68f-466331d85186.png)

A description of the alert started with the ```anomaly_detection.job_id``` where ```job_id``` can be found on Description page

## Wireguard In-Transit Encryption:

To begin, you will need a Kubernetes cluster with WireGuard installed on the host operating system.</br>
https://www.tigera.io/blog/introducing-wireguard-encryption-with-calico/
```
sudo yum install kernel-devel-`uname -r` -y
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
sudo curl -o /etc/yum.repos.d/jdoss-wireguard-epel-7.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
sudo yum install wireguard-dkms wireguard-tools -y
```
Enable WireGuard encryption across all the nodes using the following command:
```
kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
```
To verify that the nodes are configured for WireGuard encryption:
```
kubectl get node ip-192-168-30-158.eu-west-1.compute.internal -o yaml | grep Wireguard
```
Show how this has applied to traffic in-transit:
```
sudo wg show
```

## Cleaner Script (Removes unwanted policies after workshop)
```
wget https://raw.githubusercontent.com/n1g3ld0uglas/EuroEKSClusterCC/main/cleaner.sh
```

```
chmod +x cleaner.sh
```

```
./cleaner.sh
```


## Scale down your AKS Cluster
Scale down cluster to 0 nodes in not in planned usage (to reduce AKS costs)
```
az aks scale --resource-group nigelResourceGroup -name nigelAKSCluster -node-count 0
```

Alternatively, you can stop clusters
```
az aks stop --name nigelAKSCluster --resource-group nigelResourceGroup
```
And start those clusters
```
az aks start --name nigelAKSCluster --resource-group nigelResourceGroup
```
