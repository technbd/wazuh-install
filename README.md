
## Wazuh:
Wazuh is an open-source security platform that provides threat detection, compliance monitoring, and incident response capabilities. It is widely used to secure workloads across various environments, including physical, virtual, cloud-based, and containerized infrastructure.


### Wazuh Main Features: 
- Security Analytics
- Intrusion Analytics (IDS)
- Log Data Analysis
- File Integrity Monitoring (FIM)
- Vulnerability Detection
- Configuration Assessment
- Incident Response
- Regulatory Compliance
- Cloud Security
- Containers Security
- Agent-Based Monitoring


### Requirements:
#### Hardware:
| Agents | CPU     | RAM     | Storage (90 days) | 
| ------ | ------- | ------- | ----------------- | 
| 1–25   | 4 vCPU | 8 GiB |  50 GB |
| 25–50  | 8 vCPU | 8 GiB |  100 GB |
| 50–100 | 8 vCPU | 8 GiB |  200 GB |


#### Operating system:
- Amazon Linux 2, Amazon Linux 2023
- CentOS 7, 8
- Red Hat Enterprise Linux 7, 8, 9
- Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04


#### Dependencies:: 
- For Wazuh Manager: ensure Python 3.6+ is installed for Wazuh API.
- Java installed (for ELK Stack)


### Wazuh Architecture: 
1. Wazuh Manager:
    - Central server that processes data from agents and sends alerts.

2. Wazuh Agent:
    - Installed on monitored systems to collect data and send it to the manager.

3. Elastic Stack:
    - Elasticsearch stores the data, and Kibana provides a graphical interface for analysis and visualization.

4. Filebeat:
    - Used to forward logs from the manager to Elasticsearch.


### Wazuh components
Wazuh System consists of several components:

- OSSEC HIDS – Host Based Intrusion Detection System
- OpenSCAP – Open Vulnerability Assessment Language
- Elastic Stack – Filebeat, Elasticsearch, Kibana
- Wazuh is loaded with a number of valued capabilities.




### Installing Wazuh: (on Centos-7)

The installation process is divided into two stages: 

- Wazuh server node installation
- Cluster configuration for multi-node deployment


#### Wazuh server node installation:

_Download and run the Wazuh installation assistant:_
```
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```


Or,


```
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
```

```
bash wazuh-install.sh --wazuh-server wazuh-1
```



Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful.

```
### Output: 

05/12/2024 15:49:11 INFO: Starting Wazuh installation assistant. Wazuh version: 4.9.2
05/12/2024 15:49:11 INFO: Verbose logging redirected to /var/log/wazuh-install.log
05/12/2024 15:49:12 INFO: Verifying that your system meets the recommended minimum hardware requirements.
05/12/2024 15:49:12 INFO: Wazuh web interface port will be 443.
05/12/2024 15:49:14 INFO: Wazuh repository added.
05/12/2024 15:49:14 INFO: --- Configuration files ---
05/12/2024 15:49:14 INFO: Generating configuration files.
05/12/2024 15:49:14 INFO: Generating the root certificate.
05/12/2024 15:49:14 INFO: Generating Admin certificates.
05/12/2024 15:49:14 INFO: Generating Wazuh indexer certificates.
05/12/2024 15:49:14 INFO: Generating Filebeat certificates.
05/12/2024 15:49:14 INFO: Generating Wazuh dashboard certificates.
05/12/2024 15:49:15 INFO: Created wazuh-install-files.tar. It contains the Wazuh cluster key, certificates, and passwords necessary for installation.
05/12/2024 15:49:15 INFO: --- Wazuh indexer ---
05/12/2024 15:49:15 INFO: Starting Wazuh indexer installation.
05/12/2024 16:02:00 INFO: Wazuh indexer installation finished.
05/12/2024 16:02:00 INFO: Wazuh indexer post-install configuration finished.
05/12/2024 16:02:00 INFO: Starting service wazuh-indexer.
05/12/2024 16:02:17 INFO: wazuh-indexer service started.
05/12/2024 16:02:17 INFO: Initializing Wazuh indexer cluster security settings.
05/12/2024 16:02:23 INFO: Wazuh indexer cluster security configuration initialized.
05/12/2024 16:02:23 INFO: Wazuh indexer cluster initialized.
05/12/2024 16:02:23 INFO: --- Wazuh server ---
05/12/2024 16:02:23 INFO: Starting the Wazuh manager installation.
05/12/2024 16:08:01 INFO: Wazuh manager installation finished.
05/12/2024 16:08:01 INFO: Wazuh manager vulnerability detection configuration finished.
05/12/2024 16:08:01 INFO: Starting service wazuh-manager.
05/12/2024 16:08:16 INFO: wazuh-manager service started.
05/12/2024 16:08:16 INFO: Starting Filebeat installation.
05/12/2024 16:16:07 INFO: Filebeat installation finished.
05/12/2024 16:16:08 INFO: Filebeat post-install configuration finished.
05/12/2024 16:16:08 INFO: Starting service filebeat.
05/12/2024 16:16:08 INFO: filebeat service started.
05/12/2024 16:16:08 INFO: --- Wazuh dashboard ---
05/12/2024 16:16:08 INFO: Starting Wazuh dashboard installation.
05/12/2024 16:21:43 INFO: Wazuh dashboard installation finished.
05/12/2024 16:21:43 INFO: Wazuh dashboard post-install configuration finished.
05/12/2024 16:21:43 INFO: Starting service wazuh-dashboard.
05/12/2024 16:21:44 INFO: wazuh-dashboard service started.
05/12/2024 16:21:44 INFO: Updating the internal users.
05/12/2024 16:21:53 INFO: A backup of the internal users has been saved in the /etc/wazuh-indexer/internalusers-backup folder.
05/12/2024 16:22:00 INFO: The filebeat.yml file has been updated to use the Filebeat Keystore username and password.
05/12/2024 16:22:39 INFO: Initializing Wazuh dashboard web application.
05/12/2024 16:22:40 INFO: Wazuh dashboard web application initialized.


05/12/2024 16:22:40 INFO: --- Summary ---
05/12/2024 16:22:40 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: ?eAsqKgtxuxfjZSBoFNS6255mj5TA0cL
05/12/2024 16:22:40 INFO: Installation finished.
```


```
systemctl status wazuh-manager
systemctl status wazuh-dashboard
systemctl status wazuh-indexer
```




#### Note: 
You can find the passwords for all the Wazuh indexer and Wazuh API users in the `wazuh-passwords.txt` file inside `wazuh-install-files.tar`.

```
tar -xvf wazuh-install-files.tar

cd wazuh-install-files
```


```
ll

-r--------  1 root root 1.7K Dec  5 15:49 admin-key.pem
-r--------  1 root root 1.1K Dec  5 15:49 admin.pem
-rw-------  1 root root  180 Dec  5 15:49 config.yml
-r--------  1 root root 1.7K Dec  5 15:49 root-ca.key
-r--------  1 root root 1.2K Dec  5 15:49 root-ca.pem
-r--------  1 root root 1.7K Dec  5 15:49 wazuh-dashboard-key.pem
-r--------  1 root root 1.3K Dec  5 15:49 wazuh-dashboard.pem
-r--------  1 root root 1.7K Dec  5 15:49 wazuh-indexer-key.pem
-r--------  1 root root 1.3K Dec  5 15:49 wazuh-indexer.pem
-rw-------  1 root root 1.4K Dec  5 15:49 wazuh-passwords.txt
-r--------  1 root root 1.7K Dec  5 15:49 wazuh-server-key.pem
-r--------  1 root root 1.3K Dec  5 15:49 wazuh-server.pem
```






### Web interface:
- Username: admin
- Password: ADMIN_PASSWORD

```
https://192.168.10.192/
```



---
---



## Install Wazuh agent:

Now that your Wazuh installation is ready, you can start deploying the Wazuh agent. The Wazuh agent provides key features to enhance your system’s security.

- Log collector
- Command execution
- File integrity monitoring (FIM)
- Security configuration assessment (SCA)
- System inventory
- Malware detection
- Active Response
- Container security
- Cloud security


### For RHEL/CentOS Based:

_Import the GPG key:_
```
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
```


_Add Wazuh repository:_
```
cat > /etc/yum.repos.d/wazuh.repo << EOF

[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
```


### For Ubuntu Based:

_Install the GPG key:_
```
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```


_Add the repository:_
```
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```


### To deploy/install the Wazuh agent:

- `WAZUH_MANAGER` variable to contain your Wazuh manager IP address or hostname.

_For CentOS:_
```
WAZUH_MANAGER="192.168.10.192" yum install wazuh-agent
```



_For Ubuntu:_
```
WAZUH_MANAGER="192.168.10.192" apt install wazuh-agent
```



```
cat /var/ossec/etc/ossec.conf | grep 192.168.10.192

    <address>192.168.10.192</address>
```


```
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

systemctl status wazuh-agent
```


#### Recommended action - Disable Wazuh updates:

_For Centos:_
```
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
```


_For Ubuntu::_
```
sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
apt update
```




### Add Windows Agent:

1. Go to `Dashboard` - `Server management` - `Endpoints summary` - click `Deploy new agent`: 

```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.10.193' WAZUH_AGENT_NAME='windows10-44' 
```


```
NET START WazuhSvc
NET STOP WazuhSvc
```



### File integrity monitoring:
File Integrity Monitoring (FIM) helps in auditing sensitive files and meeting regulatory compliance requirements. Wazuh has an inbuilt FIM module that monitors file system changes to detect the creation, modification, and deletion of files.


#### Ubuntu endpoint:
Perform the following steps to configure the Wazuh agent to monitor filesystem changes in the `/root` directory.

Edit the Wazuh agent `/var/ossec/etc/ossec.conf` configuration file. Add the directories for monitoring within the `<syscheck>` block.

```
  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

     <scan_on_start>yes</scan_on_start>

     <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>


    <directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>

    <!-- ... -->
    <!-- ... -->

    <!-- File types to ignore -->
    <ignore type="sregex">.log$|.swp$</ignore>

    <!-- ... -->
    <!-- ... -->


  </syscheck>

```


```
systemctl restart wazuh-agent
```



#### Windows endpoint:

Take the following steps to configure the Wazuh agent to monitor filesystem changes in the `C:\Users\Administrator\Desktop` or `C:\Users\*\Documents` directory.

Edit the `C:\Program Files (x86)\ossec-agent\ossec.conf` configuration file on the monitored Windows endpoint. Add the directories for monitoring within the `<syscheck>` block. 

```
  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <!-- Default files to be monitored. -->
    <!-- ... -->
    <!-- ... -->

    <directories realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>


    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Users\*\Documents</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\Users\*\Desktop</directories>


    <ignore>%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini</ignore>

    <ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>

    <!-- ... -->
    <!-- ... -->
  </syscheck>

```




### Links:
- [Wazuh Quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Installing the Wazuh server](https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html)




Wazuh is often compared to other security platforms like `Splunk`, `OSSEC`, and `AlienVault`. Its open-source nature and integration capabilities make it a strong contender for organizations looking for a comprehensive yet affordable security solution.

