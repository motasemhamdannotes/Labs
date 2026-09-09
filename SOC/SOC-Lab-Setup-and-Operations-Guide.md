# SOC Home Lab: setup and operations guide

Based on [Amit29533/SOC-Home-Lab](https://github.com/Amit29533/SOC-Home-Lab). Reviewed 7 September 2026.

This is an expanded implementation guide, not a claim that the repository supplies a complete automated deployment. It combines the repository's intended tools with an explicit virtual network, corrected configuration examples, repeatable exercises, and operating procedures. The commands below are instructions for your lab VMs; they have not been executed against a running lab during preparation of this guide.

**Outcome:** Kali generates controlled traffic against a Linux target; Suricata observes it; Wazuh collects endpoint events and Suricata alerts; Splunk searches both raw network events and Wazuh alerts; Wireshark verifies packets. An optional Microsoft Sentinel extension receives Wazuh alerts through an Azure Monitor Agent collector.

## How to use this guide

Follow sections 1–10 in order. Complete the checkpoint at each stage before moving on. Section 11 adds Sentinel; sections 12–16 cover operations, troubleshooting, and extensions. Commands assume a Bash shell on the named Linux VM unless explicitly labeled otherwise. Replace interface names and downloaded package filenames with those on your machines. Code fragments marked as configuration belong in the specified file, not in a terminal.

Allow roughly two to four focused sessions for a first build, plus time for downloads and troubleshooting. That is a planning estimate, not an installation guarantee.

### Contents

1. [Repository corrections](#1-repository-corrections)
2. [Hardware and software](#2-hardware-and-software)
3. [Network and VM creation](#3-network-and-vm-creation)
4. [Prepare the Linux target](#4-prepare-the-linux-target)
5. [Install Wazuh and enroll endpoints](#5-install-wazuh-and-enroll-endpoints)
6. [Install and validate Suricata](#6-install-and-validate-suricata)
7. [Send Suricata events to Wazuh](#7-send-suricata-events-to-wazuh)
8. [Install Splunk and forward logs](#8-install-splunk-and-forward-logs)
9. [Build searches dashboards and alerts](#9-build-searches-dashboards-and-alerts)
10. [Run detection and investigation exercises](#10-run-detection-and-investigation-exercises)
11. [Add Microsoft Sentinel](#11-add-microsoft-sentinel)
12. [Operate the lab](#12-operate-the-lab)
13. [Investigate and document incidents](#13-investigate-and-document-incidents)
14. [Troubleshooting](#14-troubleshooting)
15. [Acceptance checklist](#15-acceptance-checklist)
16. [Extensions](#16-extensions)

## 1. Repository corrections

I reviewed the README and the three actual setup files: [Splunk](https://github.com/Amit29533/SOC-Home-Lab/blob/main/splunk-setup.md), [Suricata](https://github.com/Amit29533/SOC-Home-Lab/blob/main/suricata-setup.md), and [Wazuh](https://github.com/Amit29533/SOC-Home-Lab/blob/main/wazuh-setup.md). The following adjustments make their outline actionable:

| Repository instruction or omission | Implementation in this guide |
|---|---|
| Architecture diagram omits a target and capture mechanism | Separate target and sensor, with a mandatory visibility test |
| Example `latest/linux/splunk.deb` download path | Use the actual versioned package from Splunk's download page |
| Install only `wazuh-manager`, then use a dashboard | Install manager, indexer, and dashboard together |
| Linux agent command also described for Windows | Linux installation here; Windows uses its own installer |
| Agent configuration mentions `<server-ip>` | Use `<client><server><address>…` |
| Add local paths on Splunk to read another VM's logs | Install Universal Forwarders on the log-producing VMs |
| Example searches use `action="alert"` and top-level `severity` | Use EVE `event_type`, `alert.severity`, and Wazuh `rule.level` |
| Restart described as a Wazuh rule update | Restart loads changes; it does not fetch new vendor rules |
| “Forward to Sentinel workspace” lacks a transport | Use a Linux collector, Azure Arc, AMA, and a data collection rule |

The README's Splunk → Sentinel arrow is conceptual. This guide deliberately branches Wazuh alerts to both SIEMs. Splunk does not automatically forward dashboards, detections, or incidents to Sentinel. Implementing that literal arrow would be a separate export/integration project.

## 2. Hardware and software

### 2.1 Allocate resources

For the five-VM core lab, plan for **32 GB host RAM, SSD storage with about 300 GB free, and hardware virtualization**. More memory helps. These are practical allocations for light exercises, not production sizing or throughput guarantees.

| VM | OS | vCPU | RAM | Virtual disk | Purpose |
|---|---|---:|---:|---:|---|
| `wazuh01` | Ubuntu Server 24.04 LTS, amd64 | 4 | 8 GB | 80 GB | Wazuh central components + Splunk forwarder |
| `splunk01` | Ubuntu Server 24.04 LTS, amd64 | 4 | 8 GB | 100 GB | Splunk indexer and search interface |
| `sensor01` | Ubuntu Server 24.04 LTS, amd64 | 2 | 3 GB | 30 GB | Suricata + Wazuh agent + Splunk forwarder |
| `target01` | Ubuntu Server 24.04 LTS, amd64 | 2 | 2 GB | 25 GB | SSH/web target + Wazuh agent |
| `kali01` | Kali Linux, amd64 | 2 | 2–4 GB | 30 GB | Controlled traffic + Wireshark |
| `collector01` — optional | Ubuntu Server 24.04 LTS, amd64 | 2 | 2 GB | 25 GB | Sentinel syslog collector + Arc + AMA |

Wazuh's current quickstart recommends 4 vCPU, 8 GiB RAM, and 50 GB for 1–25 agents. The larger disk above adds lab headroom. [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)

If you have only 16 GB RAM, initially run Wazuh, the target, and Kali, placing Suricata on the target's lab interface. Add Splunk later or use another host. A sensor on the target sees that target's traffic; it is not a network-wide sensor.

### 2.2 Download software and record versions

1. Install a hypervisor. This guide uses VirtualBox terminology; use equivalent isolated switches and port mirroring if using another platform.
2. Download Ubuntu Server from [Ubuntu](https://ubuntu.com/download/server), Kali from [Kali](https://www.kali.org/get-kali/), and VirtualBox from [Oracle](https://www.virtualbox.org/wiki/Downloads).
3. Obtain Splunk Enterprise and the Linux Universal Forwarder from [Splunk downloads](https://www.splunk.com/en_us/download.html). Download the amd64 `.deb` packages. Record the exact filenames and checksums.
4. Check that the selected Splunk version supports your OS and CPU before installing. Enterprise is sufficient for these exercises; Splunk Enterprise Security is not required.
5. Check the license shown in Splunk's Licensing page. Trial expiration and license capabilities affect scheduled alerts. Do not assume a permanent free entitlement or a particular ingestion allowance. [Splunk trial](https://www.splunk.com/en_us/download/splunk-enterprise.html)
6. Use vendor checksum/signature instructions to verify downloaded images and packages.
7. Keep a build record with OS, application, hypervisor, ruleset versions, installation date, IP addresses, and deviations from this guide. Save passwords separately in a password manager.

Use the current stable Suricata packages. The Wazuh quickstart reviewed for this guide uses the 4.14 installer series; if you choose a newer series, use matching central components and compatible agents throughout. Avoid combining old repository commands with new package versions without checking their documentation.

## 3. Network and VM creation

### 3.1 Understand the layout

```text
                         Host browser / administrator
                                      |
                     SOC-MGMT — host-only 192.168.56.0/24
                    /          |          |           \
               wazuh01     splunk01    sensor01     target01
                 .20         .30         .10          .21
                  |                       |            |
          Wazuh alerts → UF → Splunk       |            |
                                          |            |
                     SOC-LAB — internal 10.10.10.0/24
                                    sensor .10     target .20
                                          \         /
                                           Kali .50

Optional: wazuh01 → collector01 (.40 on MGMT) → HTTPS → Azure/Sentinel
```

The drawing shows connectivity, not a routed path through the sensor. Suricata receives copied traffic through the virtual network's promiscuous capture facility. It does not need to be the target's gateway. The baseline is IDS monitoring; it does not block packets.

### 3.2 Create the virtual networks

1. In VirtualBox's network manager, create a **host-only** network named or documented as `SOC-MGMT`.
2. Set the host adapter to `192.168.56.1/24`; disable its DHCP server for this static-IP plan.
3. Confirm that this subnet does not overlap a physical network or VPN. If it does, choose another private subnet and change every corresponding address in this guide.
4. When configuring VM adapters, create an **Internal Network** named exactly `SOC-LAB`. This is a named internal switch, not a NAT network.
5. Do not bridge `SOC-LAB` to a physical adapter. Do not enable host Internet Connection Sharing or routing between these networks.
6. Use an additional **NAT** adapter temporarily for updates. NAT permits outbound access and is not a containment boundary against outbound traffic. Disconnect it from Kali and the target before exercises.

Internal networking and host-only networking have different host-access properties; VirtualBox also exposes promiscuous mode settings for capture. [Oracle virtual networking](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html)

### 3.3 Create and attach each VM

Create each VM using the sizing table, attach the OS installer, complete a normal installation, create a non-root administrator such as `labadmin`, install OpenSSH on Ubuntu, and remove the installer ISO after reboot.

| VM | Adapter 1 | Adapter 2 | Adapter 3 |
|---|---|---|---|
| `wazuh01` | MGMT `.20` | Temporary NAT | None |
| `splunk01` | MGMT `.30` | Temporary NAT | None |
| `sensor01` | MGMT `.10` | LAB `.10`; promiscuous **Allow All** | Temporary NAT |
| `target01` | MGMT `.21` | LAB `.20` | Temporary NAT |
| `kali01` | LAB `.50` | Temporary NAT | None |
| `collector01` | MGMT `.40` | NAT for Azure access | None |

Only the sensor's LAB adapter needs Allow All. Leave the other adapters at their normal settings. Do not give Kali a management adapter.

### 3.4 Configure Ubuntu addresses

On each Ubuntu VM, identify interfaces and their MAC addresses:

```bash
ip -br link
ip -br address
ip route
```

Match MAC addresses to the hypervisor's adapters. Do not assume interface names are identical across VMs.

For example, if the sensor's MGMT, LAB, and NAT interfaces are `enp0s3`, `enp0s8`, and `enp0s9`, edit its existing Netplan configuration under `/etc/netplan/` to contain:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [192.168.56.10/24]
    enp0s8:
      dhcp4: false
      addresses: [10.10.10.10/24]
    enp0s9:
      dhcp4: true
      optional: true
```

Use the address table for each other VM. Omit nonexistent interfaces. There must be **no default gateway on MGMT or LAB**; only NAT supplies a default route while attached. Avoid multiple Netplan files defining conflicting settings for the same interface. Back up the original file outside `/etc/netplan/`, retain any necessary existing settings, then run from the VM console:

```bash
sudo netplan generate
sudo netplan try
ip -br address
ip route
```

Confirm the trial configuration when connectivity is correct. For Kali, use NetworkManager's connection editor: select its LAB wired connection, set IPv4 to Manual, add `10.10.10.50/24`, leave gateway/DNS empty, and mark the connection as usable only for resources on its network. Reconnect and verify with `ip -br address`.

### 3.5 Prepare the Ubuntu VMs

Run on each Ubuntu VM while its NAT adapter is connected:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y curl ca-certificates gnupg jq tcpdump acl netcat-openbsd
sudo timedatectl set-timezone UTC
sudo timedatectl set-ntp true
timedatectl status
```

Set each hostname appropriately, for example on the sensor:

```bash
sudo hostnamectl set-hostname sensor01
```

Update `/etc/hosts` if its old hostname remains. On dual-network machines ensure forwarding is disabled:

```bash
sudo tee /etc/sysctl.d/99-soc-lab.conf >/dev/null <<'EOF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
EOF
sudo sysctl --system
```

This is a training network; retain VM console access throughout. Host-only networking still connects to your host. Use only designated lab data and accounts on the target, and direct exercises only at `10.10.10.20`.

### 3.6 Permit only the required services

Use guest firewalls to implement the following table. On Ubuntu, `ufw` is a convenient option. Allow the management SSH rule before enabling it; keep the VM console available.

| Destination | Allowed source | Port | Use |
|---|---|---|---|
| Ubuntu VMs on MGMT | Host `192.168.56.1` | TCP 22 | Administration |
| `wazuh01` | Sensor `.10`, target `.21` on MGMT | TCP 1514 | Agent events |
| `wazuh01` | Same agents | TCP 1515 | Enrollment |
| `wazuh01` | Host `.1` | TCP 443 | Dashboard |
| `splunk01` | Host `.1` | TCP 8000 | Splunk Web |
| `splunk01` | Sensor `.10`, Wazuh `.20` | TCP 9997 | Forwarded logs |
| `target01` LAB address | Kali `10.10.10.50` | TCP 22, 80; ICMP as needed | Exercises |
| `collector01` — optional | Wazuh `.20` | UDP 514 | Wazuh syslog output |

Do not open Wazuh's 9200 or 55000, or Splunk's 8089, to the entire lab just to make dashboards work. Their local services communicate without broadly exposed management APIs.

Example on `wazuh01`:

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.56.1 to any port 22 proto tcp
sudo ufw allow from 192.168.56.1 to any port 443 proto tcp
sudo ufw allow from 192.168.56.10 to any port 1514 proto tcp
sudo ufw allow from 192.168.56.10 to any port 1515 proto tcp
sudo ufw allow from 192.168.56.21 to any port 1514 proto tcp
sudo ufw allow from 192.168.56.21 to any port 1515 proto tcp
sudo ufw enable
sudo ufw status verbose
```

Repeat the same pattern on other Ubuntu VMs with their rows. UFW's default ICMP handling may already allow ping; inspect its rules if ping fails. A failed ping alone does not prove that TCP is unreachable.

### 3.7 Checkpoint: prove network visibility

1. From the host, connect to each Ubuntu MGMT address using SSH.
2. On Kali, ping the target: `ping -c 3 10.10.10.20`.
3. On the sensor, run the following on its LAB interface:

```bash
sudo tcpdump -ni enp0s8 'host 10.10.10.50 and host 10.10.10.20'
```

4. Repeat the ping from Kali. You must see traffic between Kali and the target, although neither endpoint is the sensor.
5. After section 4, repeat using an HTTP request; verify both request and response packets.
6. If only broadcast/ARP appears, fix the virtual-switch capture settings. On hypervisors without this capture behavior, configure port mirroring to the sensor. Do not proceed on the assumption that promiscuous mode alone guarantees mirrored traffic.
7. As a simpler fallback, install Suricata on the target and capture the target's LAB interface. Record that scope change.

Take powered-off snapshots named `01-network-ready` after updating and verifying each VM. Synchronize clocks before disconnecting temporary Internet access and after restoring snapshots.

## 4. Prepare the Linux target

On `target01`:

```bash
sudo apt install -y nginx openssh-server rsyslog
sudo systemctl enable --now nginx ssh rsyslog
sudo adduser labuser
printf '%s\n' 'SOC lab target: normal page' | sudo tee /var/www/html/index.html
sudo mkdir -p /opt/soc-lab/watch
printf '%s\n' 'baseline' | sudo tee /opt/soc-lab/watch/test.txt
sudo ss -lntp
```

Set a unique lab-only password for `labuser`. Keep the administrator account separate. Restrict MGMT access to the host and LAB SSH/HTTP access to Kali using section 3.6.

From Kali:

```bash
curl --max-time 5 http://10.10.10.20/
ssh labuser@10.10.10.20
```

Confirm a normal successful login, then exit. If password authentication is disabled and you want the failed-password exercise later, inspect `/etc/ssh/sshd_config` and its included files; enable `PasswordAuthentication yes` on this isolated target only. Run `sudo sshd -t` before restarting `ssh`. Do not enable root login.

Check `/var/log/auth.log` receives authentication events:

```bash
sudo tail -n 20 /var/log/auth.log
```

If this file is absent, confirm rsyslog is active and the Ubuntu auth/authpriv file rule is present. This guide uses that file for deterministic collection; avoid also collecting the identical authentication messages through journald.

## 5. Install Wazuh and enroll endpoints

### 5.1 Install the central components on wazuh01

Use a clean VM. Download the installer separately so it can be inspected before execution:

```bash
mkdir -p ~/soc-install
cd ~/soc-install
curl -fSLO https://packages.wazuh.com/4.14/wazuh-install.sh
less wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Record the generated dashboard credentials. Protect the install archive containing credentials, and store a backup securely. Check services:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat --no-pager
sudo /var/ossec/bin/wazuh-control status
```

Open `https://192.168.56.20` from the host. Verify that the certificate belongs to your new VM before accepting its initial self-signed certificate. Log in with the installer-provided credentials. An empty agent list is expected at this point. The assistant installs the complete central stack. [Installation reference](https://documentation.wazuh.com/current/quickstart.html)

Record the installed package version:

```bash
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard
```

Hold central packages during initial lab setup to prevent an accidental partial upgrade:

```bash
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard
```

Later upgrades must be coordinated; these holds are not a permanent patching policy.

### 5.2 Install agents on sensor01 and target01

The dashboard's **Deploy new agent** workflow can generate an OS-specific command. Alternatively, on each Ubuntu endpoint add the signed repository:

```bash
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh-signing-key.asc
sudo gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh-signing-key.asc
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
apt-cache madison wazuh-agent
```

Select the agent package version matching your manager. In the next command replace `MATCHING_VERSION` with the full value from that list, including its package revision; change `sensor01` to `target01` on the target:

```bash
sudo env WAZUH_MANAGER=192.168.56.20 WAZUH_AGENT_NAME=sensor01 apt install wazuh-agent=MATCHING_VERSION
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo apt-mark hold wazuh-agent
```

If configuring an existing agent manually, edit its existing `/var/ossec/etc/ossec.conf` client section to use:

```xml
<client>
  <server>
    <address>192.168.56.20</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

Preserve other client settings and avoid duplicate client sections. Restart the agent after changes. Enrollment and event delivery are different connections; allow both required ports. Use unique agent names and do not clone an already-enrolled agent identity. [Linux agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)

### 5.3 Configure target telemetry

On `target01`, back up `/var/ossec/etc/ossec.conf`. Inside the existing `<ossec_config>` block, add these entries only if equivalent entries do not already exist:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>
```

The default Nginx combined access log is compatible with this access-log collection format. If you changed Nginx's log format, inspect decoding before relying on its detections.

Within the existing `<syscheck>` section, ensure `<disabled>no</disabled>` and add:

```xml
<directories check_all="yes" realtime="yes">/opt/soc-lab/watch</directories>
```

Restart and wait for the initial file-integrity scan to finish:

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 60 /var/ossec/logs/ossec.log
```

The directory must exist before real-time monitoring begins. The first scan establishes a baseline; modify the file afterward to generate an event. [Wazuh file integrity settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)

### 5.4 Checkpoint

On `wazuh01`:

```bash
sudo /var/ossec/bin/agent_control -l
sudo tail -n 10 /var/ossec/logs/alerts/alerts.json | jq .
```

Both agents should be active. In the dashboard, confirm their names and recent events. If the alerts file is initially empty, run the file-change exercise in section 10 after the baseline scan. Take `02-wazuh-ready` snapshots.

## 6. Install and validate Suricata

### 6.1 Install on sensor01

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata jq
suricata --build-info
sudo suricata-update
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.pre-soc
```

The stable OISF repository and Suricata-Update provide the engine and managed rules. Record their versions for repeatable testing. [Suricata installation](https://docs.suricata.io/en/suricata-7.0.14/install.html), [rule update reference](https://github.com/OISF/suricata-update/blob/master/doc/quickstart.rst)

### 6.2 Configure capture and EVE output

Edit the existing sections in `/etc/suricata/suricata.yaml`; do not replace the complete file with these fragments.

Under `vars` → `address-groups`, set:

```yaml
HOME_NET: "[10.10.10.0/24]"
```

Under `af-packet`, set the actual LAB interface:

```yaml
af-packet:
  - interface: enp0s8
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

Retain other appropriate package defaults. Inspect `sudo systemctl cat suricata` and any referenced environment/default file: a command-line interface setting can override your expectation. The running service must capture the LAB interface.

Find the existing `eve-log` output and configure a modest set of event types:

```yaml
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
        - stats
```

Keep `default-log-dir: /var/log/suricata/`. This baseline omits embedded payload/packet copies to limit event size. Capture a PCAP separately for exercises. [Suricata quickstart](https://docs.suricata.io/en/latest/quickstart.html)

### 6.3 Add deterministic lab rules

Create `/etc/suricata/rules/local.rules`:

```bash
sudo mkdir -p /etc/suricata/rules
sudo nano /etc/suricata/rules/local.rules
```

Paste these locally authored exercise rules, one rule per line:

```text
alert http 10.10.10.50 any -> 10.10.10.20 80 (msg:"SOC LAB HTTP marker"; flow:established,to_server; http.uri; content:"/soc-lab-test"; sid:1000001; rev:1;)
alert tcp 10.10.10.50 any -> 10.10.10.20 any (msg:"SOC LAB SYN burst"; flags:S; flow:stateless; detection_filter:track by_src,count 10,seconds 10; sid:1000002; rev:1;)
```

In the existing YAML `rule-files` list include both managed and local rules:

```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```

These rules deliberately use lab addresses. Both attacker and target belong to `HOME_NET`, so rules requiring `$EXTERNAL_NET` as the source might never match these internal exercises. The SYN-burst rule is a learning signal, not proof of a port scan or malicious intent. The syntax follows the documented HTTP sticky-buffer and detection-filter mechanisms. [HTTP rule syntax](https://docs.suricata.io/en/latest/rules/http-keywords.html), [thresholding](https://docs.suricata.io/en/suricata-8.0.3/rules/thresholding.html)

Validate and start:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable suricata
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager
sudo tail -n 40 /var/log/suricata/suricata.log
```

If the configuration test fails, correct it before restarting. Use the previous backup to recover if needed.

### 6.4 Checkpoint: create an alert

On Kali:

```bash
curl --max-time 5 http://10.10.10.20/soc-lab-test
```

An HTTP 404 is acceptable; the request URI is the marker. On `sensor01`:

```bash
sudo tail -n 1000 /var/log/suricata/eve.json | jq -c 'select(.event_type == "alert" and .alert.signature_id == 1000001)'
```

Expect an alert with Kali's source address and target's destination address. If absent, first prove the HTTP packets are visible with tcpdump, then check rule loading and the service interface. Do not start a second capture-mode Suricata process while diagnosing the managed service.

## 7. Send Suricata events to Wazuh

On **sensor01**, back up `/var/ossec/etc/ossec.conf`. Add inside its existing `<ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Restart the agent and generate a fresh HTTP marker:

```bash
sudo systemctl restart wazuh-agent
sudo tail -n 40 /var/ossec/logs/ossec.log
```

On `wazuh01`, inspect the arriving alert:

```bash
sudo tail -n 2000 /var/ossec/logs/alerts/alerts.json | jq -c 'select(.data.alert.signature_id? == "1000001" or .data.alert.signature_id? == 1000001)'
```

In Wazuh's event/Threat Hunting view, filter `rule.groups` for `suricata`, choose a recent time range, and expand the raw event. Inspect `agent.name`, `data.src_ip`, `data.dest_ip`, and `data.alert.signature_id`. UI labels can vary by version. [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)

**Distinction:** Wazuh's `alerts.json` contains events that produce alerts at its configured threshold. It is not an archive of every EVE DNS/HTTP/flow record. Splunk's direct EVE input in the next section preserves those additional network events.

If decoding fails, copy one complete EVE alert line and paste it into `/var/ossec/bin/wazuh-logtest` on the manager. Inspect decoder and rule results. Use a newly generated live event afterward; logtest does not prove agent transport or write a normal live alert.

## 8. Install Splunk and forward logs

### 8.1 Install Splunk Enterprise on splunk01

Transfer the downloaded `.deb` to this VM, for example into `~/soc-install/`. Substitute its exact name below:

```bash
cd ~/soc-install
sudo dpkg -i ./SPLUNK_ENTERPRISE_PACKAGE.deb
id splunk
```

If the `splunk` OS account does not exist, create it with `sudo useradd --system --create-home --home-dir /opt/splunk --shell /bin/bash splunk`. Then:

```bash
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

Create the Splunk application administrator credentials when prompted; they are separate from the Linux account. Configure boot startup:

```bash
sudo -u splunk /opt/splunk/bin/splunk stop
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk -group splunk
sudo systemctl start Splunkd
sudo systemctl status Splunkd --no-pager
```

`Splunkd` is the default generated unit name; if your installer reports another name, use that name consistently. [Splunk systemd setup](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/start-splunk-enterprise-and-perform-initial-tasks/run-splunk-enterprise-as-a-systemd-service)

Open `http://192.168.56.30:8000` from the host. Under **Settings → Server settings → General settings**, enable SSL for Splunk Web where offered, restart, and use `https://192.168.56.30:8000`. Verify the local certificate. Keep access restricted to the host.

If configuring this by file, create or edit `/opt/splunk/etc/system/local/web.conf` with the following, preserve existing settings, and restart `Splunkd`:

```ini
[settings]
httpport = 8000
enableSplunkWebSSL = true
```

The built-in certificate is suitable only as an initial lab convenience; use your own trusted certificate for a durable setup. [Splunk Web HTTPS configuration](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/secure-communications-between-splunk-web-and-your-browser/turn-on-https-encryption-for-splunk-web-using-the-web.conf-configuration-file)

### 8.2 Create indexes and event parsing settings

Create a small configuration app on `splunk01`:

```bash
sudo mkdir -p /opt/splunk/etc/apps/soc_lab/local
sudo nano /opt/splunk/etc/apps/soc_lab/local/indexes.conf
```

Use:

```ini
[suricata]
homePath = $SPLUNK_DB/suricata/db
coldPath = $SPLUNK_DB/suricata/colddb
thawedPath = $SPLUNK_DB/suricata/thaweddb
maxTotalDataSizeMB = 10240
frozenTimePeriodInSecs = 604800

[wazuh]
homePath = $SPLUNK_DB/wazuh/db
coldPath = $SPLUNK_DB/wazuh/colddb
thawedPath = $SPLUNK_DB/wazuh/thaweddb
maxTotalDataSizeMB = 10240
frozenTimePeriodInSecs = 604800
```

This lab policy limits each index to roughly 10 GB and ages eligible data after seven days. Bucket behavior affects exact deletion timing; the size limit can remove data earlier. Frozen data is deleted unless archiving is explicitly configured. Export exercise evidence you need to retain.

Create `props.conf` in the same directory:

```ini
[suricata:eve]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 100000
KV_MODE = json

[wazuh:alerts]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 100000
KV_MODE = json
```

The design uses one JSON document per line and search-time JSON extraction. It intentionally leaves timestamp format recognition to Splunk after locating `timestamp`; validate `_time` against the raw timestamp. Do not also enable `INDEXED_EXTRACTIONS=JSON` on these inputs, which would introduce a different parsing strategy. [Splunk props.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/props.conf)

Create `inputs.conf` in the same directory:

```ini
[splunktcp://9997]
disabled = 0
```

This is a Splunk-to-Splunk receiver, not a raw TCP JSON or syslog input. The baseline 9997 connection is unencrypted and restricted to the two forwarders on the private host-only network. Before using a shared or routed network, replace it with certificate-validated Splunk TLS forwarding; an SSL checkbox in Splunk Web does not encrypt port 9997.

Apply the configuration:

```bash
sudo chown -R splunk:splunk /opt/splunk/etc/apps/soc_lab
sudo -u splunk /opt/splunk/bin/splunk btool check
sudo systemctl restart Splunkd
sudo ss -lntp | grep 9997
```

### 8.3 Install a Universal Forwarder on sensor01 and wazuh01

Transfer the Linux Universal Forwarder `.deb` to each machine. On each:

```bash
sudo dpkg -i ./SPLUNK_FORWARDER_PACKAGE.deb
id splunkfwd
```

Current Linux packages normally create `splunkfwd`. If missing, create it with `sudo useradd --system --create-home --home-dir /opt/splunkforwarder --shell /bin/bash splunkfwd`. Then:

```bash
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk start --accept-license
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk stop
sudo /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1 -user splunkfwd -group splunkfwd
sudo systemctl list-unit-files | grep -i splunk
```

Record the forwarder's generated service name. The instructions below use `SplunkForwarder`; substitute the reported name if different. [Forwarder installation](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/universal-forwarder-manual/10.0/install-the-universal-forwarder/install-a-nix-universal-forwarder), [least-privileged service setup](https://help.splunk.com/en/data-management/forward-data/universal-forwarder-manual/9.2/working-with-the-universal-forwarder/manage-a-linux-least-privileged-user)

On both forwarders, create `/opt/splunkforwarder/etc/apps/soc_lab/local/outputs.conf`:

```ini
[tcpout]
defaultGroup = soc_indexer

[tcpout:soc_indexer]
server = 192.168.56.30:9997
useACK = true
```

Create the parent directory first using `sudo mkdir -p /opt/splunkforwarder/etc/apps/soc_lab/local`.

On **sensor01 only**, create `inputs.conf` in that directory:

```ini
[monitor:///var/log/suricata/eve.json]
disabled = 0
index = suricata
sourcetype = suricata:eve
host = sensor01
```

On **wazuh01 only**, create its `inputs.conf`:

```ini
[monitor:///var/ossec/logs/alerts/alerts.json]
disabled = 0
index = wazuh
sourcetype = wazuh:alerts
host = wazuh01
```

Do not monitor entire `/var/ossec/logs/` or `/var/log/suricata/` trees. Those include diagnostic logs, rotated files, and alternate representations of the same data. Do not add these source paths on the remote Splunk server itself.

### 8.4 Grant file access and account for rotation

On **sensor01**:

```bash
sudo setfacl -m u:splunkfwd:rx /var/log/suricata
sudo setfacl -m u:splunkfwd:r /var/log/suricata/eve.json
sudo setfacl -m d:u:splunkfwd:rx /var/log/suricata
sudo -u splunkfwd head -n 1 /var/log/suricata/eve.json
```

On **wazuh01**:

```bash
sudo setfacl -m u:splunkfwd:--x /var/ossec /var/ossec/logs
sudo setfacl -m u:splunkfwd:r-x /var/ossec/logs/alerts
sudo setfacl -m u:splunkfwd:r-- /var/ossec/logs/alerts/alerts.json
sudo setfacl -m d:u:splunkfwd:r-x /var/ossec/logs/alerts
sudo -u splunkfwd head -n 1 /var/ossec/logs/alerts/alerts.json
```

Default ACLs help new files inherit access. Creation modes, file moves, or later chmod operations can still change effective permissions. Repeat the read test after the next actual log rotation, and inspect `getfacl` if collection stops. Do not fix permissions by making all security logs world-readable. Splunk's service may also have read capabilities; the explicit account tests verify access without relying on those capabilities.

On both forwarders:

```bash
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder/etc/apps/soc_lab
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk btool check
sudo systemctl start SplunkForwarder
nc -vz 192.168.56.30 9997
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk list forward-server
```

The CLI may prompt for the forwarder's application credentials. The receiver should appear as active. Inspect `/opt/splunkforwarder/var/log/splunk/splunkd.log` if it does not.

### 8.5 Checkpoint: verify fields and time

Generate another HTTP marker from Kali. In Splunk Search & Reporting, choose **Last 15 minutes** and run:

```spl
(index=suricata OR index=wazuh)
| stats count latest(_time) AS latest_event by index sourcetype host
| convert ctime(latest_event)
```

Inspect the raw Suricata alert:

```spl
index=suricata event_type=alert alert.signature_id=1000001
| table _time timestamp host src_ip dest_ip alert.signature alert.severity
```

Inspect its Wazuh representation:

```spl
index=wazuh data.alert.signature_id=1000001
| table _time timestamp agent.name rule.id rule.level data.src_ip data.dest_ip
```

Check that timestamps represent the same moment, JSON is not truncated, and fields are populated. If events appear only under All time, diagnose timestamp parsing before creating scheduled alerts.

**Counting rule:** the direct EVE alert and Wazuh's representation are two records describing the same activity. Do not add their counts and call the sum unique attacks. Take `03-pipeline-ready` snapshots after stopping services and shutting down cleanly.

## 9. Build searches dashboards and alerts

The following searches are written for this guide's raw JSON sourcetypes, not for an installed third-party data model. Validate fields against one expanded event before saving them.

### 9.1 Network alerts by signature

```spl
index=suricata event_type=alert
| stats count AS alerts by alert.signature src_ip dest_ip
| sort - alerts
```

### 9.2 Alert timeline

```spl
index=suricata event_type=alert
| timechart span=1m count by alert.signature limit=10
```

### 9.3 Wazuh events at or above a chosen level

```spl
index=wazuh
| where tonumber('rule.level') >= 7
| stats count AS alerts by agent.name rule.level rule.description
| sort - alerts
```

Wazuh levels and Suricata priorities are different scales. Higher Wazuh levels indicate greater severity; Suricata priority/severity 1 is conventionally highest. Do not directly compare the numbers as one common scale.

### 9.4 HTTP activity for a suspected source

```spl
index=suricata event_type=http src_ip=10.10.10.50
| table _time src_ip dest_ip http.hostname http.url http.http_method http.status
| sort _time
```

Some HTTP fields depend on what was observed in the transaction. Missing status can indicate incomplete capture or an unfinished response, not necessarily a failed request.

### 9.5 Compare network and endpoint evidence

```spl
(index=suricata src_ip=10.10.10.50)
OR (index=wazuh (data.srcip=10.10.10.50 OR data.src_ip=10.10.10.50))
| eval source_ip=coalesce(src_ip,'data.srcip','data.src_ip')
| eval destination_ip=coalesce(dest_ip,'data.dest_ip','agent.ip')
| eval description=coalesce('alert.signature','rule.description',event_type)
| table _time index agent.name source_ip destination_ip description
| sort _time
```

`agent.ip` may be a management address, not the target's LAB address. Preserve the asset inventory rather than assuming two different IPs mean two different endpoints. This timeline assists investigation; it is not a deduplication or correlation engine.

### 9.6 Build a dashboard

1. Run each search individually and confirm meaningful results.
2. Save the timeline as a line-chart panel in a new dashboard named `SOC Lab Overview`.
3. Add a table for top signatures and a table for Wazuh events.
4. Add a single-value panel using `index=suricata event_type=alert | stats count`.
5. Add a data-freshness table:

```spl
(index=suricata OR index=wazuh)
| stats latest(_time) AS last_event by index host
| eval seconds_since_event=round(now()-last_event)
| convert ctime(last_event)
```

6. Add a shared time picker, initially Last 60 minutes. Confirm each panel uses the intended time range.
7. Label panels precisely: `Suricata alert records`, not `Attacks stopped`.

An idle log source may legitimately produce no alerts. A freshness panel based on alert data is an investigation hint; combine it with agent/service status or a periodic known marker to test pipeline health.

### 9.7 Create a scheduled lab alert

Use this deterministic search:

```spl
index=suricata event_type=alert alert.signature_id=1000001
```

1. Select **Save As → Alert**.
2. Name it `SOC LAB — HTTP marker detected`.
3. Use a scheduled search every five minutes, with an initial range of earliest `-6m@m` and latest `-1m@m` to allow a minute of ingestion delay.
4. Trigger when the number of results is greater than zero.
5. Use the Triggered Alerts action where available; no external notifications are required for testing.
6. Generate a marker, wait for the next relevant run, and verify a triggered alert.
7. Inspect execution history if nothing triggers. A working manual search does not prove the scheduler, permissions, or license allows alerting.

This narrow timing window is a starting point. Measure ingestion latency and adjust the delay/lookback. Overlapping windows can create duplicates; introduce suppression or stable event-ID deduplication if you overlap them.

## 10. Run detection and investigation exercises

For every exercise, record a case ID, UTC start/end times, expected observation, actual result, and evidence locations. Disconnect Kali and the target's temporary NAT adapters. Start captures before generating traffic.

### 10.1 Exercise A — HTTP marker, end to end

**Purpose:** prove the complete network detection pipeline with a benign, deterministic request.

On `sensor01`:

```bash
mkdir -p ~/soc-evidence/EX-A
sudo timeout 90 tcpdump -ni enp0s8 -s 0 -w /tmp/soc-ex-a.pcap 'host 10.10.10.50 and host 10.10.10.20'
```

While capture runs, on Kali:

```bash
date -u
curl --max-time 5 http://10.10.10.20/soc-lab-test
```

After capture finishes on the sensor:

```bash
sudo cp /tmp/soc-ex-a.pcap ~/soc-evidence/EX-A/
sudo chown "$(id -un):$(id -gn)" ~/soc-evidence/EX-A/soc-ex-a.pcap
sha256sum ~/soc-evidence/EX-A/soc-ex-a.pcap
```

Verify in this order:

1. PCAP contains the HTTP request.
2. EVE contains signature ID `1000001`.
3. Wazuh contains the matching Suricata alert attributed to `sensor01`.
4. Splunk contains both representations in their respective indexes.
5. The scheduled Splunk alert triggers.
6. If Sentinel is enabled, its Wazuh alert arrives too.

### 10.2 Exercise B — controlled SYN scan

On Kali, ensure Nmap is installed during the preparation phase. Then run only against your designated target:

```bash
sudo nmap -sS -Pn -n -p 1-100 --max-rate 20 10.10.10.20
```

Search for:

```spl
index=suricata event_type=alert alert.signature_id=1000002
| table _time src_ip dest_ip dest_port alert.signature
```

Expect the local SYN-burst rule to match if more than ten matching SYNs are observed within ten seconds. Retransmissions can also contribute. This rule may produce multiple alert records and does not guarantee a one-scan/one-alert relationship.

Confirm the scan using packets, not just the alert message: repeated SYNs from one source to different destination ports support the port-scan interpretation. Open ports and firewall behavior determine responses. Do not assume the downloaded community ruleset must detect this exact scan.

### 10.3 Exercise C — failed SSH authentication

From Kali, make three to five manual attempts with the wrong password for your lab account:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 labuser@10.10.10.20
```

On the target, verify failed-password entries in `/var/log/auth.log`. In Splunk:

```spl
index=wazuh agent.name=target01
| search "Failed password" OR "authentication failed" OR "sshd"
| table _time rule.id rule.level rule.description data.srcip data.dstuser full_log
```

Inspect actual rule IDs and decoded fields before building an aggregate detection. A small number of failures may produce individual authentication alerts without reaching a built-in brute-force threshold.

**Learning point:** Suricata can observe an SSH connection's network behavior, but encrypted SSH does not expose password outcomes. The target's authentication logs supply that evidence.

### 10.4 Exercise D — file-integrity change

After Wazuh's initial scan completes, on `target01`:

```bash
date -u
printf '%s\n' 'exercise D: changed' | sudo tee -a /opt/soc-lab/watch/test.txt
```

Search:

```spl
index=wazuh agent.name=target01 syscheck.path="/opt/soc-lab/watch/test.txt"
| table _time rule.description syscheck.path syscheck.event syscheck.sha256_before syscheck.sha256_after
```

You should see a modification event, with available before/after hashes. Restore the file content afterward; the restoration may create another legitimate event. This exercise validates file monitoring, not malware detection.

### 10.5 Open and analyze the PCAP in Wireshark

Install Wireshark from its official package/source on the host or use Kali's copy. Transfer the sensor's PCAP through your management connection, then open it with **File → Open**. Wireshark is used here for packet evidence, independent of the SIEM. [Wireshark documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html)

Useful **display filters**:

```text
ip.addr == 10.10.10.50 && ip.addr == 10.10.10.20
http.request.uri contains "soc-lab-test"
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.port == 22
```

1. Select the HTTP request and inspect the request URI.
2. Use **Follow → TCP Stream** to view request/response context.
3. Compare packet time, source/destination addresses, and ports with the Suricata event.
4. For the scan, inspect destination port changes and replies.
5. Note that capture filters used by tcpdump and Wireshark display filters are different syntaxes.
6. Preserve the original PCAP and its hash; save annotations or filtered exports separately.

TLS and SSH traffic generally reveal metadata rather than application plaintext. Do not interpret absent plaintext as a capture failure.

## 11. Add Microsoft Sentinel

Complete the local pipeline first. This extension uses a **separate collector VM** so cloud forwarding and received syslog do not feed back into the Wazuh manager's own log collection.

```text
wazuh01 alerts → JSON syslog / UDP 514 → collector01 rsyslog
                                         → AMA → HTTPS → Log Analytics / Sentinel
```

This is a small training transport. UDP does not guarantee delivery, and oversized messages can be lost or truncated. Keep Wazuh's original alerts and the Splunk copy as local evidence. For a production-style extension, use a supported reliable, encrypted export path and test loss, queues, size limits, and recovery explicitly.

### 11.1 Create cloud resources and cost controls

1. Use a subscription where you can create a resource group, Log Analytics workspace, Sentinel resources, DCRs, and Arc/AMA extensions. Relevant scoped roles include Monitoring Contributor and Azure Connected Machine Resource Administrator; workspace/Sentinel onboarding also needs appropriate workspace permissions.
2. Create a dedicated resource group, such as `rg-soc-lab`, in your chosen region.
3. Create a Log Analytics workspace named `law-soc-lab` in that group.
4. Open Microsoft Sentinel and add/enable it on this workspace.
5. Review the current pricing and your subscription's eligibility for any trial. Do not assume the cloud extension is free.
6. Configure an Azure budget alert and review workspace ingestion/retention settings. A budget sends notifications; it is not an automatic spending stop. A daily cap can reduce ingestion but is not an exact total-cost limit.
7. Start with only the Wazuh alert stream. Keep raw EVE flow records and PCAPs local.

The current connector supports Azure and Defender portal workflows; navigation labels may move. [Sentinel connector prerequisites](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama), [cost controls](https://learn.microsoft.com/en-us/azure/sentinel/billing-reduce-costs)

### 11.2 Prepare collector01 and connect Azure Arc

1. Build `collector01` with MGMT address `192.168.56.40` and a NAT adapter for cloud access; no LAB adapter.
2. Apply the common Ubuntu preparation steps and synchronize time.
3. Install and enable rsyslog: `sudo apt install -y rsyslog` and `sudo systemctl enable --now rsyslog`.
4. In Azure Arc → Servers → Add/Create, select onboarding of a single non-Azure server.
5. Choose the resource group, region, and Linux OS; generate the onboarding script.
6. Inspect and run that tenant-specific script on `collector01`, authenticate using the offered flow, and verify that the Arc resource becomes **Connected**.
7. Retain outbound HTTPS/DNS connectivity to the documented Azure endpoints. No public inbound port forwarding is required.

Azure Arc makes the local VM available for Azure management; AMA is the separate component that collects the logs. [Arc onboarding](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-portal)

### 11.3 Configure Syslog via AMA

1. Install the **Syslog** solution from Sentinel's Content hub.
2. Open **Data connectors → Syslog via AMA → Open connector page**.
3. Create a DCR named `dcr-soc-lab-syslog`.
4. Select `collector01` as the resource and `law-soc-lab` as the destination.
5. During initial validation, select all syslog facilities and severities. This dedicated collector should have very little traffic. Later narrow collection to the observed Wazuh facility and severity.
6. Complete creation and verify that the `AzureMonitorLinuxAgent` extension is provisioned successfully and the DCR is associated with `collector01`.
7. Follow the connector's Linux forwarder configuration step. Run the current installation script displayed by that connector to configure rsyslog's receiving/AMA connection.
8. Verify a UDP 514 listener using `sudo ss -lunp | grep ':514'`. If a listener already exists, do not add another duplicate input.
9. Restrict guest firewall ingress to UDP 514 from `192.168.56.20` only. Do not expose it via the NAT adapter or a router forwarding rule.

For a missing UDP listener, inspect `/etc/rsyslog.conf` and `/etc/rsyslog.d/`. If the connector installed no UDP input, add one file with:

```text
module(load="imudp")
input(type="imudp" port="514")
```

Only load `imudp` once. Validate with `sudo rsyslogd -N1`, then restart rsyslog. Preserve the AMA-generated forwarding configuration rather than hard-coding an internal AMA port. [Forwarder tutorial](https://learn.microsoft.com/en-us/azure/sentinel/forward-syslog-monitor-agent)

### 11.4 Verify transport before sending Wazuh data

From `wazuh01`:

```bash
logger --udp --server 192.168.56.40 --port 514 --tag soc-lab -p local5.info 'SOC-LAB-AMA-SMOKE-TEST'
```

On the collector, verify arrival using `sudo tcpdump -ni any udp port 514`. In workspace Logs:

```kusto
Syslog
| where TimeGenerated > ago(30m)
| where SyslogMessage has "SOC-LAB-AMA-SMOKE-TEST"
| project TimeGenerated, Computer, Facility, SeverityLevel, ProcessName, SyslogMessage
```

Initial connector setup can take time; Microsoft advises that syslog can take up to 20 minutes to appear after configuration. A connected extension alone does not prove ingestion. [AMA troubleshooting](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-troubleshooting)

### 11.5 Enable Wazuh JSON syslog output

On `wazuh01`, back up `/var/ossec/etc/ossec.conf`. Ensure the existing `<global>` section contains `<jsonout_output>yes</jsonout_output>`. Add inside the top-level configuration:

```xml
<syslog_output>
  <server>192.168.56.40</server>
  <port>514</port>
  <format>json</format>
  <level>3</level>
</syslog_output>
```

Level 3 is an initial lab threshold so ordinary test alerts are included; it cannot recover events below the manager's own alert-writing threshold. Raise it later only after checking which exercises would be excluded. Restart the manager and generate a **new** HTTP marker. [Wazuh syslog output](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syslog-output.html)

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-control status
```

### 11.6 Parse and validate in KQL

Run in workspace Logs:

```kusto
Syslog
| where TimeGenerated > ago(1h)
| extend JsonText = extract(@"(\{.*\})", 1, SyslogMessage)
| extend W = parse_json(JsonText)
| where isnotempty(tostring(W.rule.id))
| extend WazuhId = tostring(W.id),
         EventTime = todatetime(W.timestamp),
         Agent = tostring(W.agent.name),
         RuleId = tostring(W.rule.id),
         RuleLevel = toint(W.rule.level),
         Description = tostring(W.rule.description),
         SrcIp = coalesce(tostring(W.data.srcip), tostring(W.data.src_ip)),
         SignatureId = tostring(W.data.alert.signature_id)
| project TimeGenerated, EventTime, WazuhId, Agent, RuleId,
          RuleLevel, Description, SrcIp, SignatureId, Facility, SeverityLevel
| order by TimeGenerated desc
```

The JSON extraction accommodates a syslog prefix. Confirm the actual payload has complete braces and parseable fields. If parsing fails, inspect `SyslogMessage` without filtering; do not silently treat dropped rows as successful ingestion.

Compare the Wazuh event ID and marker signature with the local alert. `TimeGenerated` is the syslog record's time; `EventTime` is the original embedded Wazuh time. Preserve both. Once working, narrow the DCR to the actual facility/severity observed, repeat the test, and check for losses.

### 11.7 Create a Sentinel incident from the marker

Create a scheduled analytics rule using:

```kusto
Syslog
| extend W = parse_json(extract(@"(\{.*\})", 1, SyslogMessage))
| where tostring(W.data.alert.signature_id) == "1000001"
| extend WazuhId = tostring(W.id),
         SrcIp = tostring(W.data.src_ip),
         DstIp = tostring(W.data.dest_ip),
         Agent = tostring(W.agent.name)
| summarize arg_max(TimeGenerated, *) by WazuhId
```

1. Name it `SOC LAB — Wazuh HTTP marker` and use Low severity for this benign test.
2. Run every five minutes with a ten-minute lookback during initial latency testing.
3. Trigger if results exceed zero and enable incident creation.
4. Map IP Address entities to `SrcIp` and `DstIp` where the editor allows; retain Agent and WazuhId as custom details.
5. Use alert/incident grouping or suppression to control repeated results across overlapping runs. The `summarize` above removes duplicates within a run only.
6. Generate a fresh marker, verify the alert and incident, inspect entities, add an analyst note, and close with a classification explaining the authorized lab simulation.

Record observed ingestion delay and tune the lookback accordingly. Do not label an authorized simulation as a real compromise. [Scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)

### 11.8 Cloud shutdown and cleanup

For a short pause, stop Wazuh syslog forwarding and the collector; review retained storage costs. For full teardown, export wanted evidence and rule definitions, disconnect/remove the Arc registration following its cleanup instructions, and delete the dedicated lab resource group only after verifying it contains no unrelated resources. Check for any resources created outside it. Stopping a local VM does not delete cloud storage or other billable resources.

## 12. Operate the lab

### 12.1 Start-of-session procedure

1. Start `wazuh01` and `splunk01` first.
2. Wait for their dashboards to load and central services to become healthy.
3. Start `sensor01`, then `target01`; verify Wazuh agent connections and forwarder status.
4. Start the optional collector and verify Arc/AMA when using Sentinel.
5. Start Kali last. Confirm it has only its intended LAB connectivity for exercises.
6. Check clock synchronization after any snapshot restore. If updating requires NAT, temporarily reconnect it, synchronize, then disconnect it from exercise endpoints.
7. Check free disk and memory on sensor and SIEM VMs:

```bash
df -h
free -h
```

8. Check sensor capture statistics and log growth. Investigate sustained packet drops, permission errors, or indexing backlogs.
9. Run one HTTP marker and verify the full path. Record the health-check time so it can be excluded from exercise counts.
10. Create the new case folder and begin packet capture if required.

### 12.2 During a session

Keep a UTC activity log. Record each command and target before running it. Check results at the source first, then at each downstream system. Preserve anomalies: a missed event is a useful finding if you document where it disappeared. Change one rule or setting at a time and repeat the same test.

### 12.3 End-of-session procedure

1. Stop traffic generation and captures.
2. Export selected events, queries, screenshots, and PCAPs; calculate hashes of evidence files.
3. Record open issues, false positives, rule changes, and next steps.
4. Stop Kali, then the target.
5. Allow the sensor and forwarders to drain. Verify the last expected events arrived.
6. Stop sensor and collector, then shut down Splunk and Wazuh cleanly using `sudo shutdown -h now`.
7. Take consistent powered-off snapshots if preserving a new milestone. Snapshots are rollback points, not independent backups.

### 12.4 Weekly maintenance

| Area | Procedure | Success check |
|---|---|---|
| OS updates | Update with temporary NAT during a maintenance session; reboot as needed | Network and service health tests pass |
| Suricata rules | Back up config/local rules; run `suricata-update`, configuration test, restart | Both local signatures still fire |
| Wazuh updates | Review compatibility/release notes; back up; unhold and upgrade central components coherently before agents | Agents reconnect; baseline exercises pass |
| Splunk updates | Back up app configs and follow selected release's supported upgrade path | Ingestion, searches, and scheduled alerts pass |
| Rotation | Inspect new EVE and Wazuh alert files and effective permissions | Forwarders read events after rotation |
| Storage | Review retention and growth on both SIEMs and sensor | Free space remains above your chosen threshold |
| Azure | Inspect daily ingestion and charges | Only intended sources/facilities arrive |

Run the Suricata update validation as separate steps:

```bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

Do not restart after a failed configuration test. Keep local rules outside the generated `suricata.rules` file.

### 12.5 Backups and retention

Back up these configuration locations securely:

| Machine | Configuration to preserve |
|---|---|
| All Linux VMs | Netplan files, hostname/IP inventory, firewall rules |
| Sensor | `/etc/suricata/`, Wazuh agent config, forwarder `soc_lab` app |
| Wazuh | `/var/ossec/etc/`, required certificates/credentials, supported indexer backup if preserving history |
| Splunk | `/opt/splunk/etc/apps/soc_lab/`, saved searches/dashboards, supported backup of wanted indexed data |
| Collector | rsyslog config and exported DCR/analytics definitions |

Agent keys and credentials are sensitive; a public Git repository is not an appropriate backup destination for them. Configuration backups alone do not preserve indexed history. Test one restore before depending on your backups.

For local Suricata logs, inspect the package's existing logrotate configuration before adding another rotation policy. Maintain one owner for rotation, check disk use, and re-test forwarding after rotation. Avoid deleting active log files to free space. For Wazuh indexer history, use its supported index lifecycle/retention settings rather than removing index files from disk.

## 13. Investigate and document incidents

Use the same sequence for every alert:

1. **Validate the alert:** identify source tool, rule, time, endpoint, and raw event. Confirm that the rule means what its title implies.
2. **Establish scope:** resolve management and LAB addresses to assets; search the source and destination over a narrow window, then expand it if justified.
3. **Build a timeline:** compare network events, target authentication/access logs, and file events. Distinguish source-event time from ingestion time.
4. **Verify with packets:** where a PCAP exists, identify the actual request, connection, or scan. Record encryption and capture limitations.
5. **Classify:** authorized simulation, benign expected activity, detection false positive, or suspicious activity needing further investigation.
6. **Contain if needed in the lab:** disconnect the affected target's virtual adapters through the hypervisor. Preserve console access and evidence before reverting it.
7. **Recover:** restore known-good state, reconnect deliberately, and verify agents and the marker test again.
8. **Improve detection:** record a narrowly scoped rule change and compare its effect on the same exercise plus normal traffic.

Use this case template in your notes:

```text
Case ID:
Analyst / date:
Exercise or suspected activity:
UTC start and end:
Source and destination / asset mapping:
Rule IDs and descriptions:
Expected result:
Actual result at sensor / Wazuh / Splunk / Sentinel:
Timeline:
Evidence filenames and SHA-256 hashes:
Queries used and time range:
Assessment and confidence:
Containment / recovery performed:
Limitations or missing telemetry:
Detection change and retest result:
Closure classification:
```

Do not automatically block based on the lab SYN-burst rule. Automated response can disconnect agents or administrators and obscure the exercise. Introduce it later with a short timeout, a narrow target, and a tested recovery path.

## 14. Troubleshooting

Work left to right through the pipeline. Fix the earliest failed checkpoint rather than changing several downstream settings at once.

| Symptom | Likely cause | Check and corrective action |
|---|---|---|
| Kali cannot reach target | Wrong internal network name, interface address, or target firewall | Check both VM adapter settings, `ip route`, target listener, and firewall |
| Sensor sees ARP but no peer unicast | No virtual-switch traffic copy | Recheck sensor promiscuous policy; configure actual port mirroring or use target-local capture |
| Suricata running, EVE empty | Wrong service interface or no traffic | Inspect systemd unit and `tcpdump` on the configured interface |
| EVE contains HTTP but no marker alert | Local rule not loaded or URI/IP mismatch | Run `suricata -T`, inspect rule-files, and reproduce exact request |
| Only some flows detected | Asymmetric capture, drops, offload effects | Inspect capture/stats; compare both directions in PCAP before changing offload settings |
| Wazuh agent never active | Enrollment blocked, duplicate identity, wrong manager, incompatible version | Check 1514/1515 connectivity and endpoint `ossec.log` |
| Wazuh receives target logs but not EVE | Wrong localfile location or permissions | Inspect sensor agent config and use one EVE line in manager `wazuh-logtest` |
| Wazuh dashboard missing but manager runs | Central stack incomplete or indexer/dashboard failure | Check all four central services; manager alone does not provide UI |
| File changes absent | Directory missing during startup or baseline unfinished | Create directory, restart agent, wait for scan, then modify again |
| SSH failures absent | Wrong auth source, collection duplicated/missing, password auth disabled | Read target auth.log first and inspect effective SSH settings |
| Splunk has no data | Receiver/firewall/output/index/permissions error | Test 9997, forward-server status, file read access, and both sides' splunkd.log |
| Splunk fields absent | Sourcetype differs from props stanza | Check `sourcetype`, parsing app, and raw JSON; try `spath` diagnostically |
| Splunk only shows events under All time | Clock or timestamp parser problem | Compare raw timestamp and `_time`; inspect TIME_PREFIX and system clocks |
| Forwarding stops after midnight | Rotated file not readable | Check `getfacl`, parent traversal permissions, and current filename |
| Events appear duplicated | Overlapping inputs, archives re-read, both EVE and Wazuh counted | List effective monitor stanzas; count sources separately |
| Search works but alert does not | Schedule, time window, permissions, or license | Check alert execution history and trigger actions |
| Sentinel has heartbeat but no syslog | DCR/facility/receiver/AMA handoff issue | Follow packet arrival → rsyslog → DCR association → workspace table |
| Sentinel has syslog but no parsed Wazuh | Non-JSON format or truncated payload | Inspect complete `SyslogMessage`, compare original alert length and JSON |
| Sentinel incident absent | Query mismatch, scheduling delay, disabled rule, filtering threshold | Run query manually on known marker and inspect rule status |
| Services fail after restore | Time jump, stale addresses, partial multi-VM restore | Synchronize clocks, confirm identities and addressing, restart in dependency order |

Useful diagnostics, on the appropriate machine:

```bash
sudo journalctl -u suricata -n 100 --no-pager
sudo journalctl -u wazuh-agent -n 100 --no-pager
sudo tail -n 100 /var/ossec/logs/ossec.log
sudo tail -n 100 /opt/splunkforwarder/var/log/splunk/splunkd.log
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk btool inputs list --debug
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk btool outputs list --debug
sudo -u splunk /opt/splunk/bin/splunk btool props list --debug
```

Only run commands for software installed on that VM. Btool shows the effective file origin of settings, which helps identify a conflicting app configuration.

## 15. Acceptance checklist

The core lab is ready when all core checks pass:

- [ ] Kali and target use the isolated LAB network, with temporary NAT disconnected for exercises.
- [ ] Host can administer designated MGMT addresses; Kali has no MGMT adapter.
- [ ] Sensor sees bidirectional Kali-to-target traffic.
- [ ] Wazuh central services are healthy and both agents are active.
- [ ] HTTP marker produces local Suricata signature `1000001`.
- [ ] Wazuh receives the matching alert.
- [ ] Splunk receives direct EVE records and Wazuh alerts in separate indexes.
- [ ] JSON fields and source timestamps are correct.
- [ ] Scheduled marker alert fires.
- [ ] Controlled SYN scan, failed SSH attempts, and file-change exercise produce the expected evidence or a documented explanation of any threshold limitation.
- [ ] A PCAP supports at least one network alert.
- [ ] New events still arrive after a log rotation and reboot.
- [ ] Configurations, versions, and at least one completed case are saved.
- [ ] Optional: Sentinel receives the marker, parses its Wazuh ID, and creates an incident.
- [ ] Optional: cloud ingestion and budget controls have been reviewed.

## 16. Extensions

After the baseline passes, add one capability at a time:

1. **Windows endpoint:** create a licensed/evaluation Windows VM, attach MGMT and LAB appropriately, install the Windows Wazuh agent using the dashboard's Windows command, verify Security/System/Application collection, and repeat a known event test. Never run the Linux apt command on Windows.
2. **Windows process telemetry:** add Sysmon using an explicitly reviewed configuration, collect `Microsoft-Windows-Sysmon/Operational`, and validate a benign process event before adding detection rules.
3. **TLS for Splunk forwarding:** deploy a trusted lab CA and certificates with correct identities, configure the SSL receiver and forwarder verification, then prove wrong certificates fail and valid forwarding works.
4. **Detection tuning:** replace broad thresholds with evidence-based conditions; test normal activity alongside each simulated case.
5. **Packet replay:** analyze known benign/training PCAPs with Suricata in an independent offline output directory. Label replay events and preserve original timestamps so they are not mistaken for live incidents.
6. **Response automation:** introduce one reversible Wazuh response with a short timeout and test its impact on connectivity.

Keep the working baseline snapshot and a brief change log. A useful SOC lab is one where you can explain what happened, show the evidence, identify what was missed, and reproduce the result after a change.
