# Deploy CRUCIBLE on Vultr VMs

The SSH deployment scripts prepare existing Debian or Ubuntu VMs. VM creation
and VPC attachment use separate guarded helpers below. The control VM serves
the dashboard at `127.0.0.1:8787`; the sandbox VM applies the dedicated
firewall policy, builds the worker, and runs `infra/prove-wall.sh`.

The guarded provisioning helper below uses Vultr's default `root` login. If
you deploy an instance with Vultr's Limited User Login option, substitute its
`linuxuser` account and arrange passwordless `sudo` for the deployment command.

## Existing VM

1. Use a dedicated VM with a current Debian or Ubuntu image, systemd, Python
   3.10 or newer, SSH access, and a user with noninteractive `sudo`. Review the
   VM's Docker networking first:
   the default CRUCIBLE bridge is `br-crucible` on `172.30.80.0/24`; neither
   name nor subnet should already serve another workload. The script requires
   Docker's `iptables` backend and its `DOCKER-USER` chain. Docker documents
   [`DOCKER-USER`](https://docs.docker.com/engine/network/firewall-iptables/)
   as the place for user forwarding rules.
2. Verify the VM's SSH host key out of band and add it to `known_hosts`. Use a
   [Vultr SSH key](https://docs.vultr.com/products/compute/instances/vx1-cloud-compute/connection/openssh)
   for the login; adding a key through the deployment settings later can
   reinstall the instance.
3. Commit the application files locally. The archive builder reads **only
   committed Git blobs** from an explicit allowlist under `crucible/`, `infra/`,
   `dsh/`, and selected `deploy/` bootstraps and the remote gateway. It never includes `secrets/`, `data/`,
   `.env` files, planning documents, or uncommitted changes. If the checkout
   does not have Git metadata and a commit, deployment stops.
4. Deploy:

   ```bash
   ./deploy/ssh-deploy.sh --target root@YOUR_VM_IP --identity ~/.ssh/YOUR_KEY --apply
   ```

   This installs missing `docker.io`, `iptables`, and Python packages with
   `apt-get`, preserving an existing Docker installation and daemon settings.
   The VM must be able to pull the Python base image and resolve the configured
   HTTPS allowlist. The installer runs `setup-net.sh`, builds the worker image,
   runs `prove-wall.sh`, and starts the systemd dashboard only after the proof
   passes. It leaves previous releases and `/var/lib/crucible/data` in place.
   A failed dashboard health check restores the prior release symlink.
5. Read the evidence printed by the VM, including the default DROP counter,
   teardown check, and syscall results. Local simulation results do not prove
   the Linux wall. Inspect service logs with
   `sudo journalctl -u crucible-dashboard.service` and firewall counters with
   `sudo iptables -nvx -L CRUCIBLE_EGRESS`.
6. Reach the private dashboard through an SSH tunnel:

   ```bash
   ssh -i ~/.ssh/YOUR_KEY -L 8787:127.0.0.1:8787 root@YOUR_VM_IP
   ```

   Open `http://127.0.0.1:8787` locally. If a public dashboard is required,
   configure a separate authenticated TLS reverse proxy and review its access
   rules. The deployment script never opens or publishes the dashboard port.

The firewall setup touches the dedicated Docker bridge, the `CRUCIBLE_EGRESS`
chain, and bridge-specific `DOCKER-USER`, `INPUT`, and IPv6 rules. It does not
flush general host firewall rules. Docker notes that published container ports
can bypass some host firewall frontends, so keep the dashboard on loopback and
avoid publishing worker ports: [Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

The Docker image is the production execution path here. The local DSH adapter
can call a host broker, but this deployment does not install DSH or place its
tool execution inside the per-task worker container. Do not treat DSH host
tool calls as isolated by the container wall.

## Two-VM control and sandbox deployment

This variant runs the model, pre-exec classifier, experience bank, and loopback
dashboard on **VM1 (control)**. VM1's `--control` bootstrap does not install
Docker. **VM2 (sandbox)** runs rootful Docker, the D1/D2 wall, and a forced SSH
gateway; its `--sandbox` bootstrap installs no inference key, management key,
bank, or dashboard. Each episode creates one VM2 container, then destroys it.
The SSH client requires a pinned host key and a private RFC 1918 destination.
The gateway accepts only bounded create/exec/destroy/cleanup messages, checks
the episode label and a four-container capacity limit, and scans results before
returning them. VM1 scans them again. A successful pre-exec judgment alone is
still not kernel evidence; keep VM2's `prove-wall.sh` output with the demo.

1. Select one region, two available VM plans, a combined compute estimate cap,
   a 24-hour (or shorter) teardown target, and a public admin `/32`. Both VMs
   must be in the **same region**. The first provisioning state is separate from
   the second. Replace the example plan and admin address with the live catalog
   choices. Run each command without `--apply` first, review both estimates,
   then append `--apply --confirm-hourly-billing` to create each VM:

   ```bash
   python3 -m deploy.provision_vm provision --region sjc --plan vc2-2c-4gb \
     --ssh-public-key ~/.ssh/YOUR_ADMIN_KEY.pub --admin-ip YOUR_PUBLIC_IPV4/32 \
     --max-hours 24 --max-total-spend 10.00 --state-file secrets/control_vm.json
   python3 -m deploy.provision_vm provision --region sjc --plan vx1-g-2c-8g-120s \
     --ssh-public-key ~/.ssh/YOUR_ADMIN_KEY.pub --admin-ip YOUR_PUBLIC_IPV4/32 \
     --max-hours 24 --max-total-spend 10.00 --state-file secrets/sandbox_vm.json \
     --peer-state secrets/control_vm.json
   ```

   The second command checks **the sum** of the first recorded estimate and
   the second live plan estimate against `$10`; neither helper imposes an
   automatic billing cap. A partial retry can reuse an unattached firewall
   group only through `--existing-firewall-group-id ID`, after the helper
   verifies its description and exact sole `/32` SSH rule. Inspect the account
   before retrying any timed-out write.

2. Create or select one Vultr private VPC network and attach both recorded VM IDs.
   The helper is read-only until `--apply`; it records the VPC ID in ignored
   `secrets/vpc_pair.json` and verifies both nodes after attachment:

   ```bash
   python3 deploy/vpc_pair.py --control-state secrets/control_vm.json \
     --sandbox-state secrets/sandbox_vm.json --kind vpc
   python3 deploy/vpc_pair.py --control-state secrets/control_vm.json \
     --sandbox-state secrets/sandbox_vm.json --kind vpc --apply
   ```

   The account used for this run returned HTTP 404 for the documented VPC 2.0
   API, so `--kind vpc` uses the working [VPC create API](https://docs.vultr.com/public/doc-assets/pdfs/collection_item/products-network-vpc-provisioning.pdf)
   and [instance attach API](https://docs.vultr.com/public/doc-assets/pdfs/collection_item/products-compute-cloud-compute-networking-vpc.pdf).
   The helper's default `--kind vpc2` remains available where supported.
   Wait for both VMs to return to `active/ok/running` and for cloud-init to
   configure the private interface; inspect `ip -4 -o addr show scope global`
   on each VM and record `CONTROL_PRIVATE` and `SANDBOX_PRIVATE`. Confirm the
   two private IPs are on the same VPC and do not overlap the CRUCIBLE Docker
   bridge (`172.30.80.0/24`). The VPC should carry only these two VMs.

3. Verify each VM's **public** SSH host-key fingerprint through the Vultr web
   console, then pin both public host keys locally for the strict SSH deployer.
   Deploy the sandbox first and retain its printed wall proof. Deploy the
   control VM second:

   ```bash
   ./deploy/ssh-deploy.sh --target root@SANDBOX_PUBLIC \
     --identity ~/.ssh/YOUR_ADMIN_KEY --known-hosts secrets/admin_known_hosts --sandbox --apply
   ./deploy/ssh-deploy.sh --target root@CONTROL_PUBLIC \
     --identity ~/.ssh/YOUR_ADMIN_KEY --known-hosts secrets/admin_known_hosts --control --apply
   ./deploy/install-inference-key.sh --target root@CONTROL_PUBLIC \
     --identity ~/.ssh/YOUR_ADMIN_KEY --known-hosts secrets/admin_known_hosts --apply
   ```

   The inference key goes only to VM1 at `/etc/crucible/inference.env`. The
   local `secrets/vultr_key.json` management key goes to neither VM.

4. On VM1, create a dedicated control-to-sandbox Ed25519 key under
   `/etc/crucible/worker_ed25519` (mode `0600`). Transfer **only its `.pub`
   file** to VM2 using the verified admin SSH connection. On VM2 run:

   ```bash
   ssh -i ~/.ssh/YOUR_ADMIN_KEY root@CONTROL_PUBLIC \
     'install -d -m 0700 /etc/crucible && test ! -e /etc/crucible/worker_ed25519 && ssh-keygen -q -t ed25519 -N "" -f /etc/crucible/worker_ed25519'
   ssh -i ~/.ssh/YOUR_ADMIN_KEY root@CONTROL_PUBLIC \
     'cat /etc/crucible/worker_ed25519.pub' > /tmp/crucible-control.pub
   scp -i ~/.ssh/YOUR_ADMIN_KEY /tmp/crucible-control.pub \
     root@SANDBOX_PUBLIC:/root/crucible-control.pub
   ssh -i ~/.ssh/YOUR_ADMIN_KEY root@SANDBOX_PUBLIC \
     'sudo /opt/crucible/current/deploy/authorize-control-key.sh --control-ip CONTROL_PRIVATE --public-key-file /root/crucible-control.pub --apply && rm /root/crucible-control.pub'
   rm /tmp/crucible-control.pub
   ```

   This appends `restrict,from="CONTROL_PRIVATE",command="...remote-worker-gateway.py"`
   to root's `authorized_keys`. It does not install the VM1 private key on
   VM2. Remove `/root/crucible-control.pub` after installation.

5. Pin VM2's **private-IP** host key on VM1. Obtain VM2's
   `/etc/ssh/ssh_host_ed25519_key.pub` through the already verified admin SSH
   path, compare its fingerprint with the Vultr console, and put one line
   `SANDBOX_PRIVATE ssh-ed25519 KEY_BLOB` in
   `/etc/crucible/worker_known_hosts` on VM1, root-owned and mode `0600`.
   The remote client ignores user SSH config and global known-hosts files; this
   dedicated file is its sole trust source. After independently checking the
   fingerprint, these commands construct that exact line:

   ```bash
   ssh -i ~/.ssh/YOUR_ADMIN_KEY root@SANDBOX_PUBLIC \
     'cat /etc/ssh/ssh_host_ed25519_key.pub' > /tmp/crucible-sandbox-host.pub
   ssh-keygen -lf /tmp/crucible-sandbox-host.pub
   awk -v host=SANDBOX_PRIVATE '{print host, $1, $2}' \
     /tmp/crucible-sandbox-host.pub > /tmp/crucible-worker-known-hosts
   scp -i ~/.ssh/YOUR_ADMIN_KEY /tmp/crucible-worker-known-hosts \
     root@CONTROL_PUBLIC:/tmp/crucible-worker-known-hosts
   ssh -i ~/.ssh/YOUR_ADMIN_KEY root@CONTROL_PUBLIC \
     'install -m 0600 /tmp/crucible-worker-known-hosts /etc/crucible/worker_known_hosts && rm /tmp/crucible-worker-known-hosts'
   rm /tmp/crucible-sandbox-host.pub /tmp/crucible-worker-known-hosts
   ```

6. Add the control private IP as an SSH `/32` in VM2's Vultr firewall group
   while retaining public admin access during the test. The helper verifies
   the expected group and rules. Vultr says firewall groups apply to the
   [main network interface](https://docs.vultr.com/products/network/firewall-groups/management/link/),
   so the forced SSH key and VPC remain required even if the provider's group
   does not filter the private interface:

   ```bash
   python3 deploy/limit_sandbox_ssh.py --sandbox-state secrets/sandbox_vm.json \
     --admin-ip YOUR_PUBLIC_IPV4/32 --control-private-ip CONTROL_PRIVATE
   python3 deploy/limit_sandbox_ssh.py --sandbox-state secrets/sandbox_vm.json \
     --admin-ip YOUR_PUBLIC_IPV4/32 --control-private-ip CONTROL_PRIVATE --apply
   ```

7. Run a private SSH episode from VM1. Use these variables with the active
   release and a root shell on VM1; the command prints `execution_mode=remote`
   and the dashboard labels remote runs separately from same-host Docker and
   simulation:

   ```bash
   cd /opt/crucible/current
   CRUCIBLE_ENV_FILE=/etc/crucible/inference.env \
   CRUCIBLE_REMOTE_TARGET=root@SANDBOX_PRIVATE \
   CRUCIBLE_REMOTE_IDENTITY=/etc/crucible/worker_ed25519 \
   CRUCIBLE_REMOTE_KNOWN_HOSTS=/etc/crucible/worker_known_hosts \
     python3 -m crucible demo --mode vultr --execution remote --rounds 4
   ```

   Confirm the expected VM2 worker was created, its CID was destroyed, and the
   VM2 wall proof shows the direct-IP DROP counter, allowed TLS, blocked DNS,
   and denied syscall. After the private path succeeds, remove VM2's public
   admin `/32` rule with:

   ```bash
   python3 deploy/limit_sandbox_ssh.py --sandbox-state secrets/sandbox_vm.json \
     --admin-ip YOUR_PUBLIC_IPV4/32 --control-private-ip CONTROL_PRIVATE \
     --close-public-admin --private-path-verified --apply
   ```

   The final flag records an operator-verified private SSH test; the helper
   cannot perform that test from the local laptop. Use the Vultr console for
   recovery if private access later fails. Export sanitized evidence, then
   destroy **both** VMs after the proof to stop hourly compute billing. Also
   remove the temporary VPC/firewall resources when the demo is finished.

## Guarded Cloud Compute provisioning

`python3 -m deploy.provision_vm list --region sjc` reads the live Vultr
region, availability, OS, and plan catalogs, including available VX1 plans.
The provisioning command is a
**dry run by default**. It requires a selected region, plan, local `.pub` SSH
key, public admin IPv4 `/32`, and either maximum planned hours or maximum
estimated compute spend. For example, after replacing the example values with
your own approved choices:

```bash
python3 -m deploy.provision_vm provision \
  --region YOUR_REGION --plan YOUR_PLAN \
  --ssh-public-key ~/.ssh/YOUR_KEY.pub --admin-ip YOUR_PUBLIC_IPV4/32 \
  --max-hours 24 --max-total-spend 1.00 --dry-run
```

The local management key is read from ignored `secrets/vultr_key.json` by
default. Set `CRUCIBLE_MANAGEMENT_KEY_FILE` to another owner-only local key
file when rotating it. The file must be mode `0600` with an `api_key` field.
It is used only from the controller; it never moves to the VM. The dry run checks live region
availability and prices and prints the key fingerprint without printing key
material. Once the user has approved the concrete region, plan, admin IP,
key, and spend, append `--apply --confirm-hourly-billing` instead of
`--dry-run`. That command registers the selected public key if needed,
creates a fresh default-deny Vultr firewall group with only TCP/22 from the
specified `/32`, verifies the rule, and creates an Ubuntu 24.04 VM with the
key and firewall attached. IPv6, backups, and DDoS add-ons are disabled.
It prints the resource IDs, public IPv4, hourly rate, and planned destroy
time; an ignored recovery record is saved at `secrets/provisioned_vm.json`.
If a write request times out, inspect the account before retrying because
the request may already have created a resource.

The hours or spend amount is a **planning estimate**, not an automatic
billing cap. To avoid understating rounded API rates, the estimate uses the
higher of the catalog hourly rate and monthly price divided by Vultr's
672-hour non-GPU monthly cap, then rounds up to cents. The helper does not
destroy the VM at the deadline. Destroy the
VM to stop hourly charges; a powered-off VM still incurs charges. The
[Vultr billing guide](https://docs.vultr.com/support/platform/billing/how-am-i-billed-for-my-servers)
explains the hourly minimum and ongoing billing. The live API response supplies
the compute rate, while taxes, bandwidth overages, and other separately billed
resources are outside this estimate. The helper accepts a listed VX1
local-NVMe plan when available in the selected region. VX1 is useful if a
later experiment needs `/dev/kvm`; the currently attested worker still uses
Docker `runc` and does not claim a microVM boundary merely because it runs on
VX1. The helper uses the documented
[SSH key](https://docs.vultr.com/products/orchestration/ssh-keys/add-ssh-keys),
[firewall rule](https://docs.vultr.com/products/network/firewall-groups/management/rules),
and [instance](https://docs.vultr.com/reference/terraform/resources/instance)
fields. Available VX1 plans are supported by the same guarded helper.

## Inference-only credential on the VM

After verifying the VM SSH host key and deploying the application, run
`./deploy/install-inference-key.sh --target root@YOUR_VM_IP --identity
~/.ssh/YOUR_KEY --apply`. It sends only the Serverless Inference key from the
private local `.env.local` through SSH and installs it root-owned at
`/etc/crucible/inference.env` with mode `0600`. The Vultr **management** key
remains on the controller. For a live CLI command on the VM, use
`sudo env CRUCIBLE_ENV_FILE=/etc/crucible/inference.env python3 -m crucible ...`.

## VX1 checks

Choose a **region** and a **maximum spend** before provisioning. No API key is
needed for the deployment scripts above.

- Check VX1 availability in the selected region, select a plan and boot disk,
  and record the hourly rate in the Vultr Console. The [VX1 provisioning
  guide](https://docs.vultr.com/products/compute/instances/vx1-cloud-compute/provisioning)
  notes that availability varies by region and distinguishes local NVMe from
  block boot options. Avoid hardcoding a plan, OS ID, or price.
- Set a budget and teardown time before deployment. [Vultr billing](https://docs.vultr.com/support/platform/billing/how-am-i-billed-for-my-servers)
  is hourly from deployment, and stopping a VM does not stop compute billing;
  destroy it when the experiment ends, while checking for separately billed
  storage or other resources.
- Choose a supported Debian or Ubuntu image and attach your SSH key **at
  creation**. Add a [Vultr Firewall Group](https://docs.vultr.com/products/compute/instances/vx1-cloud-compute/networking/enable-firewall)
  permitting SSH only from your trusted address. The dashboard needs no public
  inbound rule. Keep the CRUCIBLE bridge CIDR clear of other Docker/VPC ranges.
- `deploy/provision_vm.py` uses the Vultr **management** API key on the trusted
  controller for guarded API deployment. It verifies the chosen VX1 plan in
  the live regional catalog and estimates compute charge before any write.
  Keep that key out of the worker container and deployment archive. The
  [VX1 API examples](https://docs.vultr.com/vultr-vx1-cloud-compute) use
  `POST /v2/instances` with region, plan, and OS fields.

The installer uses Debian/Ubuntu's `docker.io` package only when Docker is
absent. Docker's [official Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/)
describes the separate Docker CE package route and package conflicts; if you
already use Docker CE, this installer leaves it intact.
