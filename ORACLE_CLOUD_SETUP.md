# Oracle Cloud Always Free — Provisioning Guide

Follow these steps to get a free VPS running before you SSH in and run `setup_vps.sh`.

---

## Step 1 — Create an Oracle Cloud account

1. Go to **https://cloud.oracle.com** and click **Start for free**.
2. Fill in your name, email, and choose a **Home Region** — pick the one closest to you (London, Frankfurt, or Amsterdam are good for EU; Ashburn/Phoenix for US). **You cannot change the home region later.**
3. Enter a credit/debit card for identity verification. Always Free resources are **never charged**.
4. Complete email verification. Your account may take a few minutes to activate.

---

## Step 2 — Launch an Always Free VM

1. In the OCI Console, click the **☰ hamburger menu → Compute → Instances → Create instance**.
2. **Name:** `threatscope-honeypot` (or anything you like).
3. **Image:** Click *Edit* → *Change image* → choose **Ubuntu 22.04** (Canonical).
4. **Shape:** Click *Edit* → *Change shape* → **Ampere** tab → `VM.Standard.A1.Flex`
   - Set **OCPUs = 1**, **Memory = 6 GB** (well within Always Free limits of 4 OCPUs / 24 GB total).
5. **Networking:** Leave defaults (a new VCN is created automatically). Make sure **Assign a public IPv4 address** is checked.
6. **SSH keys:** Click *Save private key* to download your `.key` file. Save it somewhere safe — you need it to SSH in.
7. Click **Create**. The instance will be in *Provisioning* state for ~1–2 minutes, then *Running*.
8. Note the **Public IP address** shown on the instance details page.

---

## Step 3 — Open ports in the OCI Security List (cloud firewall)

OCI blocks all inbound traffic by default. You must open the honeypot ports at the cloud layer.

1. In the instance details, click the **Subnet** link → **Default Security List** → **Add Ingress Rules**.
2. Add one rule per row below (Source CIDR = `0.0.0.0/0`, Protocol = TCP):

| Port(s)                         | Purpose                   |
|---------------------------------|---------------------------|
| `49222`                         | Your new SSH port         |
| `22`                            | Honeypot (SSH lure)       |
| `23`                            | Honeypot (Telnet lure)    |
| `80`                            | Honeypot (HTTP lure)      |
| `443`                           | Honeypot (HTTPS lure)     |
| `2222`                          | Honeypot (SSH-alt lure)   |
| `3389`                          | Honeypot (RDP lure)       |
| `5900`                          | Honeypot (VNC lure)       |
| `8080`                          | Honeypot (HTTP-alt lure)  |
| `8000`                          | Dashboard                 |

> **Tip:** You can optionally restrict the `49222` rule's Source CIDR to your own home IP for tighter security.

---

## Step 4 — SSH into the VM

```bash
# Fix key permissions (macOS/Linux)
chmod 400 /path/to/your-key.key

# Connect
ssh -i /path/to/your-key.key ubuntu@<YOUR_PUBLIC_IP>
```

---

## Step 5 — Run the setup script

```bash
# Upload setup_vps.sh to the VM (run this from your Mac, not the VM)
scp -i /path/to/your-key.key -P 22 \
  "/path/to/attack-map/setup_vps.sh" \
  ubuntu@<YOUR_PUBLIC_IP>:~/setup_vps.sh

# Back on the VM:
chmod +x ~/setup_vps.sh
bash ~/setup_vps.sh
```

The script will:
- Move SSH to port 49222 (it will pause and ask you to verify the new port works)
- Open all ports in the host iptables firewall and persist them
- Install Python, clone the repo, and set up the virtualenv
- Optionally write AbuseIPDB / GreyNoise keys
- Install and start two systemd services (sensor + dashboard)

**When it finishes** it prints your dashboard URL: `http://<YOUR_IP>:8000`

---

## Step 6 — Push your code to GitHub first (so the script can clone it)

Before running the script, push your local project to GitHub:

```bash
cd "/path/to/attack-map/attack-map"
git remote add origin https://github.com/YOUR_USERNAME/attack-map.git
git push -u origin main
```

Then edit line ~35 of `setup_vps.sh` and replace `YOUR_USERNAME` with your actual GitHub username.

---

## Troubleshooting

**"Connection refused" on SSH after moving the port**
- Make sure port 49222 is open in *both* the OCI Security List (Step 3) and iptables (done by the script).
- Run `sudo iptables -L INPUT --line-numbers` and confirm your ACCEPT rules appear **above** the `REJECT` line.

**Dashboard loads but map is empty**
- Give it a few minutes on a fresh public IP — bots find you fast.
- Hit **SIMULATE** for instant test arcs.
- Check that `events.jsonl` is growing: `sudo journalctl -fu threatscope-sensor`

**`sudo journalctl -fu threatscope-dashboard` shows import errors**
- Make sure you ran `pip install -r requirements.txt` inside the virtualenv.
- The dashboard expects `static/index.html` — this is already in place after the fix applied to your local repo.
