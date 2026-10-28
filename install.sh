#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID == 0 ]] || { echo 'Ejecutar con sudo.'; exit 1; }
source /etc/os-release
case "$ID:$VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;; *) echo 'Solo Debian 12/13 o Ubuntu 22.04/24.04.'; exit 1;; esac
[[ ${1:-} == --check || ${1:-} == --install ]] || { echo 'Uso: sudo bash install.sh --check | --install'; exit 1; }
: "${JITTER_HOST:?Define JITTER_HOST con el dominio certificado}"
: "${JITTER_TLS_CERT:?Define JITTER_TLS_CERT con la ruta del certificado PEM}"
: "${JITTER_TLS_KEY:?Define JITTER_TLS_KEY con la ruta de su clave privada}"
[[ $JITTER_HOST =~ ^[a-zA-Z0-9.-]+$ && $JITTER_HOST != -* ]] || exit 1
for file in "$JITTER_TLS_CERT" "$JITTER_TLS_KEY"; do
  [[ $file =~ ^/[a-zA-Z0-9_./-]+$ && -r $file ]] || { echo 'Ruta de certificado inválida.'; exit 1; }
done
[[ ! -e /etc/jitter-premium && ! -e /etc/wireguard/jxwg0.conf ]] || { echo 'Instalación existente; no se sobrescribe.'; exit 1; }
command -v systemctl >/dev/null
command -v ss >/dev/null
command -v openssl >/dev/null
openssl x509 -in "$JITTER_TLS_CERT" -noout -checkend 604800 >/dev/null
openssl x509 -in "$JITTER_TLS_CERT" -noout -checkhost "$JITTER_HOST" >/dev/null
certkey=$(openssl x509 -in "$JITTER_TLS_CERT" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
privkey=$(openssl pkey -in "$JITTER_TLS_KEY" -pubout -outform DER | sha256sum)
[[ $certkey == "$privkey" ]] || { echo 'Certificado y clave no coinciden.'; exit 1; }
for port in 2222 4443 9443; do
  [[ -z $(ss -H -ltn "sport = :$port") ]] || { echo "Puerto TCP $port ocupado; nada modificado."; exit 1; }
done
[[ -z $(ss -H -lun 'sport = :51821') ]] || { echo 'Puerto WireGuard ocupado.'; exit 1; }
python3 - <<'PY'
import ipaddress,json,subprocess
subnet=ipaddress.ip_network('10.77.0.0/24')
for route in json.loads(subprocess.check_output(['ip','-j','route','show','table','all'])):
    dst=route.get('dst','default')
    if dst != 'default' and ':' not in dst and subnet.overlaps(ipaddress.ip_network(dst,strict=False)):
        raise SystemExit('Subred 10.77.0.0/24 ocupada; nada modificado.')
PY
iface=$(ip -j route get 1.1.1.1 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["dev"])')
[[ $iface =~ ^[a-zA-Z0-9_.:-]+$ ]] || exit 1
echo 'Preflight OK. SSH administrativo y puertos 80/443 no se modificarán.'
[[ $1 == --install ]] || exit 0
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openssh-server stunnel4 wireguard-tools python3-cryptography iptables
old_forward=$(sysctl -n net.ipv4.ip_forward)
rollback() {
  echo 'Instalación fallida; revirtiendo solo servicios y archivos Jitter.' >&2
  systemctl disable --now jitter-maintain.timer jitter-agent jitter-stunnel jitter-sshd wg-quick@jxwg0 2>/dev/null || true
  rm -f /etc/systemd/system/jitter-{agent,sshd,stunnel,maintain}.{service,timer}
  rm -f /etc/wireguard/jxwg0.conf /etc/sysctl.d/90-jitter-wireguard.conf /usr/local/sbin/jitter
  rm -rf /etc/jitter-premium /opt/jitter-premium
  sysctl -w "net.ipv4.ip_forward=$old_forward" >/dev/null || true
  systemctl daemon-reload || true
  echo 'Paquetes y datos se conservan; SSH administrativo no fue modificado.' >&2
}
trap rollback ERR
# No broad firewall changes: provider firewall/UFW must explicitly allow new ports.
install -d -m 700 /etc/jitter-premium /var/lib/jitter-premium /opt/jitter-premium /etc/wireguard
install -m 700 "$HERE/jitter.py" /opt/jitter-premium/jitter.py
install -m 700 "$HERE/menu.sh" /usr/local/sbin/jitter
getent group jxclients >/dev/null || groupadd --system jxclients
ssh-keygen -q -t ed25519 -N '' -f /etc/jitter-premium/ssh_host_ed25519_key
install -d -m 755 /run/sshd
export JITTER_HOST JITTER_TLS_CERT JITTER_TLS_KEY
python3 - <<'PY'
import json,os,secrets
from pathlib import Path
cfg=dict(host=os.environ['JITTER_HOST'], tls_cert=os.environ['JITTER_TLS_CERT'],tls_key=os.environ['JITTER_TLS_KEY'], agent_token=secrets.token_urlsafe(48),bind='0.0.0.0',api_port=9443,ssh_port=2222,ssl_port=4443,wg_port=51821,wg_network='10.77.0.0/24',free_days=2,max_users=100,country='',city='',flag='')
Path('/etc/jitter-premium/config.json').write_text(json.dumps(cfg,indent=2))
PY
cat > /etc/jitter-premium/sshd_config <<'EOF'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/jitter-premium/ssh_host_ed25519_key
PidFile /run/jitter-sshd.pid
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM yes
AllowGroups jxclients
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel no
X11Forwarding no
PermitTTY no
MaxSessions 0
MaxStartups 10:30:30
LoginGraceTime 20
ClientAliveInterval 30
ClientAliveCountMax 2
EOF
/usr/sbin/sshd -t -f /etc/jitter-premium/sshd_config
cat > /etc/jitter-premium/stunnel.conf <<EOF
foreground = yes
pid =
setuid = nobody
setgid = nogroup
sslVersionMin = TLSv1.2
cert = $JITTER_TLS_CERT
key = $JITTER_TLS_KEY
[ssh]
accept = 0.0.0.0:4443
connect = 127.0.0.1:2222
EOF
private=$(wg genkey)
cat > /etc/jitter-premium/wireguard.base <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = 51821
PrivateKey = $private
PostUp = iptables -C FORWARD -i %i -o $iface -j ACCEPT || iptables -A FORWARD -i %i -o $iface -j ACCEPT; iptables -C FORWARD -i $iface -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || iptables -A FORWARD -i $iface -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -C POSTROUTING -s 10.77.0.0/24 -o $iface -j MASQUERADE || iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o $iface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o $iface -j ACCEPT; iptables -D FORWARD -i $iface -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.77.0.0/24 -o $iface -j MASQUERADE
EOF
unset private
install -m 600 /etc/jitter-premium/wireguard.base /etc/wireguard/jxwg0.conf
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-jitter-wireguard.conf
sysctl -p /etc/sysctl.d/90-jitter-wireguard.conf >/dev/null
cat > /etc/systemd/system/jitter-sshd.service <<'EOF'
[Unit]
Description=Jitter SSH tunnels (separate from administrative SSH)
After=network.target
[Service]
ExecStartPre=/usr/sbin/sshd -t -f /etc/jitter-premium/sshd_config
ExecStart=/usr/sbin/sshd -D -e -f /etc/jitter-premium/sshd_config
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/jitter-stunnel.service <<'EOF'
[Unit]
Description=Jitter SSH over TLS
After=network.target jitter-sshd.service
[Service]
ExecStart=/usr/bin/stunnel /etc/jitter-premium/stunnel.conf
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/jitter-agent.service <<'EOF'
[Unit]
Description=Jitter authenticated TLS agent
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/jitter-premium/jitter.py serve
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/jitter-maintain.service <<'EOF'
[Unit]
Description=Jitter expiry and connection limit enforcement
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/jitter-premium/jitter.py maintain
UMask=0077
EOF
cat > /etc/systemd/system/jitter-maintain.timer <<'EOF'
[Unit]
Description=Check account expiry and connection limits every 15 seconds
[Timer]
OnBootSec=15
OnUnitActiveSec=15
AccuracySec=1
[Install]
WantedBy=timers.target
EOF
chmod 600 /etc/jitter-premium/*
systemctl daemon-reload
systemctl enable --now jitter-sshd jitter-stunnel jitter-agent jitter-maintain.timer wg-quick@jxwg0
# Check each service; fail rather than report a false success.
for unit in jitter-sshd jitter-stunnel jitter-agent jitter-maintain.timer wg-quick@jxwg0; do systemctl is-active --quiet "$unit"; done
trap - ERR
echo 'Instalado. Ejecuta sudo jitter. Abre solo TCP 2222/4443/9443 y UDP 51821 en tu firewall.'
echo 'Certificados: configura renovación externa y reinicia jitter-agent y jitter-stunnel tras renovar.'
