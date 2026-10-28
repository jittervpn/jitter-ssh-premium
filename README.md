# Jitter SSH Premium

**Versión 0.1 experimental — no reemplazar todavía un VPS en producción.**

Script independiente para administrar cuentas y túneles desde un menú en el VPS, sin depender de una web. Incluye SSH para túneles, SSH sobre TLS con stunnel y WireGuard. Menú en español, agente HTTPS autenticado, cuentas SSH con vencimiento, límites de conexiones, renovaciones, suspensión, eliminación, auditoría local y backup consistente de SQLite. Contraseñas y configuraciones de peers cifradas en reposo.

## Estado real

Pruebas de lógica y contrato HTTP con comandos Linux simulados. **Aún no validado en una VM Debian/Ubuntu con túneles reales.** El instalador no se ejecutó en el VPS actual. No es una promesa de ausencia de vulnerabilidades.

- No incluye WebSocket, V2Ray/Xray, UDP custom ni un proxy HTTP de payloads. V2Ray, UDP adicional y bhttp están solicitados para la próxima ampliación; todavía no están implementados.
- La prueba gratuita tiene dos días y una conexión; una identidad no puede volver a reclamarla. Son valores iniciales configurables.
- WireGuard se gestiona desde el menú: peers independientes, sin vencimiento automático en esta versión.
- Los límites SSH se revisan cada 15 segundos; puede haber exceso temporal. Se cuentan procesos de túneles OpenSSH. Validar en la versión concreta de OpenSSH antes de vender límites estrictos.
- Sólo túneles SSH (`ssh -N -D ...` o cliente compatible), sin terminal/shell/SFTP para clientes. No modifica el SSH administrativo.
- Backup guarda la base, no la clave de cifrado ni usuarios Linux: no es restauración de servidor completo.

## Instalación revisable

Objetivo: Debian 12/13, Ubuntu 22.04/24.04 con systemd y acceso root. Estos sistemas son objetivos de soporte **pendientes de pruebas reales**. Usa un VPS de prueba limpio. No pegues contraseñas ni claves privadas en GitHub.

1. Descarga/clona este repositorio privado usando tu propia cuenta GitHub.
2. Obtén un certificado público válido para un dominio que apunta al VPS. El instalador **no** corta 80/443 ni obtiene certificados. Configura renovación externa (preferentemente desafío DNS) y tras renovar reinicia `jitter-agent` y `jitter-stunnel`.
3. Revisa el código y ejecuta primero preflight, cambiando las rutas por las reales:

```bash
sudo env JITTER_HOST=vps.tudominio.com \
  JITTER_TLS_CERT=/etc/letsencrypt/live/vps.tudominio.com/fullchain.pem \
  JITTER_TLS_KEY=/etc/letsencrypt/live/vps.tudominio.com/privkey.pem \
  bash install.sh --check
```

4. Con las mismas variables ejecuta `bash install.sh --install`.
5. Permite TCP **2222** (SSH), **4443** (SSH TLS), **9443** (agente HTTPS) y UDP **51821** (WireGuard) en el firewall de tu proveedor/servidor. No desactives el firewall. No expongas 9443 a internet para administrar desde el menú local; si habilitas administración remota, restringe su acceso por IP. Usa el dominio, no una IP sin certificado coincidente.
6. Ejecuta `sudo jitter`.

Preflight verifica puertos libres, subnet de WireGuard, dominio/certificado y clave coincidente. Se niega a sobrescribir instalación existente. Si falla tras instalar paquetes, revierte servicios/archivos propios; conserva paquetes y datos. La instalación de openssh-server puede activar el servicio estándar si no existía: requiere VM de prueba, no ejecutar a ciegas en producción.

## Administración

```bash
sudo jitter status
sudo jitter list
sudo jitter create jxcliente --device ID-CLIENTE --days 30 --limit 2
sudo jitter renew jxcliente --days 30
sudo jitter suspend jxcliente
sudo jitter delete jxcliente
sudo jitter wg-add cliente
sudo jitter wg-delete cliente
sudo jitter backup
```

`create` y `wg-add` muestran credenciales: no redirigir a logs compartidos. Una cuenta suspendida no se reactiva por renovación. No hay operación de reactivación de suspendidos en 0.1; requiere decisión administrativa explícita futura. Copia protegida de `/var/lib/jitter-premium/encryption.key` imprescindible para descifrar backups. Protege también configuración, claves TLS y WireGuard. El proceso HTTP requiere root para crear usuarios; el sandbox de systemd no elimina ese privilegio. Mantén actualizaciones y evita exponer servicios administrativos a internet.

## Verificación previa a producción

- Instalar en VM descartable y revisar todos los servicios con `systemctl status`.
- Crear cuenta y comprobar un túnel real por 2222 y 4443, bloqueo de shell, vencimiento y dos conexiones simultáneas.
- Crear peer WireGuard, comprobar internet, aislamiento deseado, reinicio y eliminación.
- Probar renovación del certificado y reiniciar ambos servicios TLS.
- No migrar cuentas existentes: el script nunca adopta ni modifica usuarios ajenos.

## Tests sin privilegios

```bash
python3 -m pip install cryptography  # sólo en entorno de pruebas aislado
python3 -m unittest discover -s tests -v
bash -n install.sh menu.sh
```

Pruebas no ejecutan useradd, firewall, wg ni servicios. No sustituyen las verificaciones VM anteriores.
