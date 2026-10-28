# Jitter SSH Premium

**Versión 0.1 experimental — no reemplazar todavía un VPS en producción.**

Repositorio independiente de la tienda y del panel. Incluye SSH para túneles, SSH sobre TLS con stunnel y WireGuard. Menú en español, agente HTTPS autenticado, cuentas SSH con vencimiento, límites de conexiones, renovaciones, suspensión, eliminación, auditoría local y backup consistente de SQLite. Contraseñas y configuraciones de peers cifradas en reposo.

## Estado real

Pruebas de lógica y contrato HTTP con comandos Linux simulados. **Aún no validado en una VM Debian/Ubuntu ni contra la tienda en producción.** El instalador no se ejecutó en el VPS actual. No es una promesa de ausencia de vulnerabilidades.

- No incluye WebSocket, V2Ray/Xray, UDP custom ni un proxy HTTP de payloads. La tienda existente tiene funciones V2Ray: `/v2/*` devuelve 501 explícitamente y esas opciones no deben ofrecerse con este agente.
- La prueba gratuita tiene dos días y una conexión; una identidad no puede volver a reclamarla. Son valores iniciales configurables, no cambios a tus planes actuales.
- WireGuard se gestiona desde el menú: peers independientes, sin vencimiento automático ni entrega desde la tienda en esta versión.
- Los límites SSH se revisan cada 15 segundos; puede haber exceso temporal. Se cuentan procesos de túneles OpenSSH. Validar en la versión concreta de OpenSSH antes de vender límites estrictos.
- Sólo túneles SSH (`ssh -N -D ...` o cliente compatible), sin terminal/shell/SFTP para clientes. No modifica el SSH administrativo.
- Backup guarda la base, no la clave de cifrado ni usuarios Linux: no es restauración de servidor completo.

## Instalación revisable

Objetivo: Debian 12/13, Ubuntu 22.04/24.04 con systemd y acceso root. Estos sistemas son objetivos de soporte **pendientes de pruebas reales**. Usa un VPS de prueba limpio. No pegues contraseñas ni tokens en GitHub.

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
5. Permite TCP **2222** (SSH), **4443** (SSH TLS), **9443** (agente HTTPS) y UDP **51821** (WireGuard) en el firewall de tu proveedor/servidor. No desactives el firewall. Restricción por IP para 9443 cuando el origen de la tienda lo permita. Usa el dominio, no una IP sin certificado coincidente.
6. Ejecuta `sudo jitter`.

Preflight verifica puertos libres, subnet de WireGuard, dominio/certificado y clave coincidente. Se niega a sobrescribir instalación existente. Si falla tras instalar paquetes, revierte servicios/archivos propios; conserva paquetes y datos. La instalación de openssh-server puede activar el servicio estándar si no existía: requiere VM de prueba, no ejecutar a ciegas en producción.

## Conectar al panel y tienda

Después de validar HTTPS y operaciones reales, agrega **otro VPS**, sin sustituir el actual:

- URL agente: `https://TU-DOMINIO:9443`.
- Token agente: campo `agent_token` de `/etc/jitter-premium/config.json`, léelo únicamente en tu sesión administrativa y pégalo en el panel. Nunca lo envíes a clientes ni al chat.
- Puerto SSH de cliente: 2222; TLS: 4443.

Compatibilidad contractual: `x-agent-token`, `GET /status`, `GET /account` con `x-jx-device`, `POST /create` con `{device, username}` o `{device, paid:true, days, max_login, ref}`. Sólo la tienda autenticada y que ya verificó el pago debe usar `paid`; el agente confía en ese token, no verifica pagos. Cada referencia pagada se entrega una vez y devuelve la misma cuenta en los reintentos mientras esté vigente. Tras expiración/eliminación devuelve 409, no renueva ni entrega otra cuenta. No comparte token con clientes.

Nombres nuevos llevan `jx` seguido de 3–20 caracteres minúsculos, dígitos o guion bajo. La tienda puede mandar nombre vacío para generar uno. Esta restricción puede necesitar un ajuste de validación en la tienda; no se modificó su código en esta entrega.

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

`create` y `wg-add` muestran credenciales: no redirigir a logs compartidos. Una cuenta suspendida no se reactiva por renovación. No hay operación de reactivación de suspendidos en 0.1; requiere decisión administrativa explícita futura. Copia protegida de `/var/lib/jitter-premium/encryption.key` imprescindible para descifrar backups. Protege también configuración, claves TLS y WireGuard. El proceso HTTP requiere root para crear usuarios; el sandbox de systemd no elimina ese privilegio. Mantén actualizaciones y exposición mínima del agente.

## Verificación previa a producción

- Instalar en VM descartable y revisar todos los servicios con `systemctl status`.
- Crear cuenta y comprobar un túnel real por 2222 y 4443, bloqueo de shell, vencimiento y dos conexiones simultáneas.
- Crear peer WireGuard, comprobar internet, aislamiento deseado, reinicio y eliminación.
- Validar desde la tienda un pago de prueba, entrega y lectura posterior sin exponer tokens en el navegador.
- Probar renovación del certificado y reiniciar ambos servicios TLS.
- No migrar cuentas existentes: el script nunca adopta ni modifica usuarios ajenos.

## Tests sin privilegios

```bash
python3 -m pip install cryptography  # sólo en entorno de pruebas aislado
python3 -m unittest discover -s tests -v
bash -n install.sh menu.sh
```

Pruebas no ejecutan useradd, firewall, wg ni servicios. No sustituyen las verificaciones VM anteriores.
