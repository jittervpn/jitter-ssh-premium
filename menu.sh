#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Ejecutar sudo jitter'; exit 1; }
manager() { /usr/bin/python3 /opt/jitter-premium/jitter.py "$@"; }
if (($#)); then manager "$@"; exit; fi
while true; do
  printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  JITTER · PREMIUM 0.1\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  1 Estado       2 Cuentas\n  3 Crear SSH    4 Renovar\n  5 Suspender    6 Eliminar\n  7 WireGuard +  8 WireGuard −\n  9 Backup       0 Salir\n'
  read -r -p 'Opción: ' option
  case "$option" in
    1) manager status;;
    2) manager list;;
    3) read -r -p 'Nombre (prefijo jx): ' name; read -r -p 'Identidad cliente: ' device; read -r -p 'Días: ' days; read -r -p 'Conexiones: ' limit; manager create "$name" --device "$device" --days "$days" --limit "$limit" || true;;
    4) read -r -p 'Nombre: ' name; read -r -p 'Días adicionales: ' days; manager renew "$name" --days "$days" || true;;
    5) read -r -p 'Nombre: ' name; manager suspend "$name" || true;;
    6) read -r -p 'Nombre: ' name; read -r -p 'Escribe ELIMINAR para confirmar: ' confirm; [[ $confirm != ELIMINAR ]] || manager delete "$name";;
    7) read -r -p 'Nombre peer: ' name; manager wg-add "$name" || true;;
    8) read -r -p 'Nombre peer: ' name; read -r -p 'Escribe ELIMINAR: ' confirm; [[ $confirm != ELIMINAR ]] || manager wg-delete "$name";;
    9) manager backup;;
    0) exit 0;;
    *) echo 'Opción inválida';;
  esac
done
