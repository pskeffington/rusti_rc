#!/bin/sh
# G2f read-only, offline OS/ABI capability inventory.
# Never opens a network socket, secret store, TPM, serial number or interface.
# No root is required. Output is compatibility *evidence*, never approval.
set -eu

safe_token() {
    printf '%s' "$1" | LC_ALL=C tr -cd 'A-Za-z0-9._-'
}

bool_node() {
    if [ -c "$1" ]; then printf 'present'; else printf 'absent'; fi
}

arch="$(safe_token "$(uname -m 2>/dev/null || printf unknown)")"
kernel="$(safe_token "$(uname -s 2>/dev/null || printf unknown)")"
kernel_release="$(safe_token "$(uname -r 2>/dev/null || printf unknown)")"
os_id=unknown
if [ -r /etc/os-release ]; then
    candidate="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
    os_id="$(safe_token "$candidate")"
fi
if [ -z "$os_id" ]; then os_id=unknown; fi

libc=unknown
if command -v getconf >/dev/null 2>&1; then
    candidate="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
    if [ -n "$candidate" ]; then libc="$(safe_token "$candidate")"; fi
fi

systemd_version=unknown
if command -v systemd >/dev/null 2>&1; then
    candidate="$(systemd --version 2>/dev/null | sed -n '1s/^systemd \([0-9][0-9]*\).*$/\1/p')"
    if [ -n "$candidate" ]; then systemd_version="$(safe_token "$candidate")"; fi
fi

has_tpm_tool=absent
if command -v tpm2_getcap >/dev/null 2>&1; then has_tpm_tool=present; fi

uefi_vars=absent
if [ -d /sys/firmware/efi/efivars ]; then uefi_vars=present; fi

# Deliberately never execute tpm2_getcap or read TPM public properties:
# a device node is not proof of a usable, trusted, provisioned TPM.
printf 'probe=g2f-legacy-offline-v1\n'
printf 'network_activity=none\n'
printf 'kernel_family=%s\n' "$kernel"
printf 'kernel_release=%s\n' "$kernel_release"
printf 'cpu_arch=%s\n' "$arch"
printf 'os_family=%s\n' "$os_id"
printf 'libc_hint=%s\n' "$libc"
printf 'systemd_version=%s\n' "$systemd_version"
printf 'tpmrm_node=%s\n' "$(bool_node /dev/tpmrm0)"
printf 'tpm_node=%s\n' "$(bool_node /dev/tpm0)"
printf 'tpm2_userspace_tool=%s\n' "$has_tpm_tool"
printf 'efi_variable_directory=%s\n' "$uefi_vars"
printf 'rtc_node=%s\n' "$(bool_node /dev/rtc0)"
printf 'credential_provider=unverified\n'
printf 'hardware_runtime=unverified\n'
printf 'signature_chain=unverified\n'
printf 'field_deployment=blocked\n'
