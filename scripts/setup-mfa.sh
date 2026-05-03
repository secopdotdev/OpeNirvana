#!/usr/bin/env bash
# setup-mfa.sh — interactive TOTP + SSH key hardening for the docker host.
# Run as root after docker-host-config.sh has bootstrapped the host.
# Not idempotent by design: google-authenticator is interactive and one-shot.
set -euo pipefail

c_red()  { printf "\033[31m%s\033[0m\n" "$*"; }
c_grn()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yel()  { printf "\033[33m%s\033[0m\n" "$*"; }
c_blu()  { printf "\033[34m%s\033[0m\n" "$*"; }
step()   { printf "\n\033[36m==> %s\033[0m\n" "$*"; }

SSHD_CFG=/etc/ssh/sshd_config
PAM_SSHD=/etc/pam.d/sshd
TARGET_USER=${SUDO_USER:-rooter}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

require_root() {
    if [ "$EUID" -ne 0 ]; then
        c_red "Run as root: sudo $0"
        exit 1
    fi
}

sshd_set() {
    local key="$1" val="$2"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$SSHD_CFG"; then
        sed -i -E "s|^#?[[:space:]]*(${key})[[:space:]].*|\1 ${val}|" "$SSHD_CFG"
    else
        echo "${key} ${val}" >> "$SSHD_CFG"
    fi
}

install_google_authenticator() {
    step "Installing libpam-google-authenticator..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq libpam-google-authenticator
    c_grn "Installed."
}

run_google_authenticator() {
    step "Running google-authenticator for ${TARGET_USER}..."
    echo
    c_blu "You will be asked several questions. Scan the QR code with your TOTP app."
    c_blu "Answer 'y' to update ~/.google_authenticator to proceed with SSH hardening."
    echo
    sudo -u "$TARGET_USER" google-authenticator
}

generate_ssh_key() {
    local key_path="${TARGET_HOME}/.ssh/id_ed25519"
    step "Generating ed25519 SSH key for ${TARGET_USER}..."
    install -d -o "$TARGET_USER" -m 700 "${TARGET_HOME}/.ssh"
    if [ -f "$key_path" ]; then
        c_yel "Key already exists at ${key_path} — skipping generation."
    else
        sudo -u "$TARGET_USER" ssh-keygen -t ed25519 -f "$key_path" -N ""
        c_grn "Key generated."
    fi
    echo
    c_blu "=== Public key — add to ~/.ssh/authorized_keys on any client that should connect ==="
    cat "${key_path}.pub"
    echo
}

harden_ssh_password_auth() {
    step "Hardening SSH: disabling password authentication..."

    # Disable password auth
    sshd_set PasswordAuthentication no

    # Enable keyboard-interactive (required for PAM TOTP challenge)
    sshd_set KbdInteractiveAuthentication yes

    # Add PAM google-authenticator module if not already present
    if grep -q 'pam_google_authenticator.so' "$PAM_SSHD"; then
        c_grn "pam_google_authenticator.so already in ${PAM_SSHD}"
    else
        echo 'auth required pam_google_authenticator.so' >> "$PAM_SSHD"
        c_grn "Added pam_google_authenticator.so to ${PAM_SSHD}"
    fi

    # Validate config before restarting
    if ! sshd -t -f "$SSHD_CFG"; then
        c_red "sshd_config validation failed — NOT restarting. Fix ${SSHD_CFG} manually."
        return 1
    fi

    systemctl daemon-reload
    systemctl restart ssh.socket
    c_grn "SSH restarted. Password authentication is now disabled."
    c_yel "IMPORTANT: Keep this session open and verify key+TOTP login works in a new terminal before closing."
}

wall_of_shame_warning() {
    echo
    c_red "╔══════════════════════════════════════════════════════════════════╗"
    c_red "║                     ⚠  SECURITY WARNING  ⚠                      ║"
    c_red "╠══════════════════════════════════════════════════════════════════╣"
    c_red "║  Password authentication remains enabled on this host.           ║"
    c_red "║  This makes it susceptible to brute-force and credential-        ║"
    c_red "║  stuffing attacks.                                                ║"
    c_red "║                                                                   ║"
    c_red "║  Hosts that retain password auth will be listed on the           ║"
    c_red "║  Wall of Shame: https://github.com/secopdev/wall-of-shame        ║"
    c_red "║                                                                   ║"
    c_red "║  Re-run this script when you are ready to disable it.            ║"
    c_red "╚══════════════════════════════════════════════════════════════════╝"
    echo
}

main() {
    require_root

    install_google_authenticator
    run_google_authenticator

    # Check if the user completed TOTP setup
    if [ ! -f "${TARGET_HOME}/.google_authenticator" ]; then
        c_red "${TARGET_HOME}/.google_authenticator not found — TOTP setup was not completed."
        wall_of_shame_warning
        exit 1
    fi

    c_grn "TOTP setup complete."
    echo

    # Ask about SSH key generation
    read -r -p "Generate SSH key for ${TARGET_USER} and display public key? (y/n): " gen_key
    if [[ "$gen_key" =~ ^[Yy]$ ]]; then
        generate_ssh_key

        # Ask about disabling password auth
        read -r -p "Disable password authentication (key + TOTP only)? (y/n): " disable_pass
        if [[ "$disable_pass" =~ ^[Yy]$ ]]; then
            harden_ssh_password_auth
        else
            wall_of_shame_warning
        fi
    else
        wall_of_shame_warning
    fi
}

main "$@"
