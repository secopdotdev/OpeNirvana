#!/usr/bin/env bash
# Install custom Wazuh decoders/rules into the host-level Wazuh Agent.
# Idempotent: safe to re-run; copies files and reloads agent only if they changed.
set -euo pipefail

SRC_DIR=/dock/conf/wazuh
AGENT_ETC=/var/ossec/etc
OSSEC_CONF="$AGENT_ETC/ossec.conf"

WAZUH_CONTROL=/var/ossec/bin/wazuh-control
if ! [ -x "$WAZUH_CONTROL" ]; then
    echo "$WAZUH_CONTROL not found. Install wazuh-agent first." >&2
    exit 1
fi

changed=0

# Copy decoders
if ! diff -r "$SRC_DIR/decoders" "$AGENT_ETC/decoders" >/dev/null 2>&1; then
    install -d "$AGENT_ETC/decoders"
    cp -r "$SRC_DIR/decoders/"*.xml "$AGENT_ETC/decoders/"
    chown -R root:wazuh "$AGENT_ETC/decoders"
    chmod 640 "$AGENT_ETC/decoders/"*.xml
    changed=1
fi

# Copy rules
if ! diff -r "$SRC_DIR/rules" "$AGENT_ETC/rules" >/dev/null 2>&1; then
    install -d "$AGENT_ETC/rules"
    cp -r "$SRC_DIR/rules/"*.xml "$AGENT_ETC/rules/"
    chown -R root:wazuh "$AGENT_ETC/rules"
    chmod 640 "$AGENT_ETC/rules/"*.xml
    changed=1
fi

# Merge agent-host.conf into ossec.conf (splice inner XML before </ossec_config>).
if ! grep -q "unified-stack localfiles" "$OSSEC_CONF" 2>/dev/null; then
    inner=$(sed -n '/<ossec_config>/,/<\/ossec_config>/{/<ossec_config>/d;/<\/ossec_config>/d;p;}' "$SRC_DIR/agent-host.conf")
    {
        awk '/<\/ossec_config>/{exit}1' "$OSSEC_CONF"
        echo "<!-- BEGIN unified-stack localfiles -->"
        printf '%s\n' "$inner"
        echo "<!-- END unified-stack localfiles -->"
        echo "</ossec_config>"
    } > "$OSSEC_CONF.new"
    mv "$OSSEC_CONF.new" "$OSSEC_CONF"
    chown root:wazuh "$OSSEC_CONF"
    chmod 640 "$OSSEC_CONF"
    changed=1
fi

if [ "$changed" -eq 1 ]; then
    systemctl restart wazuh-agent
    echo "wazuh-agent restarted with updated decoders/rules/localfiles"
else
    echo "no wazuh-agent changes"
fi
