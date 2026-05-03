# Load frameworks we use. Stock zeek ships these under policy/.
@load policy/tuning/json-logs
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssh/software
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/frameworks/files/hash-all-files

# Emit JSON instead of TSV — Wazuh decoders parse JSON.
redef LogAscii::use_json = T;

# Intel framework: read feeds dropped into /usr/local/zeek/intel/ by the
# nightly zeek-intel-refresh.sh script. Each file must be a Zeek Intel
# TSV (see https://docs.zeek.org/en/current/frameworks/intel.html).
redef Intel::read_files += {
    "/usr/local/zeek/intel/urlhaus.tsv",
    "/usr/local/zeek/intel/feodo.tsv",
    "/usr/local/zeek/intel/crowdstrike-domains.tsv",
};

# Tune noticed: promote Intel::Notice to an action-worthy event.
hook Notice::policy(n: Notice::Info) {
    if ( n$note == Intel::Notice ) {
        add n$actions[Notice::ACTION_LOG];
    }
}
