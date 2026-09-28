# services.helios: the Helios binary cache server, optionally behind nginx
# with ACME TLS. NAR downloads go through nginx's sendfile via
# X-Accel-Redirect after the server has checked access.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.helios;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    optional
    optionalString
    types
    ;

  dataDir = cfg.dataDir;
  defaultDataDir = "/var/lib/helios";
  secret = name: file: optional (file != null) "${name}:${file}";

  # The maintenance socket lives in a setgid directory, so it belongs to
  # group helios-admin: the daemon can reach it, nginx (group helios) cannot.
  adminDir = "/run/helios-admin";
  adminSocket = "${adminDir}/admin.sock";

  daemonArgs = lib.cli.toCommandLineShellGNU { } (
    {
      socket = adminSocket;
      data-dir = dataDir;
      gc-interval = cfg.daemon.gcInterval;
      scrub-interval = if cfg.daemon.scrub.interval == null then "0" else cfg.daemon.scrub.interval;
      scrub-rate = cfg.daemon.scrub.rate;
      checkpoint-interval = cfg.daemon.checkpointInterval;
      optimize-interval = cfg.daemon.optimizeInterval;
      backup-interval = if cfg.daemon.backup.interval == null then "0" else cfg.daemon.backup.interval;
      backup-keep = cfg.daemon.backup.keep;
      quota-high = cfg.daemon.quotaHigh;
      quota-low = cfg.daemon.quotaLow;
    }
    // lib.optionalAttrs (cfg.daemon.quota != null) { quota = cfg.daemon.quota; }
    // lib.optionalAttrs (cfg.daemon.minFree != null) { min-free = cfg.daemon.minFree; }
    // lib.optionalAttrs (cfg.daemon.metrics.listen != null) { metrics-listen = cfg.daemon.metrics.listen; }
  );

  watchSpool = "/var/lib/helios-watch-store/spool";
  # Runs as root inside the nix-daemon after every build; a failing
  # post-build hook fails the build, so queueing problems are only logged.
  queueHook = pkgs.writeShellScript "helios-queue-paths" ''
    ${cfg.package}/bin/helios queue-paths --spool ${watchSpool} \
      || echo "helios: could not queue $OUT_PATHS for pushing" >&2
    exit 0
  '';

  hardening = {
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [ "@system-service" "~@privileged" ];
  };
  credential = flag: name: file: optionalString (file != null) " ${flag} %d/${name}";
in
{
  options.services.helios = {
    enable = mkEnableOption "the Helios Nix binary cache";

    package = mkOption {
      type = types.package;
      description = "Package providing `helios-server`.";
    };

    dataDir = mkOption {
      type = types.str;
      default = defaultDataDir;
      description = ''
        Where the database and NARs live. The default is managed by systemd
        (StateDirectory); another path, such as a mounted data disk, is
        created with the right ownership and made writable in the sandbox.
      '';
    };

    listen = mkOption {
      type = types.str;
      default = "127.0.0.1:8080";
      description = "Address the server listens on. Keep it on loopback when nginx is enabled.";
    };

    signingKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Nix secret key (`nix key generate-secret`) used to sign narinfo. Read by
        systemd as a credential, so it may be root-only (for example an agenix
        secret). Without it narinfo is unsigned.
      '';
    };

    jwtSecretFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "HMAC secret for API tokens (at least 16 bytes). Without it no tokens can be issued or used.";
    };

    adminSecretFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Bearer secret for the admin API (at least 16 bytes). Without it the admin API is disabled.";
    };

    logLevel = mkOption {
      type = types.enum [ "error" "warn" "info" "debug" ];
      default = "info";
    };

    settings = {
      narinfoCacheEntries = mkOption {
        type = types.ints.positive;
        default = 262144;
        description = "Rendered narinfo bodies kept in memory.";
      };
      maxUploadBytes = mkOption {
        type = types.ints.positive;
        default = 64 * 1024 * 1024 * 1024;
        description = "Largest accepted compressed NAR.";
      };
      gcIntervalHours = mkOption {
        type = types.ints.positive;
        default = 6;
      };
      auditRetentionDays = mkOption {
        type = types.ints.unsigned;
        default = 30;
      };
    };

    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "cache.example.com";
      description = "Public host name. When set, nginx serves the cache on it.";
    };

    nginx = {
      enable = mkOption {
        type = types.bool;
        default = cfg.domain != null;
        defaultText = lib.literalExpression "config.services.helios.domain != null";
        description = "Put nginx in front of the server (TLS, HTTP/2, zero-copy NAR downloads).";
      };
      acme = mkOption {
        type = types.bool;
        default = true;
        description = "Obtain a certificate for `domain` from Let's Encrypt. Requires `security.acme` terms and email.";
      };
    };

    openFirewall = mkOption {
      type = types.bool;
      default = cfg.nginx.enable;
      defaultText = lib.literalExpression "config.services.helios.nginx.enable";
      description = "Open TCP 80 and 443.";
    };

    daemon = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Run helios-daemon beside the server: WAL checkpoints, database
          backups and an integrity scrub, plus auto-GC once a quota is set.
        '';
      };
      quota = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "500G";
        description = "Keep stored NARs under this size by evicting least-recently-used paths. Null disables auto-GC by size.";
      };
      quotaHigh = mkOption {
        type = types.float;
        default = 0.9;
        description = "Start evicting above this fraction of the quota.";
      };
      quotaLow = mkOption {
        type = types.float;
        default = 0.8;
        description = "Evict down to this fraction of the quota.";
      };
      minFree = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "20G";
        description = "Also evict while the data filesystem has less free space than this.";
      };
      gcInterval = mkOption {
        type = types.str;
        default = "5m";
      };
      scrub = {
        interval = mkOption {
          type = types.nullOr types.str;
          default = "7d";
          description = "Time between full integrity scrubs; null disables.";
        };
        rate = mkOption {
          type = types.str;
          default = "64M";
          description = "Scrub read rate per second; \"0\" is unlimited.";
        };
      };
      checkpointInterval = mkOption {
        type = types.str;
        default = "15m";
      };
      optimizeInterval = mkOption {
        type = types.str;
        default = "1d";
      };
      backup = {
        interval = mkOption {
          type = types.nullOr types.str;
          default = "1d";
          description = "Time between database backups (to <dataDir>/backups); null disables.";
        };
        keep = mkOption {
          type = types.ints.positive;
          default = 7;
        };
      };
      metrics.listen = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "127.0.0.1:9120";
        description = "Serve Prometheus metrics on this address.";
      };
    };

    watchStore = {
      enable = mkEnableOption "pushing every locally built path to a Helios cache (post-build hook)";
      url = mkOption {
        type = types.str;
        example = "https://cache.example.com";
        description = "Helios server to push to.";
      };
      cache = mkOption {
        type = types.str;
        example = "main";
      };
      tokenFile = mkOption {
        type = types.path;
        description = "File holding a push token for `cache`; read as a systemd credential.";
      };
      jobs = mkOption {
        type = types.ints.positive;
        default = 8;
        description = "Parallel uploads.";
      };
    };
  };

  config = lib.mkMerge [
  (mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.nginx.enable -> cfg.domain != null;
        message = "services.helios.nginx.enable requires services.helios.domain";
      }
    ];

    users.users.helios = {
      isSystemUser = true;
      group = "helios";
      home = dataDir;
    };
    users.groups.helios = { };

    systemd.services.helios = {
      description = "Helios Nix binary cache";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = {
        HELIOS_LOG = cfg.logLevel;
        HELIOS_LISTEN = cfg.listen;
        HELIOS_DATA_DIR = dataDir;
        HELIOS_NARINFO_CACHE_ENTRIES = toString cfg.settings.narinfoCacheEntries;
        HELIOS_MAX_UPLOAD_BYTES = toString cfg.settings.maxUploadBytes;
        HELIOS_GC_INTERVAL_HOURS = toString cfg.settings.gcIntervalHours;
        HELIOS_AUDIT_RETENTION_DAYS = toString cfg.settings.auditRetentionDays;
      }
      // lib.optionalAttrs cfg.daemon.enable {
        HELIOS_ADMIN_SOCKET = adminSocket;
      }
      // lib.optionalAttrs cfg.nginx.enable {
        HELIOS_ACCEL_REDIRECT = "/_nar";
        HELIOS_TRUST_PROXY = "true";
      };

      serviceConfig = {
        ExecStart =
          "${cfg.package}/bin/helios-server"
          + credential "--signing-key-file" "signing-key" cfg.signingKeyFile
          + credential "--jwt-secret-file" "jwt-secret" cfg.jwtSecretFile
          + credential "--admin-secret-file" "admin-secret" cfg.adminSecretFile;
        LoadCredential =
          secret "signing-key" cfg.signingKeyFile
          ++ secret "jwt-secret" cfg.jwtSecretFile
          ++ secret "admin-secret" cfg.adminSecretFile;

        User = "helios";
        Group = "helios";
        # nginx (in group helios) reads NARs for X-Accel-Redirect.
        StateDirectory = mkIf (dataDir == defaultDataDir) "helios";
        StateDirectoryMode = "0750";
        ReadWritePaths = optional (dataDir != defaultDataDir) dataDir ++ optional cfg.daemon.enable adminDir;
        UMask = "0027";
        Restart = "on-failure";
        RestartSec = 2;
        LimitNOFILE = 65536;

        # The server only needs its state directory and the network.
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      }
      // hardening;
    };

    systemd.tmpfiles.rules = mkIf (dataDir != defaultDataDir) [ "d '${dataDir}' 0750 helios helios -" ];

    users.users.nginx.extraGroups = mkIf cfg.nginx.enable [ "helios" ];

    services.nginx = mkIf cfg.nginx.enable {
      enable = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      recommendedOptimisation = true;
      virtualHosts.${cfg.domain} = {
        enableACME = cfg.nginx.acme;
        forceSSL = cfg.nginx.acme;
        locations."/" = {
          proxyPass = "http://${cfg.listen}";
          extraConfig = ''
            # Stream uploads straight to the server instead of spooling them.
            proxy_request_buffering off;
            client_max_body_size 0;
            proxy_read_timeout 1h;
            proxy_send_timeout 1h;
          '';
        };
        locations."/_nar/" = {
          alias = "${dataDir}/nar/";
          extraConfig = ''
            internal;
          '';
        };
      };
    };

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ 80 443 ];
  })

  (mkIf (cfg.enable && cfg.daemon.enable) {
    users.users.helios-daemon = {
      isSystemUser = true;
      group = "helios-admin";
      # Reads NARs for the scrub.
      extraGroups = [ "helios" ];
    };
    users.groups.helios-admin = { };

    systemd.tmpfiles.rules = [ "d ${adminDir} 2750 helios helios-admin -" ];

    systemd.services.helios-daemon = {
      description = "Helios cache maintenance";
      wantedBy = [ "multi-user.target" ];
      after = [ "helios.service" ];
      wants = [ "helios.service" ];
      environment.HELIOS_LOG = cfg.logLevel;
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/helios-daemon ${daemonArgs}";
        User = "helios-daemon";
        Group = "helios-admin";
        SupplementaryGroups = [ "helios" ];
        Restart = "on-failure";
        RestartSec = 5;
        # Maintenance must not compete with serving.
        Nice = 10;
        CPUSchedulingPolicy = "batch";
        IOSchedulingClass = "idle";
        # Reaches the server over its Unix socket; the network only for metrics.
        PrivateNetwork = cfg.daemon.metrics.listen == null;
        RestrictAddressFamilies = [ "AF_UNIX" ] ++ lib.optionals (cfg.daemon.metrics.listen != null) [ "AF_INET" "AF_INET6" ];
      }
      // hardening;
    };
  })

  (mkIf cfg.watchStore.enable {
    users.users.helios-watch-store = {
      isSystemUser = true;
      group = "helios-watch-store";
      home = "/var/lib/helios-watch-store";
    };
    users.groups.helios-watch-store = { };

    nix.settings.post-build-hook = queueHook;
    systemd.tmpfiles.rules = [ "d ${watchSpool} 0750 helios-watch-store helios-watch-store -" ];

    systemd.services.helios-watch-store = {
      description = "Push locally built paths to ${cfg.watchStore.url}";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "nix-daemon.socket" ];
      wants = [ "network-online.target" ];
      path = [ config.nix.package ];
      environment = {
        HELIOS_URL = cfg.watchStore.url;
        HOME = "/var/lib/helios-watch-store";
      };
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/helios --token-file %d/token watch-store ${lib.escapeShellArg cfg.watchStore.cache} --spool ${watchSpool} --jobs ${toString cfg.watchStore.jobs}";
        LoadCredential = [ "token:${cfg.watchStore.tokenFile}" ];
        User = "helios-watch-store";
        Group = "helios-watch-store";
        StateDirectory = "helios-watch-store";
        StateDirectoryMode = "0750";
        Restart = "always";
        RestartSec = 5;
        Nice = 10;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      }
      // hardening;
    };
  })
  ];
}
