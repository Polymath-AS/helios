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
  };

  config = mkIf cfg.enable {
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
        ReadWritePaths = mkIf (dataDir != defaultDataDir) [ dataDir ];
        UMask = "0027";
        Restart = "on-failure";
        RestartSec = 2;
        LimitNOFILE = 65536;

        # Sandboxing: the server only needs its state directory and the network.
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
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
      };
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
  };
}
