# OCI image: helios-server and helios-daemon in one container, running as
# an unprivileged user, with everything persistent under /var/lib/helios.
#
#   docker load < $(nix build .#docker --print-out-paths)
#   docker run -d -p 8080:8080 -v helios:/var/lib/helios helios:<version>
#
# On first start, without HELIOS_*_FILE secrets configured, the entrypoint
# generates a signing key, token secret and admin secret into
# /var/lib/helios/secrets.
{ pkgs, helios }:

let
  uid = "10000";

  entrypoint = pkgs.writeShellApplication {
    name = "helios-entrypoint";
    runtimeInputs = [ helios pkgs.coreutils ];
    text = ''
      data="''${HELIOS_DATA_DIR:-/var/lib/helios}"
      secrets="$data/secrets"

      # docker stop: forward SIGTERM so both shut down cleanly. Installed
      # first because bash is PID 1, which ignores signals without a
      # handler, and a stop can come before either process has started.
      stopping=0
      server=
      daemon=
      # shellcheck disable=SC2329 # invoked by the trap below
      stop() {
        stopping=1
        if [[ -n "$server$daemon" ]]; then
          kill -TERM ''${server:+"$server"} ''${daemon:+"$daemon"} 2>/dev/null || true
        fi
      }
      trap stop TERM INT

      # Generate secrets on first start unless they are provided (for
      # example as Docker secrets under /run/secrets).
      if [[ -z "''${HELIOS_SIGNING_KEY_FILE:-}''${HELIOS_JWT_SECRET_FILE:-}''${HELIOS_ADMIN_SECRET_FILE:-}" ]]; then
        pubkey=$(helios-server generate-secrets --dir "$secrets" --key-name "''${HELIOS_KEY_NAME:-helios-1}")
        echo "helios: signing key $pubkey (secrets in $secrets)" >&2
        export HELIOS_SIGNING_KEY_FILE="$secrets/signing-key"
        export HELIOS_JWT_SECRET_FILE="$secrets/jwt-secret"
        export HELIOS_ADMIN_SECRET_FILE="$secrets/admin-secret"
      fi

      if [[ "''${1:-serve}" != serve ]]; then
        exec "$@"
      fi
      if (( stopping )); then
        exit 0
      fi

      export HELIOS_ADMIN_SOCKET="''${HELIOS_ADMIN_SOCKET:-/run/helios/admin.sock}"
      # A restarted container keeps the last run's socket; without this the
      # wait below would pass before the server is listening.
      rm -f "$HELIOS_ADMIN_SOCKET"
      helios-server &
      server=$!
      # The trap may have run between the fork and the assignment.
      if (( stopping )); then stop; fi
      if [[ "''${HELIOS_DAEMON:-1}" != 0 ]]; then
        for _ in {1..100}; do
          if [[ -S "$HELIOS_ADMIN_SOCKET" ]] || (( stopping )); then break; fi
          sleep 0.1
        done
        if (( ! stopping )); then
          helios-daemon --socket "$HELIOS_ADMIN_SOCKET" --data-dir "$data" --state-dir "$data/daemon" &
          daemon=$!
          if (( stopping )); then stop; fi
        fi
      fi

      # If either process exits on its own, take the other down too.
      status=0
      wait -n || status=$?
      kill -TERM "$server" ''${daemon:+"$daemon"} 2>/dev/null || true
      wait || true
      if (( stopping )); then
        exit 0
      fi
      exit $(( status == 0 ? 1 : status ))
    '';
  };

  # docker exec helpers; the image has no shell utilities of its own.
  admin = pkgs.writeShellApplication {
    name = "helios-admin";
    runtimeInputs = [ helios ];
    text = ''
      # The CLI, pointed at this container's server with the admin secret:
      #   docker exec helios helios-admin cache create main
      listen="''${HELIOS_LISTEN:-0.0.0.0:8080}"
      exec helios --url "http://127.0.0.1:''${listen##*:}" \
        --token-file "''${HELIOS_ADMIN_SECRET_FILE:-''${HELIOS_DATA_DIR:-/var/lib/helios}/secrets/admin-secret}" "$@"
    '';
  };
  publicKey = pkgs.writeShellApplication {
    name = "helios-public-key";
    runtimeInputs = [ helios ];
    text = ''
      exec helios-server --print-public-key \
        --signing-key-file "''${HELIOS_SIGNING_KEY_FILE:-''${HELIOS_DATA_DIR:-/var/lib/helios}/secrets/signing-key}"
    '';
  };

  nss = pkgs.dockerTools.fakeNss.override {
    extraPasswdLines = [ "helios:x:${uid}:${uid}:helios:/var/lib/helios:/bin/false" ];
    extraGroupLines = [ "helios:x:${uid}:" ];
  };
in
pkgs.dockerTools.buildLayeredImage {
  name = "helios";
  tag = helios.version;
  contents = [
    helios
    entrypoint
    admin
    publicKey
    pkgs.cacert
  ];
  # Copies, not store symlinks: docker exec resolves the user through
  # /etc/passwd and /etc/group and refuses absolute symlinks there.
  fakeRootCommands = ''
    mkdir -p etc var/lib/helios run/helios tmp
    cp -L ${nss}/etc/passwd ${nss}/etc/group ${nss}/etc/nsswitch.conf etc/
    chown ${uid}:${uid} var/lib/helios run/helios
    chmod 0750 var/lib/helios run/helios
    chmod 1777 tmp
  '';
  config = {
    Entrypoint = [ "${entrypoint}/bin/helios-entrypoint" ];
    Cmd = [ "serve" ];
    User = "${uid}:${uid}";
    WorkingDir = "/var/lib/helios";
    Env = [
      "HELIOS_LISTEN=0.0.0.0:8080"
      "HELIOS_DATA_DIR=/var/lib/helios"
      "HOME=/var/lib/helios"
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
    ExposedPorts."8080/tcp" = { };
    Volumes."/var/lib/helios" = { };
    Labels = {
      "org.opencontainers.image.title" = "helios";
      "org.opencontainers.image.description" = "Self-hosted Nix binary cache";
      "org.opencontainers.image.version" = helios.version;
      # Links the GHCR package to the repository.
      "org.opencontainers.image.source" = "https://github.com/Polymath-AS/helios";
    };
  };
}
