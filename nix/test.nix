# NixOS VM test for services.helios: a server behind nginx with the
# maintenance daemon, and a client that pushes a closure with the CLI,
# substitutes it back through Nix with signatures required, and pushes
# new builds automatically with watchStore.
{ pkgs, module, helios }:

let
  system = pkgs.stdenv.hostPlatform.system;
in
pkgs.testers.runNixOSTest {
  name = "helios";

  nodes.server =
    { lib, ... }:
    {
      imports = [ module ];
      services.helios = {
        enable = true;
        package = helios;
        domain = "server";
        # A custom location exercises the tmpfiles and sandbox path handling.
        dataDir = "/srv/helios";
        caches = {
          main = { };
          team.public = false;
        };
        nginx.acme = false;
        signingKeyFile = "/etc/helios/signing-key";
        jwtSecretFile = "/etc/helios/jwt-secret";
        adminSecretFile = "/etc/helios/admin-secret";
        daemon = {
          metrics.listen = "127.0.0.1:9120";
          checkpointInterval = "5s";
          scrub = {
            interval = "5s";
            rate = "0";
          };
          backup = {
            interval = "5s";
            keep = 2;
          };
        };
      };
      # Started by the test once the secrets exist.
      systemd.services.helios.wantedBy = lib.mkForce [ ];
      systemd.services.helios-daemon.wantedBy = lib.mkForce [ ];
      nix.settings.experimental-features = [ "nix-command" ];
    };

  nodes.client =
    { lib, ... }:
    {
      imports = [ module ];
      services.helios = {
        package = helios;
        watchStore = {
          enable = true;
          url = "http://server";
          cache = "main";
          tokenFile = "/etc/helios-push-token";
        };
      };
      systemd.services.helios-watch-store.wantedBy = lib.mkForce [ ];
      environment.systemPackages = [
        helios
        pkgs.hello
      ];
      # A derivation that builds offline in the VM. storePath gives the
      # builder string context, so the build sandbox includes busybox.
      environment.etc."watched.nix".text = ''
        derivation {
          name = "watched";
          system = "${system}";
          builder = "''${builtins.storePath "${pkgs.busybox}"}/bin/sh";
          args = [ "-c" "echo built > $out" ];
        }
      '';
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.memorySize = 2048;
    };

  testScript = ''
    import json

    start_all()

    def narinfo_url(path):
        return f"http://server/main/{path.split('/')[-1][:32]}.narinfo"

    def metric(name):
        out = server.succeed("curl -sf http://127.0.0.1:9120/metrics")
        for line in out.splitlines():
            if line.startswith(name + " ") or line.startswith(name + "{"):
                return line
        raise Exception(f"{name} not in metrics:\n{out}")

    with subtest("secrets and startup"):
        server.succeed(
            "install -d -m 0700 /etc/helios",
            "nix key generate-secret --key-name test-1 > /etc/helios/signing-key",
            "head -c 32 /dev/urandom | base64 > /etc/helios/jwt-secret",
            "head -c 32 /dev/urandom | base64 > /etc/helios/admin-secret",
            "chmod 0400 /etc/helios/*",
            "systemctl start helios helios-daemon",
        )
        server.wait_for_unit("helios.service")
        server.wait_for_unit("helios-daemon.service")
        server.wait_for_unit("nginx.service")
        server.wait_for_open_port(8080)
        server.wait_for_open_port(80)
        client.wait_for_unit("multi-user.target")
        pubkey = server.succeed("nix key convert-secret-to-public < /etc/helios/signing-key").strip()
        admin = server.succeed("cat /etc/helios/admin-secret").strip()

    with subtest("sandboxing"):
        # The unit reads its secrets as credentials, not from /etc.
        server.fail("sudo -u helios cat /etc/helios/signing-key")
        props = server.succeed("systemctl show helios -p NoNewPrivileges -p ProtectSystem -p User")
        assert "NoNewPrivileges=yes" in props and "ProtectSystem=strict" in props and "User=helios" in props, props
        # nginx may read NARs but not reach the maintenance socket.
        server.succeed("stat -c %G /run/helios-admin/admin.sock | grep -qx helios-admin")
        server.fail("sudo -u nginx curl -sf --unix-socket /run/helios-admin/admin.sock http://x/v1/stats")
        server.succeed("sudo -u helios-daemon curl -sf --unix-socket /run/helios-admin/admin.sock http://x/v1/stats")

    with subtest("admin and push"):
        client.succeed(f"helios login admin http://server {admin}")
        caches = {c["name"]: c["public"] for c in json.loads(client.succeed("helios cache list"))["caches"]}
        assert caches == {"main": True, "team": False}, caches
        token = json.loads(client.succeed("helios token create ci --caches main --perms push,pull 2>/dev/null"))["token"]
        client.succeed(f"helios login ci http://server {token}")
        client.succeed("helios push main --closure ${pkgs.hello}")
        out = client.succeed("helios push main --closure ${pkgs.hello} 2>&1")
        assert "already in 'main'" in out, out

    with subtest("substitute with signatures required"):
        client.succeed(
            f"NIX_CONFIG='trusted-public-keys = {pubkey}\nrequire-sigs = true' "
            "nix copy --from http://server/main --to /tmp/store ${pkgs.hello}"
        )
        client.succeed(f"nix store verify --store /tmp/store --trusted-public-keys '{pubkey}' -r ${pkgs.hello}")

    with subtest("nginx serves NARs from disk"):
        url = client.succeed(f"curl -sf {narinfo_url('${pkgs.hello}')} | sed -n 's/^URL: //p'").strip()
        client.succeed(f"curl -sf -o /dev/null http://server/main/{url}")
        # The internal location is not reachable directly.
        client.fail("curl -sf -o /dev/null http://server/_nar/")
        server.succeed("find /srv/helios/nar -name '*.nar.zst' | grep -q .")
        server.succeed("stat -c %U:%G:%a /srv/helios | grep -qx helios:helios:750")

    with subtest("state survives restarts"):
        server.succeed("systemctl restart helios")
        server.wait_for_open_port(8080)
        client.succeed(f"curl -sf {narinfo_url('${pkgs.hello}')}")

    with subtest("daemon: metrics, backups, scrub"):
        server.wait_until_succeeds("curl -sf http://127.0.0.1:9120/metrics | grep -qx 'helios_up 1'")
        assert int(metric('helios_cache_paths{cache="main"}').split()[-1]) > 0
        server.wait_until_succeeds("test $(ls /srv/helios/backups | wc -l) -eq 2", timeout=60)
        # Corrupt a dependency's NAR; the scrub must take it out of service.
        url = client.succeed(f"curl -sf {narinfo_url('${pkgs.glibc}')} | sed -n 's/^URL: nar\\///p'").strip()
        server.succeed(f"printf garbage | dd of=/srv/helios/nar/{url[:2]}/{url} bs=1 seek=100 conv=notrunc")
        server.wait_until_succeeds("ls /srv/helios/quarantine | grep -q .", timeout=60)
        client.fail(f"curl -sf {narinfo_url('${pkgs.glibc}')}")
        assert metric('helios_scrub_blobs_total{result="corrupt"}').endswith(" 1")

    with subtest("watch-store pushes new builds"):
        client.succeed(f"echo {token} > /etc/helios-push-token", "systemctl start helios-watch-store")
        built = client.succeed("nix-build /etc/watched.nix --no-out-link").strip()
        client.wait_until_succeeds(f"curl -sf {narinfo_url(built)}", timeout=60)

    with subtest("auto-gc evicts least recently used paths, except pinned closures"):
        # The scrub unpublished glibc; a re-push restores the whole closure,
        # which --pin then protects.
        client.succeed("helios push main --closure --pin ${pkgs.hello}")
        client.succeed(f"curl -sf {narinfo_url('${pkgs.glibc}')}")
        pinned = client.succeed("nix-store -qR ${pkgs.hello}").split()
        before = int(metric('helios_cache_paths{cache="main"}').split()[-1])
        server.succeed(
            "sudo -u helios-daemon timeout 5 ${helios}/bin/helios-daemon "
            "--socket /run/helios-admin/admin.sock --data-dir /srv/helios "
            "--quota 1K --gc-interval 1s --scrub-interval 0 --backup-interval 0 || test $? -eq 124"
        )
        after = int(metric('helios_cache_paths{cache="main"}').split()[-1])
        assert after < before, (before, after)
        for p in pinned:
            client.succeed(f"curl -sf http://server/main/{p[11:43]}.narinfo")
        assert after == len(pinned), (after, pinned)

    with subtest("SIGTERM shuts down cleanly"):
        server.succeed("systemctl stop helios-daemon helios")
        server.succeed("journalctl -u helios | grep -q 'shutting down'")
        server.succeed("journalctl -u helios-daemon | grep -q 'shutting down'")
        server.fail("systemctl is-failed helios")
        server.fail("systemctl is-failed helios-daemon")
  '';
}
