# NixOS VM test for services.helios: a server behind nginx and a client
# that pushes a closure with the CLI, then substitutes it back through Nix
# with signatures required.
{ pkgs, module, helios }:

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
        nginx.acme = false;
        signingKeyFile = "/etc/helios/signing-key";
        jwtSecretFile = "/etc/helios/jwt-secret";
        adminSecretFile = "/etc/helios/admin-secret";
      };
      # Started by the test once the secrets exist.
      systemd.services.helios.wantedBy = lib.mkForce [ ];
      nix.settings.experimental-features = [ "nix-command" ];
    };

  nodes.client = {
    environment.systemPackages = [
      helios
      pkgs.hello
      pkgs.jq
    ];
    nix.settings.experimental-features = [ "nix-command" ];
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import json

    start_all()

    with subtest("secrets and startup"):
        server.succeed(
            "install -d -m 0700 /etc/helios",
            "nix key generate-secret --key-name test-1 > /etc/helios/signing-key",
            "head -c 32 /dev/urandom | base64 > /etc/helios/jwt-secret",
            "head -c 32 /dev/urandom | base64 > /etc/helios/admin-secret",
            "chmod 0400 /etc/helios/*",
            "systemctl start helios",
        )
        server.wait_for_unit("helios.service")
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

    with subtest("admin and push"):
        client.succeed(f"helios login admin http://server {admin}")
        client.succeed("helios cache create main")
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
        url = client.succeed("curl -sf http://server/main/$(basename ${pkgs.hello} | cut -c1-32).narinfo | sed -n 's/^URL: //p'").strip()
        client.succeed(f"curl -sf -o /dev/null http://server/main/{url}")
        # The internal location is not reachable directly.
        client.fail("curl -sf -o /dev/null http://server/_nar/")
        server.succeed("find /srv/helios/nar -name '*.nar.zst' | grep -q .")
        server.succeed("stat -c %U:%G:%a /srv/helios | grep -qx helios:helios:750")

    with subtest("state survives restarts; SIGTERM shuts down cleanly"):
        server.succeed("systemctl restart helios")
        server.wait_for_open_port(8080)
        client.succeed("curl -sf http://server/main/$(basename ${pkgs.hello} | cut -c1-32).narinfo")
        server.succeed("systemctl stop helios")
        server.succeed("journalctl -u helios | grep -q 'shutting down'")
        server.fail("systemctl is-failed helios")
  '';
}
