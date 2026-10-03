# VM test for the OCI image: load it into Docker, run it with generated
# secrets, administer it with docker exec, push to it from the host, and
# substitute back through Nix with signatures required.
{ pkgs, image, helios }:

pkgs.testers.runNixOSTest {
  name = "helios-docker";

  nodes.machine = {
    virtualisation.docker.enable = true;
    virtualisation.diskSize = 4096;
    virtualisation.memorySize = 2048;
    environment.systemPackages = [
      helios
      pkgs.hello
    ];
    nix.settings.experimental-features = [ "nix-command" ];
  };

  testScript = ''
    import json

    machine.wait_for_unit("docker.service")
    tag = machine.succeed("docker load < ${image} | sed -n 's/^Loaded image: //p'").strip()
    machine.succeed(f"docker run -d --name helios -p 8080:8080 -v helios:/var/lib/helios {tag}")
    machine.wait_until_succeeds("curl -sf http://127.0.0.1:8080/healthz")

    with subtest("runs unprivileged with generated secrets"):
        assert machine.succeed("docker inspect -f '{{.Config.User}}' helios").strip() == "10000:10000"
        # The container's init (the entrypoint) runs as the image user.
        pid = machine.succeed("docker inspect -f '{{.State.Pid}}' helios").strip()
        machine.succeed(f"grep -Eq '^Uid:\\s+10000\\s' /proc/{pid}/status")
        machine.wait_until_succeeds("docker top helios | grep -q helios-daemon")
        pubkey = machine.succeed("docker exec helios helios-public-key").strip()
        assert pubkey.startswith("helios-1:"), pubkey

    with subtest("administer with docker exec, push from the host"):
        machine.succeed("docker exec helios helios-admin cache create main")
        token = json.loads(machine.succeed("docker exec helios helios-admin token create ci --caches main --perms push,pull 2>/dev/null"))["token"]
        machine.succeed(f"helios login ci http://127.0.0.1:8080 {token}")
        machine.succeed("helios push main --closure ${pkgs.hello}")

    with subtest("substitute with signatures required"):
        machine.succeed(
            f"NIX_CONFIG='trusted-public-keys = {pubkey}\nrequire-sigs = true' "
            "nix copy --from http://127.0.0.1:8080/main --to /tmp/store ${pkgs.hello}"
        )

    with subtest("docker stop is clean; data and keys persist"):
        machine.succeed("docker stop helios")
        assert machine.succeed("docker inspect -f '{{.State.ExitCode}}' helios").strip() == "0"
        machine.succeed("docker start helios")
        machine.wait_until_succeeds("curl -sf http://127.0.0.1:8080/healthz")
        machine.succeed("curl -sf http://127.0.0.1:8080/main/$(basename ${pkgs.hello} | cut -c1-32).narinfo")
        assert machine.succeed("docker exec helios helios-public-key").strip() == pubkey
        # The daemon waited for the new server, not the last run's socket.
        machine.wait_until_succeeds("docker logs helios 2>&1 | grep -c 'helios-daemon started' | grep -qx 2")
        machine.fail("docker logs helios 2>&1 | grep -q 'Connection refused'")

    with subtest("docker stop during startup is clean"):
        # Without a handler yet, PID 1 would ignore the TERM until the kill.
        machine.succeed("docker stop helios && docker start helios && timeout 20 docker stop -t 60 helios")
        assert machine.succeed("docker inspect -f '{{.State.ExitCode}}' helios").strip() == "0"
  '';
}
