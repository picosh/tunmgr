# tunmgr

A tunnel manager for docker services

This tool utilizes [tun.sh](https://tuns.sh) as its tunnel provider. You can self-host [sish](https://docs.ssi.sh) as well.

tunmgr automatically set's up tunnels for docker services. It utilizes `Exposed`'d ports as well as `DNSNames` (and the container name/id) to setup different permutations of tunnels.

You can also disable the docker based system by setting `-docker-events=false`. Doing this would then only setup tunnels set with a `-tunnel` setting, following the same syntax as `ssh -R`.

## Arguments

```text
Usage of tunmgr:
  -command string
        The command to run for the remote session
  -docker-events
        Whether or not to use docker events for setting up tunnels (default true)
  -local-tunnel value
        Tunnel to initialize on setup. Can be provided multiple times, in the format of a -L tunnel for SSH.
  -log-level string
        Log level to set for the logger. Can be debug, warn, error, or info (default "info")
  -networks string
        A comma separated list of networks to listen to events for
  -only-labels
        Whether or not to only use docker labels for setting up tunnels
  -remote-host string
        The remote host to connect to in the format of host:port (default "tuns.sh")
  -remote-hostname string
        The remote hostname to verify the host key (default "tuns.sh")
  -remote-key-location string
        The location on the filesystem of where to access the ssh key (default "/key")
  -remote-key-passphrase string
        The passphrase for an encrypted ssh key
  -remote-logs
        Whether or not to print logs from the remote tunnels (default true)
  -remote-user string
        The remote user to connect as
  -tunnel value
        Tunnel to initialize on setup. Can be provided multiple times, in the format of a -R tunnel for SSH.
```

## Example

```yaml
services:
  tunmgr:
    image: ghcr.io/picosh/tunmgr:latest
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - $HOME/.ssh/id_ed25519_pico_antonio:/key:ro
    # ports: # Ports map for local tunnels like below
    #   - 8000:8000
    # command: | # Provide other commands below
    #   -only-labels=true
    #   -local-tunnel=0.0.0.0:8000:antonio-httpbin:8000
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 2s
      timeout: 5s
      retries: 5
      start_period: 1s
  httpbin:
    image: kennethreitz/httpbin
    depends_on:
      tunmgr:
        condition: service_healthy
    # labels: # or provide tunnel names and ports explicitly
    #   tunmgr.names: httpbin # Comma separated list of names. Can be an empty. If empty, allows for tcp forward (or random name).
    #   tunmgr.ports: 8000:80,80:80 # Comma separated list of port maps. (remote:local). First is alias, second is http.
    command: gunicorn -b 0.0.0.0:80 httpbin:app -k gevent --access-logfile -
```

Auto tunnels will be established for:

1. [https://antonio-ce37a3511391.tuns.sh](https://tuns.sh)
2. [https://antonio-httpbin.tuns.sh](https://tuns.sh)
3. [https://antonio-tunmgr-httpbin-1.tuns.sh](https://tuns.sh)
