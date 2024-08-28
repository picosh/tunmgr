# tunmgr

A tunnel manager for docker services

This tool utilizes [tun.sh](https://tuns.sh) as its tunnel provider. You can self-host [sish](https://docs.ssi.sh) as well.

tunmgr automatically set's up tunnels for docker services. It utilizes `Exposed`'d ports as well as `DNSNames` (and the container name/id) to setup different permutations of tunnels.

You can also disable the docker based system by setting `-docker-events=false`. Doing this would then only setup tunnels set with a `-tunnel` setting, following the same syntax as `ssh -R`.

## Example

```yaml
services:
  tunmgr:
    image: ghcr.io/picosh/tunmgr:latest
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - $HOME/.ssh/id_ed25519_pico_antonio:/key:ro
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
    #   tunmgr.names: httpbin # Comma separated list of names. Can be an empty
    #   tunmgr.ports: 80:80 $ Comma separated list of port maps. (remote:local)
    command: gunicorn -b 0.0.0.0:80 httpbin:app -k gevent --access-logfile -
```

Auto tunnels will be established for:

1. [https://antonio-ce37a3511391.tuns.sh](https://tuns.sh)
2. [https://antonio-httpbin.tuns.sh](https://tuns.sh)
3. [https://antonio-tunmgr-httpbin-1.tuns.sh](https://tuns.sh)
