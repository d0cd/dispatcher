# pull-image

A workload with no source code — just a pre-built Docker image. Validates
the `PackageTypeImage` path that's distinct from the build-then-run
(`hello-docker`) and base-image-with-source (`hello-python` under docker)
paths.

Try:

```bash
dispatcher run examples/pull-image
```

You should see Docker's "Hello from Docker!" banner. The workload doesn't
have a main.py, app.py, or Dockerfile — `image:` in dispatcher.yaml is
enough.

To run a more useful pre-built tool, replace the image in dispatcher.yaml:

```yaml
name: nginx-test
image: nginx:alpine
service:
  port: 80
```
