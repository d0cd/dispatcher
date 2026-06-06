"""Workload that demonstrates .dispatchignore.

The workload directory contains a fake `node_modules/` full of irrelevant
files. Without `.dispatchignore`, those would be rsynced to the cloud VM,
costing transfer time and disk. With it, only main.py + dispatcher.yaml
ship across.

Try (after running the workload):
  ssh -i ~/.dispatcher/keys/dispatcher-<run-id> root@<ip> 'ls /tmp/dispatcher/<run-id>'

You should see main.py and dispatcher.yaml, but NOT node_modules/.
"""
import os


def main() -> None:
    print("with-dispatchignore example")
    print(f"  cwd: {os.getcwd()}")

    # On a cloud target with .dispatchignore working, this directory will
    # NOT exist on the VM — node_modules was filtered from the rsync.
    # On a local target, it will exist (we run in-place; nothing was shipped).
    if os.path.isdir("node_modules"):
        print("  node_modules: present (running locally, no rsync needed)")
    else:
        print("  node_modules: absent (.dispatchignore worked, was not shipped)")

    print("done")


if __name__ == "__main__":
    main()
