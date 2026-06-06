import os
import platform


def main() -> None:
    print(f"hello from dispatcher on {platform.platform()}")
    print(f"  python: {platform.python_version()}")
    print(f"  cwd:    {os.getcwd()}")
    # Verify .env wiring without printing the actual value.
    if "GREETING_NAME" in os.environ:
        print(f"  greeting: hello, {os.environ['GREETING_NAME']}!")
    print("done")


if __name__ == "__main__":
    main()
