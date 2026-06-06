import os


def main() -> None:
    print("hello from inside a container")
    # Verify --env-file delivered the value WITHOUT it being visible to
    # `ps` on the host (the credential-safety fix this example exercises).
    print(f"  API_KEY length: {len(os.environ.get('API_KEY', ''))} chars")
    print("done")


if __name__ == "__main__":
    main()
