import json
import os
import time

OUT_DIR = "outputs"


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    # Drop two artifacts: a JSON result and a "log" file. Both should come
    # back to the local machine via dispatcher's artifact retrieval (rsync
    # with --safe-links, validated paths).
    result = {
        "status": "ok",
        "computed_at": int(time.time()),
        "items": [1, 2, 3, 4, 5],
        "sum": 15,
    }
    with open(os.path.join(OUT_DIR, "result.json"), "w") as f:
        json.dump(result, f, indent=2)

    with open(os.path.join(OUT_DIR, "run.log"), "w") as f:
        f.write("started\nprocessed 5 items\ndone\n")

    print(f"wrote {OUT_DIR}/result.json and {OUT_DIR}/run.log")


if __name__ == "__main__":
    main()
