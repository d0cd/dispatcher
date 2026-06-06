import sys

# Deliberately fail with a specific exit code so dispatcher's failure-detail
# surfacing has something concrete to report. Verifies the CloudVM bug fix
# (Status now reads the runner's exit-code file instead of reporting
# "Completed" for every finished workload).
#
# After running, try:
#   dispatcher diagnose <run-id>
#
# You should see:
#   Likely cause: workload exited with code 1
#   Recommendation: Inspect the log tail above and fix the workload, then rerun.
print("about to fail with exit code 1", file=sys.stderr)
sys.exit(1)
