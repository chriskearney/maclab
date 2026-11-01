#!/bin/sh
# loop-judge.sh: lab-loop's judge. A fresh, headless Claude Code run per boot
# reads one finished job through `lab mcp` with read-only tools and prints one
# verdict JSON. Fresh each time so a verdict rests on that boot's evidence
# alone. lab-loop runs it with MACLAB_JOB and MACLAB_DEVICE set:
#
#   lab-loop ... --judge scripts/loop-judge.sh
#
# It is never told what was injected: that is what the score measures.
set -eu
: "${MACLAB_JOB:?}" "${MACLAB_DEVICE:?}"
LAB=${LAB:-lab}
MODEL=${LOOP_JUDGE_MODEL:-claude-opus-5-5}

cfg=$(mktemp)
trap 'rm -f "$cfg"' EXIT
jq -n --arg lab "$(command -v "$LAB")" '{mcpServers: {maclab: {command: $lab, args: ["mcp"]}}}' >"$cfg"

prompt=$(cat <<EOF
You are judging one finished maclab job on a real Apple Silicon Mac. Job: $MACLAB_JOB. Mac: $MACLAB_DEVICE.
The job booted a test kernel once. That kernel may have been broken on purpose in one of these ways, or not at all:
- none: healthy
- marker: healthy, prints a marker
- oops_late: a kernel oops about 90 s after boot; the system keeps running
- panic_late: a kernel panic about 90 s after boot
- panic_early: a panic before userspace
- hang_early: a hang with interrupts off before SMP, so only the bootloader's watchdog resets the Mac
- hang_late: userspace never starts while the kernel stays alive
- netdown: a healthy kernel with its Wi-Fi driver blacklisted
Read the evidence with the lab tools: lab_job first, then lab_log for the kernel and journal logs, lab_serial if the
Mac has a serial console, and lab_device for its state now. Decide from the evidence, not from the job's outcome alone.
Answer with one JSON object and nothing else:
{"fault": "<one of the modes above, or unsure>", "lab_outcome_agrees": <true if the lab's outcome fits what you found>,
 "human_needed": <true if the Mac needs a person now>, "evidence": ["<log file and line your call rests on>"],
 "surprise": "<anything that doesn't fit, or empty>"}
EOF
)

out=$(claude -p "$prompt" --model "$MODEL" --mcp-config "$cfg" --strict-mcp-config --no-session-persistence \
	--allowedTools "mcp__maclab__lab_job,mcp__maclab__lab_log,mcp__maclab__lab_serial,mcp__maclab__lab_device" \
	--output-format json)

# The verdict is in .result; tokens and cost come from the run itself.
printf '%s' "$out" | jq -c '
	(.result | capture("(?s)(?<j>\\{.*\\})").j | fromjson) +
	{tokens: ((.usage.input_tokens // 0) + (.usage.output_tokens // 0)), cost_usd: (.total_cost_usd // 0)}'
