package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# The gate reads one SARIF file at a time (conftest evaluates each input
# separately) plus policy/waivers.yml as static data. A finding blocks the
# pipeline unless a matching, unexpired waiver exists. An expired waiver is
# itself a failure: waivers are not "fix once, ignore forever."

blocking_levels := {"error"}

is_expired(w) if {
	time.parse_rfc3339_ns(w.expires) < time.now_ns()
}

is_waived(rule_id) if {
	some w in data.waivers
	w.rule_id == rule_id
	not is_expired(w)
}

deny contains msg if {
	some run in input.runs
	some result in run.results
	level := object.get(result, "level", "error")
	level in blocking_levels
	rule_id := result.ruleId
	not is_waived(rule_id)
	msg := sprintf("[%s] %s: %s", [level, rule_id, result.message.text])
}

deny contains msg if {
	some w in data.waivers
	is_expired(w)
	msg := sprintf(
		"waiver expired %s for rule %s (%s) — renew or remove it",
		[w.expires, w.rule_id, w.reason],
	)
}
