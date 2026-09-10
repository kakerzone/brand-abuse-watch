# Case management

Use `new` for an unreviewed candidate and `triaged` for an analyst-reviewed candidate. Only a human reviewer may set `confirmed_impersonation`; a confirmed finding may move to `takedown_pending` only after the relevant external action is separately authorized. `false_positive`, `ignored`, and `resolved` are terminal states.

Every transition needs an actor and a concrete note. Keep false-positive reasons because they are feedback for profile terms and scoring, but do not automatically remove candidates or lower future scores without review.
