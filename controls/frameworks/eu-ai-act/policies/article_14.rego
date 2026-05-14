package concord.eu_ai_act.article_14

import rego.v1

# EU AI Act Article 14 — human oversight runbook for high-risk AI systems.

required_sections := ["overseer_roles", "capabilities", "limitations", "kill_switch"]

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected"
}

deny contains msg if {
    some model in input.model_registry.models
    is_high_risk_prod(model)
    not has_oversight_doc(model.name)
    msg := sprintf("high-risk model %q has no oversight runbook at docs/ai/oversight/", [model.name])
}

deny contains msg if {
    some doc in input.oversight_docs.docs
    some section in required_sections
    not has_value(doc, section)
    msg := sprintf("oversight runbook %q is missing required section %q", [doc.path, section])
}

warn contains msg if {
    some doc in input.oversight_docs.docs
    not has_value(doc, "approver")
    msg := sprintf("oversight runbook %q has no approver field", [doc.path])
}

is_high_risk_prod(model) if {
    model.production == true
    model.eu_ai_act_tier == "high"
}

has_oversight_doc(name) if {
    some doc in input.oversight_docs.docs
    doc.model == name
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
