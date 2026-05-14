package concord.eu_ai_act.article_13

import rego.v1

# EU AI Act Article 13 — transparency / model card publication.
# A high-risk production model satisfies this control if EITHER:
#   - its MLflow tags include public_model_card_url (non-empty), OR
#   - a docs/ai/model-cards/<model>.md exists.

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected"
}

deny contains msg if {
    some model in input.model_registry.models
    is_high_risk_prod(model)
    not has_published_card(model)
    msg := sprintf("high-risk model %q has neither public_model_card_url tag nor docs/ai/model-cards/<model>.md", [model.name])
}

# Recommend deeper card content even when the file exists.
warn contains msg if {
    some doc in input.model_cards.docs
    not has_value(doc, "intended_use")
    msg := sprintf("model card %q is missing intended_use section", [doc.path])
}

warn contains msg if {
    some doc in input.model_cards.docs
    not has_value(doc, "limitations")
    msg := sprintf("model card %q is missing limitations section", [doc.path])
}

is_high_risk_prod(model) if {
    model.production == true
    model.eu_ai_act_tier == "high"
}

has_published_card(model) if {
    has_url_tag(model)
}

has_published_card(model) if {
    has_card_file(model.name)
}

has_url_tag(model) if {
    model.public_model_card_url
    model.public_model_card_url != ""
}

has_card_file(name) if {
    some doc in input.model_cards.docs
    doc.model == name
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
