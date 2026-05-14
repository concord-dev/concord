package concord.iso42001.data_quality

import rego.v1

# ISO 42001 §8.2 / EU AI Act Article 10 — data quality documentation.
# Each production model must carry an MLflow tag pointing at a dataset card.

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected"
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    not has_dataset_card(model)
    msg := sprintf("production model %q has no dataset_card_url tag", [model.name])
}

warn contains msg if {
    some model in input.model_registry.models
    model.production == true
    has_dataset_card(model)
    not model.dataset_version
    msg := sprintf("production model %q has a dataset_card_url but no dataset_version tag (recommended)", [model.name])
}

# High-risk models additionally need a documented data-quality assessment.
warn contains msg if {
    some model in input.model_registry.models
    model.production == true
    model.eu_ai_act_tier == "high"
    not model.dataset_quality_assessment
    msg := sprintf("high-risk model %q has no dataset_quality_assessment tag (required for EU AI Act Annex IV §2)", [model.name])
}

has_dataset_card(model) if {
    model.dataset_card_url
    model.dataset_card_url != ""
}
