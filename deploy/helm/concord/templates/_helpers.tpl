{{/*
  Common helpers for the concord chart.

  - "concord.fullname" produces the deterministic Resource name that all
    templates lean on, so a chart rendered twice always yields the same
    Resource names (idempotent helm upgrades).
  - "concord.labels" yields the Recommended Labels block per the
    Kubernetes "Recommended Labels" doc — these are the labels every
    template embeds, separate from selector labels.
  - "concord.selectorLabels" is the narrower set used by the Service
    selector + Deployment matchLabels. MUST be stable across upgrades:
    changing these would orphan existing Pods.
  - "concord.serviceAccountName" returns the SA name to use, honouring
    `.Values.serviceAccount.create` / `.Values.serviceAccount.name`.
*/}}

{{- define "concord.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "concord.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "concord.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "concord.labels" -}}
helm.sh/chart: {{ include "concord.chart" . }}
{{ include "concord.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "concord.selectorLabels" -}}
app.kubernetes.io/name: {{ include "concord.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "concord.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "concord.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
  imageRef resolves the container image reference, preferring digest
  over tag (immutability matters in prod). When neither is set, the
  chart appVersion is used as the tag — keeps `helm upgrade` honest.
*/}}
{{- define "concord.imageRef" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}
