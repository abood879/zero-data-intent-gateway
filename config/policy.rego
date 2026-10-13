package governance.intent

import future.keywords.if
import future.keywords.in

default allow := false
default disambiguation_required := false

approved_vendors := {"aws", "amazon", "aws_cloud_global", "azure", "microsoft", "sap", "oracle"}
allowed_departments := {"Engineering", "Infrastructure", "Security"}

# Tier 1: Intent Lock (DoF = 0)
allow if {
    input.amount <= 5000.0
    lower(input.vendor) in approved_vendors
    input.department in allowed_departments
    input.budget_cleared == true
}

# Tier 2: Active Disambiguation (DoF = 1)
disambiguation_required if {
    input.amount <= 5000.0
    lower(input.vendor) in approved_vendors
    input.department in allowed_departments
    input.budget_cleared == false
}
