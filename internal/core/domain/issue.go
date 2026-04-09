package domain

// Issue represents a correlated security concern grouped by resource.
// It uses pointers to original Evidence to maintain a low-allocation footprint.
type Issue struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	Target      Resource    `json:"target"`
	Severity    Severity    `json:"severity"`
	Remediation string      `json:"remediation"`
	Findings    []*Evidence `json:"findings"`
}

// IssueAggregator defines the result of the correlation process.
type IssueAggregator struct {
	Issues []*Issue `json:"issues"`
}
