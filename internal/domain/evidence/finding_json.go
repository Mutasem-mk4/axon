package evidence

import "encoding/json"

func (f Finding) CanonicalID() string {
	if f.ID != "" {
		return f.ID
	}
	if !f.Identity.FingerprintV1.IsZero() {
		return f.Identity.FingerprintV1.String()
	}

	return ""
}

func (f Finding) MarshalJSON() ([]byte, error) {
	type findingJSON Finding

	payload := struct {
		findingJSON
		ID string `json:"ID"`
	}{
		findingJSON: findingJSON(f),
		ID:          f.CanonicalID(),
	}

	return json.Marshal(payload)
}
