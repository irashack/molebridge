package exit

import "github.com/irashack/molebridge/internal/validate"

// marshalForTest turns what the publisher writes into the decoded form.
func marshalForTest(v any) (map[string]any, error) {
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		return nil, err
	}
	d, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	m, _ := d.(map[string]any)
	return m, nil
}
