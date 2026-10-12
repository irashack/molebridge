package providers

// ValidGluetunServerID validates an exact ID filter, including its JSON value
// type (valid_server_id): a hostname for "hostnames", a name for "names", an
// integer from 1 to 65535 for "numbers"; any other filter is invalid.
func ValidGluetunServerID(value any, selectionFilter string) bool {
	return validGluetunServerID(value, selectionFilter)
}
