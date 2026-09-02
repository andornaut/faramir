package keeper

// Flattening a decrypted document into the refs the store serves.

import (
	"encoding/json"
	"strconv"
)

// Flatten walks decrypted JSON into "path/to/key" -> string pairs.
func Flatten(node any) map[string]string {
	out := map[string]string{}
	flattenNode(node, "", out)
	return out
}

func flattenNode(node any, prefix string, out map[string]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, value := range v {
			// Exactly the top-level "sops" key, sops' own metadata block: a prefix
			// match at any depth would drop real secrets such as sops_backup_token.
			if prefix == "" && key == "sops" {
				continue
			}
			child := key
			if prefix != "" {
				child = prefix + "/" + key
			}
			flattenNode(value, child, out)
		}
	case []any:
		for i, value := range v {
			child := strconv.Itoa(i)
			if prefix != "" {
				child = prefix + "/" + strconv.Itoa(i)
			}
			flattenNode(value, child, out)
		}
	case bool, nil:
		// Never secret, and "true"/"false" would redact half the output.
		return
	case string:
		out[prefix] = v
	case int:
		out[prefix] = strconv.Itoa(v)
	case int64:
		out[prefix] = strconv.FormatInt(v, 10)
	case float64:
		out[prefix] = strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		out[prefix] = v.String()
		// Anything else -- a timestamp a YAML parser typed, a scalar with no JSON
		// shape -- is dropped rather than rendered with %v: a Go rendering is a
		// spelling no tool prints, so it would sit in the redactor matching
		// nothing and be injected as text nothing chose. secretlink's scalar()
		// refuses the same shapes with a reason.
	}
}
