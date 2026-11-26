package hostunit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ConfigFile reads FARAMIR_CONFIG from Environment= in the installed unit's
// Service section and sorted drop-ins. Missing units and unset variables return
// an empty path; unreadable or unsupported declarations return an error.
func ConfigFile(unit string) (string, error) {
	paths, err := files(unit)
	if err != nil {
		return "", err
	}
	file := ""
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && path == unit {
			continue
		}
		if err != nil {
			return "", err
		}
		file, err = configEnvironment(file, string(body))
		if err != nil {
			// Environment lines may contain credentials beside the config path.
			// Report the file and cause without quoting the declaration.
			return "", fmt.Errorf("%s: %w", path, err)
		}
	}
	parts := strings.Split(file, "%%")
	for _, part := range parts {
		if strings.Contains(part, "%") {
			return "", fmt.Errorf("%s: FARAMIR_CONFIG specifiers are not supported; use a literal absolute path", unit)
		}
	}
	file = strings.Join(parts, "%")
	if file != "" && !filepath.IsAbs(file) {
		return "", fmt.Errorf("%s: FARAMIR_CONFIG must be an absolute file path", unit)
	}
	return file, nil
}

// configEnvironment applies one file without inheriting its section into the
// next. A bare Environment= resets all earlier assignments; assigning another
// variable alone leaves FARAMIR_CONFIG unchanged.
func configEnvironment(file, body string) (string, error) {
	service := false
	continued := ""
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = continued + line
		if prefix, ok := strings.CutSuffix(line, "\\"); ok {
			continued = prefix + " "
			continue
		}
		continued = ""
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			service = line == "[Service]"
			continue
		}
		key, value, assigned := strings.Cut(line, "=")
		if !service || !assigned || strings.TrimSpace(key) != "Environment" {
			continue
		}
		words, err := environmentWords(strings.TrimSpace(value))
		if err != nil {
			return "", err
		}
		if len(words) == 0 {
			file = ""
		}
		for _, word := range words {
			name, value, assigned := strings.Cut(word, "=")
			if assigned && name == "FARAMIR_CONFIG" {
				file = value
			}
		}
	}
	if continued != "" {
		return "", errors.New("unterminated unit continuation")
	}
	return file, nil
}

// environmentWords follows systemd's whole-item quoting and C-style escapes.
// It performs neither shell expansion nor environment-variable substitution.
func environmentWords(value string) ([]string, error) {
	var words []string
	for value = strings.TrimLeft(value, " \t"); value != ""; value = strings.TrimLeft(value, " \t") {
		var word strings.Builder
		quote := byte(0)
		if value[0] == '"' || value[0] == '\'' {
			quote, value = value[0], value[1:]
		}
		closed := quote == 0
		for value != "" {
			ch := value[0]
			if quote != 0 && ch == quote {
				closed, value = true, value[1:]
				if value != "" && value[0] != ' ' && value[0] != '\t' {
					return nil, errors.New("invalid Environment item after closing quote")
				}
				break
			}
			if quote == 0 && (ch == ' ' || ch == '\t') {
				break
			}
			if ch == '\\' {
				decoded, rest, err := environmentEscape(value)
				if err != nil {
					return nil, err
				}
				word.WriteString(decoded)
				value = rest
				continue
			}
			word.WriteByte(ch)
			value = value[1:]
		}
		if !closed {
			return nil, errors.New("unterminated Environment quote")
		}
		words = append(words, word.String())
	}
	return words, nil
}

func environmentEscape(value string) (string, string, error) {
	if len(value) > 1 {
		switch value[1] {
		case 's':
			return " ", value[2:], nil
		case '\'':
			return "'", value[2:], nil
		}
	}
	decoded, multibyte, rest, err := strconv.UnquoteChar(value, '"')
	if err != nil || decoded == 0 {
		return "", "", errors.New("unsupported Environment escape")
	}
	if multibyte {
		return string(decoded), rest, nil
	}
	return string([]byte{byte(decoded)}), rest, nil
}
