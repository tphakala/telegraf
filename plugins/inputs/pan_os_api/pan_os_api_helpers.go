package pan_os_api

import "time"

func match(pattern, name string) (matched bool) {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	return deepMatchRune([]rune(name), []rune(pattern), false)
}

func deepMatchRune(str, pattern []rune, simple bool) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '?':
			if len(str) == 0 && !simple {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[1:], simple) ||
				(len(str) > 0 && deepMatchRune(str[1:], pattern, simple))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func convertDate(date string) string {
	// convert date returned by PAN-OS API to RFC3339

	// set date layout for conversion
	dateLayout := "2006/01/02 15:04:05 MST"
	// todo fix error handling
	t, _ := time.Parse(dateLayout, date)

	// todo maybe output date format should be user selectable?
	return t.Format(time.RFC3339)
}
