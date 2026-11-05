//go:build darwin || linux

package resources

// contains is used by the darwin and linux reader tests only.
func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
