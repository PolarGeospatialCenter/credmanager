package types

var (
	setEntryExists = struct{}{}
)

// PolicySet represents a collection of vault acl policies
type PolicySet map[string]struct{}

// NewPolicySet creates a new policy set from a list of strings
func NewPolicySet(policies ...string) PolicySet {
	set := make(map[string]struct{})
	for _, policy := range policies {
		set[policy] = setEntryExists
	}
	return set
}

// Add adds a string to the PolicySet if it isn't already there
func (set PolicySet) Add(policies ...string) {
	for _, policy := range policies {
		set[policy] = setEntryExists
	}
}

// IsSubsetOf returns true if this set is a subset of the supplied set
func (set PolicySet) IsSubsetOf(otherSet PolicySet) bool {
	for entry := range set {
		_, ok := otherSet[entry]
		if !ok {
			return false
		}
	}
	return true
}

// StringSlice returns a slice containing all entries in the set
func (set PolicySet) StringSlice() []string {
	entries := make([]string, len(set))
	var i uint
	for entry := range set {
		entries[i] = entry
		i++
	}
	return entries
}
